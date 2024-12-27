from hashlib import sha256
from base64 import b64encode
from database import Database
from datetime import datetime
import os

ALLOWED_EXTENSIONS = {
    'png': b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a',
    'jpg': b'\xff\xd8',
    'jpeg': b'\xff\xd8',
    'gif': b'GIF8'
}

def guess_file(file: bytes):
    """Guesses which file format it uses using its file signature header."""
    for ext in ALLOWED_EXTENSIONS.keys():
        if ALLOWED_EXTENSIONS[ext] in file:
            return (ext, file)
    return (None, file)

def allowed_file(filename) -> bool:
    """Checks if the file is an image file."""
    print(os.path.splitext(filename)[1].lower())
    return os.path.splitext(filename)[1].lower().lstrip(".") in ALLOWED_EXTENSIONS.keys()

def encrypt_password(password: str) -> str:
    """Encrypts password string into a SHA-256 hashed password string."""
    return sha256(password.encode()).hexdigest()

def encode_image(file: str|bytes) -> bytes:
    """Encodes an image into a base64-encoded string"""
    if isinstance(file, str):
        with open(file, 'rb') as file:
            return b64encode(file.read())
    else:
        return b64encode(file)

def cache_image(username: str, file_bytes: bytes, filepath: str = 'static/assets/tmp/') -> None:
    """Caches image data by username into a folder defined by `filepath`."""
    with open(filepath + sha256(username.encode()).hexdigest(), 'wb') as tmp_file:
        tmp_file.write(file_bytes)

def check_password(passwordHash: str, password: str) -> bool:
    """Checks if both passwords are correct."""
    if encrypt_password(password) == passwordHash.lower():
        return True
    else:
        return False

class Role(dict):
    """Role type :class:`dict`-based object that stores information of a role."""
    default = {
        "id": 0,
        "name": "",
        "perms": ()
    }

    def __init__(self, id: int, name: str, perms: tuple):
        super(Role, self).__init__(
            id = id if not None else self.default['id'],
            name = name if not None else self.default['name'],
            perms = perms if not None else self.default['perms']
        )

    def __repr__(self) -> str:
        return f"Role (id={self['id']} name='{self['name']}' perms={self['perms']})"

class ProfilePicture(dict):
    """Profile Picture :type:`dict`-based object that stores the user's profile picture."""
    default = {
        "username": 'user',
        "image_header": "jpg",
        "image_path": 'static/assets/placeholder.jpg'
    }

    def __init__(self, username: str, image: bytes = None):
        if image != None and username != '':
            if b"ProfilePicture" in image:
                path = str(image, encoding='ascii')
                try:
                    with open(path.split(" ")[3].split("=")[1].rstrip(")"), 'rb') as image_file:
                        image = image_file.read()
                except FileNotFoundError:
                    with open("static/assets/placeholder.jpg", 'rb') as image_file:
                        image = image_file.read()
            
            image_data = guess_file(image)

            if image_data[0] == None:
                image_header = 'undefined'
            else:
                image_header = image_data[0]  

            # Temporarily store profile picture into a temp folder
            with open("static/assets/tmp/"+sha256(username.encode()).hexdigest(), 'wb') as pfp:
                pfp.write(image)
            
            image_path = "static/assets/tmp/"+sha256(username.encode()).hexdigest()
        
        else:
            image_header = self.default['image_header']
            image_path = self.default['image_path']
            username = self.default['username']
        
        super(ProfilePicture, self).__init__(
            username = username, image_header = image_header, image_path = image_path
        )
    
    def __repr__(self) -> str:
        return f"ProfilePicture (of={self['username']} type={self['image_header']} path={self['image_path']})"
    
    @property
    def image(self) -> bytes:
        """:attr:`image` property of :class:`ProfilePicture`. Returns a base64-encoded image bytes string."""
        with open(self['image_path'], 'rb') as image_bytes:
            return encode_image(image_bytes)
    
    @image.setter
    def image(self, image_path: str):
        """Sets or replaces the current object's image."""
        with open(image_path, 'rb') as image_bytes:
            image_data = guess_file(image_bytes.read())

            if image_data[0] == None:
                self['image_header'] = 'undefined'
            else:
                self['image_header'] = image_data[0]
            
            with open("static/assets/tmp/" + sha256(self['username'].encode()).hexdigest(), 'wb') as pfp:
                pfp.write(image_data[1])
            
            self['image_path'] = image_path
    
    @image.deleter
    def image(self):
        """Removes the image from the object and replaces it with the placeholder image."""
        os.remove(self['image_path'])
        self['image_header'] = 'jpg'
        self['image_path'] = 'static/assets/placeholder.jpg'

class User(dict):
    """User :type:`dict`-based object that stores the user profile details."""
    default = {
        "id":           0,
        "username":     'user',
        "name":         'User',
        "role":         Role(2, 'user', ("login", "dashboard", "profile", "preferences", "logout")),
        "address":      'Location',
        "pfp":          ProfilePicture('user'),
        "contact":      '09123456789',
        "bio":          'Hello!',
        "theme":        'light'
    }

    def __init__(self, **kwargs):
        if any([(key if key != 'role_id' else 'role') in self.default.keys() for key in kwargs]):
            role = self.default['role'] if 'role' not in kwargs.keys() or not isinstance(kwargs['role'], Role) else kwargs['role']
            pfp = ProfilePicture(kwargs['username'], kwargs['pfp']) if 'pfp' in kwargs.keys() else self.default['pfp']

            super(User, self).__init__(
                id =        kwargs['id'] if 'id' in kwargs.keys() else self.default['id'],
                username =  kwargs['username'] if 'username' in kwargs.keys() else self.default['username'],
                name =      kwargs['name'] if 'name' in kwargs.keys() else self.default['name'],
                role =      role,
                address =   kwargs['address'] if 'address' in kwargs.keys() else self.default['address'],
                pfp =       pfp,
                contact =   kwargs['contact'] if 'contact' in kwargs.keys() else self.default['contact'],
                bio =       kwargs['bio'] if 'bio' in kwargs.keys() else self.default['bio'],
                theme =     kwargs['theme'] if 'theme' in kwargs.keys() else self.default['theme']
            )

        else:
            super(User, self).__init__(self.default)

    def __repr__(self) -> str:
        return f"User(username='{self['username']}', id={self['id']})"

class MySQLDatabase(Database):
    """Custom MySQL Database object for quicker and convenient fetching and editing"""
    def __init__(self, flask_app):
        super().__init__(flask_app)
    
    def getUser(self, user) -> User|None:
        """Fetches a :class:`User` object from a succesful query. Returns :type:`None` if user was not found.\n
        - Fetch by user id: Enter a user id (:type:`int`).
        - Fetch by username: Enter a username (:type:`str`).
        :raises TypeError: if :param:`user` is not of type :type:`int` or :type:`str`."""

        if isinstance(user, int|str):
            result = self.queryGet(
                "SELECT u.*, d.* FROM users AS u, users_data AS d WHERE " + (" u.id=%s " if isinstance(user, int) else " u.username=%s ") + "AND d.user_id=u.id",
                (user,)
            )

            if result:
                return User(
                    id =        result['id'],
                    username =  result['username'],
                    role =      self.getRole(int(result['role_id'])),
                    name =      result['name'],
                    address =   result['address'],
                    pfp =       result['pfp'],
                    contact =   result['contact'],
                    bio =       result['bio'],
                    theme =     result['theme']
                )

            else:
                return None
        
        else:
            raise TypeError(f"Expected 'str' or 'int', got '{type(user).__name__}'")
    
    def getUsers(self) -> tuple[User]:
        """Fetches a tuple of User objects from a successful query."""

        results = self.queryGetAll(
            "SELECT u.*, d.* FROM users AS u, users_data AS d WHERE u.id=d.user_id"
        )
        
        users = []

        for user in results:
            _=user.pop('passwordHash')
            _=user.pop('user_id')
            user['role'] = self.getRole(
                int(user['role_id'])
            )
            _=user.pop('role_id')
            users.append(User(**user))
        
        return tuple(users)
    
    def getPassword(self, user: User, csrf_token: str) -> str:
        """Fetches the password for user. Requires CSRF token."""
        if csrf_token:
            return self.queryGet("SELECT HEX(passwordHash) AS passwordHash FROM users WHERE id=%s", (user['id'],))['passwordHash']
    
    def editUserInfo(self, current_user: User, edited_user: User) -> int:
        """Edits user information from edited User object."""

        # Form 1 contains: username, name, address, contact, bio, and theme
        # Form 1 (admin): role_id
        changed = [
            attr for attr in edited_user.keys() if edited_user[attr] != current_user[attr] and edited_user[attr] != ''
        ]
        
        existing_users = [
            username for username in self.queryGetAll("SELECT username FROM users")
        ]

        updated = 0

        if 'username' in changed and edited_user['username'] not in existing_users:
            self.querySet(
                "UPDATE users SET username=%s WHERE id=%s",
                (edited_user['username'], current_user['id'])
            )
            updated += 1
        
        if len(changed) != 0:
            if 'role' in changed:
                self.querySet(
                    "UPDATE users SET role_id=%s WHERE id=%s",
                    (edited_user['role']['id'], current_user['id'])
                )
            
            else:
                values = tuple(
                    [edited_user[key] for key in changed if key not in ['username', 'role']]
                )

                queryStr = "=%s,".join([key for key in changed + [""] if key != 'username'])
                queryStr = queryStr.rstrip(",")

                self.querySet(
                    f"UPDATE users_data SET {queryStr} WHERE user_id=%s",
                    values + (current_user['id'],)
                )

            updated += 1
        else:
            pass

        return updated
    
    def updateUserPfp(self, user: User, edited_user: User) -> bool:
        """Edits user profile picture from edited User object"""

        # Form 2 contains: pfp
        if user['pfp'] != edited_user['pfp']:
            self.querySet(
                "UPDATE users_data SET pfp=%s WHERE user_id=%s",
                (edited_user['pfp'], user['id'])
            )
            return True
        else:
            return False

    def updateUserPassword(self, user: User, old_password: bytes, new_password: bytes, csrf_token: str) -> int:
        """Updates password for user. Requires CSRF Token."""
        if csrf_token:
            current_password = self.queryGet("SELECT HEX(passwordHash) AS passwordHash FROM users WHERE id=%s", (user['id'],))['passwordHash']

            if old_password == current_password:
                self.querySet(
                    "UPDATE users SET passwordHash=UNHEX(%s) WHERE id=%s",
                    (new_password, user['id'])
                )

                return 0
            
            else:
                return 1
        
        else:
            return 2
    
    def createUser(self, new_user: User, password: bytes, csrf_token: str) -> int:
        """Creates a new user in database from User object. Requires CSRF Token."""
        if csrf_token:
            existing_users = [
                user for user in self.queryGetAll("SELECT id, username FROM users")
            ]

            new_user['id'] = max([u['id'] for u in existing_users]) + 1

            if new_user['username'] not in [u['username'] for u in existing_users]:
                self.querySet(
                    "INSERT INTO users (id, username, passwordHash, role_id) VALUES (%s, %s, UNHEX(%s), %s)",
                    (new_user['id'], new_user['username'], encrypt_password(password), new_user['role']['id'])
                )
            
                self.querySet(
                    "INSERT INTO users_data (user_id, name) VALUES (%s, %s)",
                    (new_user['id'], new_user['name'])
                )

                return 0
            
            else:
                return 1
        
        else:
            return 2
    
    def deleteUser(self, user: User, csrf_token: str) -> int:
        """Deletes an existing user with User object. Requires CSRF Token."""
        if csrf_token:
            self.querySet(
                "DELETE FROM users WHERE id=%s",
                (user['id'],)
            )

            self.querySet(
                "DELETE FROM users_data WHERE user_id=%s",
                (user['id'],)
            )

            # Resets AUTO_INCREMENT value for users table
            self.querySet(
                "ALTER TABLE users AUTO_INCREMENT = " + str(user['id'])
            )

            return True
        
        else:
            return False

    def getRole(self, id: int|str) -> Role:
        """Fetches a :class:`Role` object from the database using the specified :param:`id` (:type:`int` or :type:`str`)."""
        if isinstance(id, str|int):
            role = self.queryGet(
                "SELECT * FROM roles WHERE " + "id=%s" if isinstance(id, int) else "name=%s",
                (id, )
            )

            role['perms'] = role['perms'].split(",")

            for i in range(len(role['perms'])):
                if "[" in role['perms'][i]:
                    role['perms'][i] = role['perms'][i].replace("[", "")
                elif "]" in role['perms'][i]:
                    role['perms'][i] = role['perms'][i].replace("]", "")
                role['perms'][i] = role['perms'][i].strip().replace("'", "")
                role['perms'][i] = role['perms'][i].strip().replace('"', "")

            return Role(role['id'], role['name'], tuple(role['perms']))
        
        else:
            raise TypeError("Expected 'str' or 'int', not '" + type(id).__name__ +"'.")

    
    def getRoles(self) -> tuple[Role]:
        """Fetches a :type:`tuple` of :class:`Role` objects from the database."""
        roles = self.queryGetAll(
            "SELECT * FROM roles"
        )

        roles_tuple = ()

        for role in roles:

            role['perms'] = role['perms'].split(",")
            for i in range(len(role['perms'])):
                if "[" in role['perms'][i]:
                    role['perms'][i] = role['perms'][i].replace("[", "")
                elif "]" in role['perms'][i]:
                    role['perms'][i] = role['perms'][i].replace("]", "")
                role['perms'][i] = role['perms'][i].strip().replace("'", "")
                role['perms'][i] = role['perms'][i].strip().replace('"', "")

            roles_tuple += (
                Role(
                    role['id'],
                    role['name'],
                    tuple(role['perms'])
                )
            ,)
        
        return roles_tuple
    
    def addRole(self, new_role: Role, csrf_token: str) -> int:
        """Adds a new role into the database. Requires CSRF token."""
        if csrf_token:
            existing_roles = self.getRoles()

            if new_role['id'] not in [role['id'] for role in existing_roles]:
                self.querySet(
                    "INSERT INTO roles (id, name, perms) VALUES (%s,%s,%s)",
                    (new_role['id'], new_role['name'], str(new_role['perms']))
                )

                return 0
            
            else:
                return 1
        
        else:
            return 2
    
    def removeRole(self, role: Role, csrf_token: str) -> bool:
        """Removes a existing role from the database. Requires CSRF token."""
        if csrf_token:
            if role['id'] <= 2:
                users_with_role = self.queryGetAll(
                    "SELECT * FROM users WHERE role_id=%s",
                    (role['id'],)
                )

                if len(users_with_role) > 0:
                    self.querySet(
                        "UPDATE users SET role_id=2 WHERE role_id=%s",
                        (role['id'],)
                    )

                self.querySet(
                    "DELETE FROM roles WHERE id=%s",
                    (role['id'],)
                )

                return True
            else:
                return False

        return False
    
    def auditChanges(self, user: User|dict, event_type: str, description: str) -> None:
        """Documents any changes into an audit log in the database.

        :param user: the user responsible for the change.
        :type user: User
        :param event_type: type of change made\n
        :type event_type: str
        :param description: detailed description of the change
        :type description: str

        Allowed values for :var:`event_type`:
        - `"logged-in"`
        - `"logged-out"`
        - `"created-user"`
        - `"created-role"`
        - `"deleted-user"`
        - `"deleted-role"`
        - `"updated-profile"`
        - `"updated-pfp"`
        - `"updated-password"`
        - `"edited-profile"`
        - `"edited-pfp"`
        - `"edited-password"`
        """
        
        ACCEPTED_TYPES = [
            "logged-in", "logged-out",
            "created-user", "deleted-user",
            "updated-profile", "updated-pfp", "updated-password",
            "edited-profile", "edited-pfp", "edited-password",
            "created-role", "deleted-role"
        ]

        if event_type in ACCEPTED_TYPES:
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            self.querySet(
                "INSERT INTO audit_log (id, timestamp, user_id, event_type, description) VALUES (NULL,%s,%s,%s,%s)",
                (current_time, user['id'], event_type, description)
            )

        else:
            raise ValueError(f"Invalid event type: {event_type}. Valid event types: {ACCEPTED_TYPES.__str__().lstrip('[').rstrip(']')}.")

    def getAuditLogs(self) -> list[dict]:
        """Fetches all audit logs from database."""
        return self.queryGetAll("SELECT a.*, u.username FROM audit_log AS a, users AS u WHERE u.id=a.user_id ORDER BY a.timestamp DESC")

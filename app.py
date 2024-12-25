from flask import Flask, request, render_template, redirect, session, flash, url_for, jsonify
from flask_wtf import CSRFProtect
from database import MySQLDatabase
from hashlib import sha256
from base64 import b64encode

ALLOWED_EXTENSIONS = {
    'png': b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a',
    'jpg': b'\xff\xd8',
    'jpeg': b'\xff\xd8',
    'gif': b'\x47\x49\x46\x38'
}

import auditor, asyncio, threading

app = Flask(__name__)
app.secret_key = b'_g3nEr41Ly;5p34k1n6'
csrf = CSRFProtect(app)
mysqldb = MySQLDatabase(app)

def allowed_file(filename):
    return '.' in filename and filename.split('.', 1)[1].lower() in ALLOWED_EXTENSIONS.keys()

def checkPassword(passwordHash: str, password: str) -> bool:
    if sha256(password.encode()).hexdigest() == passwordHash.lower():
        return True
    else:
        return False

@app.before_request
def checkSession():
    if all([x not in session.keys() for x in ['user', 'role']]):
        session['user'] = ''
        session['role'] = ''
        session['user_id'] = ''
    
    else:
        if session['role'] != 'admin' and request.endpoint in ['admin', 'register', 'edit', 'logs']:
            flash("Access denied. Only administrators can access that.", 'error')
            return redirect('/')
        elif session['role'] != 'admin' and request.endpoint in ['fetch', 'delete']:
            return jsonify({'error_code': 403, 'reason': 'unauthorized'})

        if session['user'] == '':
            if request.endpoint == 'logout':
                return redirect(url_for('login'))
            elif request.endpoint not in ['login', 'static']:
                flash("You must be logged in before proceeding.", 'warning')
                return redirect(url_for('login'))

@app.route('/')
def index():
    if session['role'] == 'admin':
        return redirect('/admin')
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    user = mysqldb.queryGet(
        "SELECT d.name, d.pfp, d.theme, u.* FROM users AS u, users_data AS d WHERE d.user_id=u.id AND u.id=%s",
        (session['user_id'],)
    )
    if user['pfp']:
        image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in user['pfp']][0]

        user['pfp'] = (image_header, str(b64encode(user['pfp']), encoding = 'ascii'))
    else:
        user['pfp'] = (None, None)

    return render_template('index.html', user=user)

@app.route('/admin')
def admin():
    user = mysqldb.queryGet(
        "SELECT d.name, d.pfp, d.theme, u.* FROM users AS u, users_data AS d WHERE d.user_id=u.id AND u.id=%s",
        (session['user_id'],)
    )
    if user['pfp']:
        image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in user['pfp']][0]

        user['pfp'] = (image_header, str(b64encode(user['pfp']), encoding = 'ascii'))
    else:
        user['pfp'] = (None, None)

    return render_template('admin.html', user=user)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        users = mysqldb.queryGetAll(
            "SELECT username FROM users"
        )

        username = request.form['username']
        password = request.form['password']

        if username in [x['username'] for x in users]:
            user_found = mysqldb.queryGet(
                "SELECT u.id as id, u.username as username, HEX(u.passwordHash) as passwordHash, r.name as role, d.theme FROM users AS u, roles AS r, users_data AS d WHERE username = %s AND u.role_id=r.id",
                (username,)
            )

            if user_found:
                if checkPassword(user_found['passwordHash'], password):
                    session['user'] = username
                    session['user_id'] = user_found['id']
                    session['role'] = user_found['role']
                    session['theme'] = user_found['theme'] if user_found['theme'] != None else 'light'
                    mysqldb.querySet(
                        *auditor.add_log(
                            int(user_found['id']), 'Logged in', f"User logged in as '{user_found['role']}' "
                        )
                    )
                    return redirect('/')
                
                else:
                    flash("Incorrect password entered. Please try again.", 'error')
                    return redirect('/login')

        else:
            flash(f"User {username} does not exist. Please ask an administrator to create an account for you.", 'warning')
            return redirect('/login')

@app.route('/logout')
def logout():
    mysqldb.querySet(
        *auditor.add_log(
        int(session['user_id']), 'Logged out', f"User logged out."
        )
    )

    session['user'] = ''
    session['user_id']
    session['role'] = ''
    session['theme'] = ''

    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        roles = mysqldb.queryGetAll(
            "SELECT * FROM roles"
        )
        return render_template('register.html', roles=roles)
    
    elif request.method == 'POST':
        name = request.form['name']
        username = request.form['username']
        role_id = request.form['role_id']
        password = request.form['password']

        user_exists = mysqldb.queryGet(
            "SELECT * FROM users WHERE username = %s",
            (username,)
        )

        if not user_exists:
            mysqldb.querySet(
                "INSERT INTO users (id, username, passwordHash, role_id) VALUES (NULL, %s, UNHEX(%s), %s)",
                (username, sha256(password.encode()).hexdigest(), role_id)
            )

            new_user = mysqldb.queryGet(
                "SELECT u.id as id, r.name as role FROM users AS u, roles as r WHERE u.username = %s",
                (username,)
            )

            mysqldb.querySet(
                "INSERT INTO users_data (user_id, name, address, pfp) VALUES (%s, %s, NULL, NULL)",
                (new_user['id'], name)
            )

            mysqldb.querySet(
                *auditor.add_log(
                    int(new_user['id']), 'Created account', f"Created '{new_user['role']}' account"
                )
            )

            flash("Account successfully created.", 'success')
            return redirect('/admin')
        
        else:
            flash(f"Account '{username}' already exists.", 'error')
            return redirect('/register')

@app.route('/profile/')
@app.route('/profile')
def profile():
    if request.method == 'GET':
        profile_details = mysqldb.queryGet(
            "SELECT d.*, u.* FROM users AS u, users_data AS d WHERE d.user_id=u.id AND u.id=%s",
            (session['user_id'],)
        )

        if profile_details['pfp']:
            image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in profile_details['pfp']][0]

            profile_details['pfp'] = (image_header, str(b64encode(profile_details['pfp']), encoding = 'ascii'))
        else:
            profile_details['pfp'] = (None, None)

        return render_template('profile.html', user = profile_details)

@app.route('/preferences', methods=['GET', 'POST'])
def pref():
    if request.method == 'GET':
        user = mysqldb.queryGet(
            "SELECT d.*, u.* FROM users AS u, users_data AS d WHERE d.user_id=u.id AND u.id=%s",
            (session['user_id'],)
        )
        if user['pfp']:
            image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in user['pfp']][0]

            user['pfp'] = (image_header, str(b64encode(user['pfp']), encoding = 'ascii'))
        else:
            user['pfp'] = (None, None)

        return render_template("preferences.html", user=user)

    elif request.method == 'POST':
        if "modify" in request.args:
            modify_type = request.args['modify']
            match modify_type:
                case "details":
                    username = request.form['username']

                    user = mysqldb.queryGet(
                        "SELECT u.username, d.name AS displayname, d.address, d.contact, d.bio, d.theme FROM users AS u, users_data AS d WHERE u.id=%s AND d.user_id=u.id",
                        (session['user_id'],)
                    )

                    usernames = [x['username'] for x in mysqldb.queryGetAll("SELECT username FROM users")]
                    
                    updated = 0
                    if any([(request.form[x] != '' and request.form[x] != str(user[x])) for x in [x for x in request.form.keys() if x not in ['csrf_token']]]):
                        if username != user['username'] and username != "" and username not in usernames:
                            mysqldb.querySet(
                                "UPDATE users SET username=%s WHERE id=%s",
                                (username, session['user_id'])
                            )
                            updated += 1
                        
                        queryStr = "UPDATE users_data SET " + "=%s, ".join([x for x in request.form.keys() if x not in ['username', 'csrf_token'] and request.form[x] != '']+[' ']).rstrip(", ")
                        mysqldb.querySet(
                            queryStr.replace('displayname', 'name') + " WHERE user_id=%s",
                            tuple([request.form[x] for x in request.form.keys() if x not in ['username', 'csrf_token'] and request.form[x] != '']) + (session['user_id'],)
                        )
                        updated += 1

                    if updated > 0:
                        flash("Account details updated successfully.", 'success')
                        mysqldb.querySet(
                            *auditor.add_log(
                            int(session['user_id']), 'Updated account', f"User updated their account details."
                            )
                        )
                    else:
                        flash("Nothing was changed.", 'info')

                    return redirect(request.base_url)
                
                case "password":
                    currentPassword = request.form['currentPassword']
                    newPassword = request.form['newPassword']

                    newPassword = sha256(newPassword.encode()).hexdigest()
                    userPassword = mysqldb.queryGet(
                        "SELECT UNHEX(passwordHash) AS password FROM users WHERE id=%s",
                        (session['user_id'],)
                    )
                    
                    if currentPassword == userPassword['password']:
                        mysqldb.querySet(
                            "UPDATE users SET passwordHash=UNHEX(%s) WHERE id=%s",
                            (newPassword, session['user_id'])
                        )

                        flash("Password has been successfully updated.", 'success')

                        mysqldb.querySet(
                            *auditor.add_log(
                            int(session['user_id']), 'Updated password', f"User updated their password."
                            )
                        )
                    else:
                        flash("Current password is incorrect.", 'danger')

                    return redirect(request.base_url)
                
                case "pfp":
                    pfp = request.files['pfp']
                    
                    if pfp.filename == '':
                        flash("No image selected. Please select one.", 'warning')
                        return redirect(request.base_url)
                    
                    if pfp and allowed_file(pfp.filename):
                        data = pfp.read()
                        
                        mysqldb.querySet(
                            "UPDATE users_data SET pfp=%s WHERE user_id=%s",
                            (data, session['user_id'])
                        )

                        flash("Updated profile picture!", 'success')

                        mysqldb.querySet(
                            *auditor.add_log(
                            int(session['user_id']), 'Updated profile picture', f"User updated their profile picture."
                            )
                        )

                        return redirect(request.base_url)
                    
                    else:
                        flash("Invalid image file uploaded. Please upload a valid photo image.", 'error')
                        return redirect(request.base_url)
                
                case _:
                    flash(f"Unknown modify parameter value: '{modify_type}'.", 'error')
                    return redirect(request.base_url)
                
        else:
            flash("Nothing to modify or update.", 'info')
            return redirect("/preferences")

@app.route("/edit/<user_id>", methods=['GET', 'POST'])
def edit(user_id):
    if request.method == 'GET':
        edit_user = mysqldb.queryGet(
            "SELECT d.*, u.* FROM users AS u, users_data AS d WHERE d.user_id=u.id AND u.id=%s",
            (user_id,)
        )

        if edit_user != None:

            edit_user['role'] = edit_user.pop('role_id')

            user = mysqldb.queryGet(
                "SELECT d.*, u.* FROM users AS u, users_data AS d WHERE d.user_id=u.id AND u.id=%s",
                (session['user_id'],)
            )
            if user['pfp']:
                image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in user['pfp']][0]

                user['pfp'] = (image_header, str(b64encode(user['pfp']), encoding = 'ascii'))
            else:
                user['pfp'] = (None, None)

            if edit_user['pfp']:
                image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in edit_user['pfp']][0]

                edit_user['pfp'] = (image_header, str(b64encode(edit_user['pfp']), encoding = 'ascii'))
            else:
                edit_user['pfp'] = (None, None)

            return render_template("edit.html", edit_user=edit_user, user=user)
        else:
            flash(f"User id {user_id} does not exist.", 'warning')
            return redirect("/")

    elif request.method == 'POST':
        if "modify" in request.args:
            modify_type = request.args['modify']
            match modify_type:
                case "details":
                    username = request.form['username']

                    user = mysqldb.queryGet(
                        "SELECT u.username, u.role_id AS role, d.name AS displayname, d.address, d.contact, d.bio, d.theme FROM users AS u, users_data AS d WHERE u.id=%s AND d.user_id=u.id",
                        (user_id,)
                    )

                    usernames = [x['username'] for x in mysqldb.queryGetAll("SELECT username FROM users")]
                    
                    updated = 0
                    if any([(request.form[x] != '' and request.form[x] != str(user[x])) for x in [x for x in request.form.keys() if x not in ['csrf_token']]]):
                        if username != user['username'] and username != "" and username not in usernames:
                            mysqldb.querySet(
                                "UPDATE users SET username=%s WHERE id=%s",
                                (username, user_id)
                            )
                            updated += 1
                        
                        if request.form['role'] != str(user['role']) and request.form['role'] != '':
                            mysqldb.querySet(
                                "UPDATE users SET role_id=%s WHERE id=%s",
                                (request.form['role'], user_id)
                            )
                            updated += 1
                        
                        queryStr = "UPDATE users_data SET " + "=%s, ".join([x for x in request.form.keys() if x not in ['username', 'role', 'csrf_token'] and request.form[x] != '']+[' ']).rstrip(", ")
                        mysqldb.querySet(
                            queryStr.replace('displayname', 'name') + " WHERE user_id=%s",
                            tuple([request.form[x] for x in request.form.keys() if x not in ['username', 'role', 'csrf_token'] and request.form[x] != '']) + (user_id,)
                        )
                        updated += 1

                    if updated > 0:
                        flash("Account details updated successfully.", 'success')

                        mysqldb.querySet(
                            *auditor.add_log(
                            int(session['user_id']), 'Edited account', f"User edited account '{user['username']}'."
                            )
                        )
                    else:
                        flash("Nothing was changed.", 'info')

                    return redirect(request.base_url)
                
                case "password":
                    newPassword = request.form['newPassword']
                    newPassword = sha256(newPassword.encode()).hexdigest()
                    
                    mysqldb.querySet(
                        "UPDATE users SET passwordHash=UNHEX(%s) WHERE id=%s",
                        (newPassword, user_id)
                    )

                    flash("Password has been successfully updated.", 'success')

                    mysqldb.querySet(
                        *auditor.add_log(
                        int(session['user_id']), 'Changed account password', f"User changed password for account '{user_id}'."
                        )
                    )

                    return redirect(request.base_url)
                
                case "pfp":
                    pfp = request.files['pfp']
                    
                    if pfp.filename == '':
                        flash("No image selected. Please select one.", 'warning')
                        return redirect(request.base_url)
                    
                    if pfp and allowed_file(pfp.filename):
                        data = pfp.read()
                        
                        mysqldb.querySet(
                            "UPDATE users_data SET pfp=%s WHERE user_id=%s",
                            (data, user_id)
                        )

                        flash("Updated profile picture!", 'success')

                        mysqldb.querySet(
                            *auditor.add_log(
                            int(session['user_id']), 'Changed account profile picture', f"User changed profile picture for account '{user_id}'."
                            )
                        )

                        return redirect(request.base_url)
                    
                    else:
                        flash("Invalid image file uploaded. Please upload a valid photo image.", 'error')
                        return redirect(request.base_url)
                
                case _:
                    flash(f"Unknown modify parameter value: '{modify_type}'.", 'error')
                    return redirect(request.base_url)
                
        else:
            flash("Nothing to modify or update.", 'info')
            return redirect("/edit/" + user_id)

@app.route("/fetch")
def fetch():
    if request.method == 'GET':
        match list(request.args.keys())[0]:
            case "users":
                users = mysqldb.queryGetAll(
                    "SELECT u.id, u.username, d.*, r.name AS role FROM users AS u, users_data AS d, roles AS r WHERE d.user_id=u.id AND r.id=u.role_id"
                )
                
                for user in users:
                    if user['pfp']:
                        image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in user['pfp']][0]

                        user['pfp'] = (image_header, str(b64encode(user['pfp']), encoding = 'ascii'))
                    else:
                        user['pfp'] = (None, None)

                return jsonify(users)

@app.route("/delete", methods=['POST'])
def delete():
    if request.method == 'POST':
        match list(request.args.keys())[0]:
            case "user":
                user_id = request.args['user']

                mysqldb.querySet(
                    "DELETE FROM users WHERE id=%s",
                    (user_id,)
                )

                mysqldb.querySet(
                    *auditor.add_log(
                    int(session['user_id']), 'Deleted account', f"User deleted account '{user_id}'."
                    )
                )

                return jsonify({'status': True})

@app.route("/logs")
def logs():
    if request.method == 'GET':
        logs = mysqldb.queryGetAll(
            "SELECT a.*, u.username FROM audit_log AS a, users AS u WHERE u.id=a.user_id ORDER BY a.timestamp DESC"
        )

        user = mysqldb.queryGet(
            "SELECT d.*, u.* FROM users AS u, users_data AS d WHERE d.user_id=u.id AND u.id=%s",
            (session['user_id'],)
        )
        if user['pfp']:
            image_header = [x for x in ALLOWED_EXTENSIONS.keys() if ALLOWED_EXTENSIONS[x] in user['pfp']][0]

            user['pfp'] = (image_header, str(b64encode(user['pfp']), encoding = 'ascii'))
        else:
            user['pfp'] = (None, None)

        return render_template("logs.html", logs=logs, user=user)

def backup_loop(loop):
    loop.run_forever()

def backup_start(loop):
    loop.create_task(mysqldb.backupDB())
    bkdb_thread = threading.Thread(target = backup_loop, args=(loop,))
    bkdb_thread.start()

loop = asyncio.get_event_loop()
backup_start(loop)
app.run(host='0.0.0.0', port=8080, debug=True)

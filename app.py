from flask import Flask, request, render_template, redirect, session, flash, url_for, jsonify
from flask_wtf import CSRFProtect

import utils    # utils.py
import asyncio, threading   # for running the auto-backup system for the database.

app = Flask(__name__)
app.secret_key = b'_g3nEr41Ly;5p34k1n6'
csrf = CSRFProtect(app)
mysqldb = utils.MySQLDatabase(app)

@app.before_request
def check_session():
    """Checks the session before a request is made to ensure the session has a user,\n
    and the user has a appropriate role for the request made."""

    if 'user' not in session.keys(): # init
        session['user'] = utils.User()
        session['role'] = mysqldb.getRole(2)
        flash("You must be logged in before proceeding.", 'warning')
        return redirect('login')
    
    elif session['user'] != utils.User(): # session has a user logged in
        session_user = session['user']
        if isinstance(session_user, dict):
            if 'static' not in request.path and request.path != '/' and request.path != '/favicon.ico':
                if not any([perm in request.path for perm in session['role']['perms']]):    # check if user has the perms to access it
                    if request.endpoint in ['fetch', 'delete']:
                        return jsonify({'error_code': 403, 'reason': 'Unauthorized'})       # give error if none (fetching)
                    else:
                        if request.endpoint not in ['static']:
                            flash("Access denied. You lack permissions to access this.", "error")
                            return redirect('/')                                            # redirect back to dashboard with error if none
        
    elif session['user'] == utils.User(): # session has no user logged in yet
        if request.endpoint == 'logout':
            return redirect(url_for('login'))
        elif request.endpoint not in ['login', 'static']:
            flash("You must be logged in before proceeding.", 'warning')
            return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
def dashboard() -> str:
    """Main home page endpoint."""
    return render_template('dashboard.html', user=session['user'])

@app.route('/add_role', methods=['POST'])
def add_role():
    """Adds a new role into the database."""
    if request.method == 'POST':
        if session['role']['id'] <= 1:
            # Get last role id to append from
            last_id = max([role['id'] for role in mysqldb.getRoles()])

            # Create new Role object
            new_role = utils.Role(
                last_id + 1,
                request.form['rolename'],
                list(request.form.getlist('perms'))
            )

            # Create role into database
            mysqldb.addRole(new_role, request.form['csrf_token'])

            # Audit changes into log
            mysqldb.auditChanges(
                session['user'],
                "created-role",
                f"User '{session['user']['username']}' created a new role '{new_role['name']}' with set permissions: " + str(new_role['perms']).replace("[", "").replace("]", "")
            )
            
            return jsonify({'status': True})
        
        else:
            return jsonify({'status': False})

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint"""
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        users = mysqldb.getUsers()

        username = request.form['username']
        password = request.form['password']

        if username in [x['username'] for x in users]:
            # See if user exists to log in for
            user_found = mysqldb.getUser(username)

            if user_found:
                # Verify password entered
                if utils.check_password(mysqldb.getPassword(user_found, request.form['csrf_token']), password):                    
                    session['user'] = user_found
                    session['role'] = user_found['role']

                    # Audit login
                    mysqldb.auditChanges(
                        session['user'], "logged-in", f"User \'{session['user']['username']}\' logged in as \'{session['user']['role']['name']}\'"
                    )
                    return redirect('/')
                
                else:
                    flash("Incorrect password entered. Please try again.", 'error')
                    return redirect('/login')

        else:
            flash(f"User '{username}' does not exist. Please ask an administrator to create an account for you.", 'warning')
            return redirect('/login')

@app.route('/logout')
def logout():
    """Logout endpoint"""

    # Audit logout
    mysqldb.auditChanges(
        session['user'], "logged-out", f"User \'{session['user']['username']}\' logged out."
    )

    # Clear current session user
    session['user'] = utils.User()

    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register endpoint for admin and other related roles."""
    if request.method == 'GET':
        # Fetch roles for role select
        roles = mysqldb.getRoles()
        return render_template('register.html', user=session['user'], roles=roles)
    
    elif request.method == 'POST':
        # New User object
        new_user = utils.User(
            name =      request.form['name'],
            username =  request.form['username'],
            role =   mysqldb.getRole(int(request.form['role_id']))
        )

        # Check if user already exists
        user_exists = mysqldb.getUser(new_user['username'])

        if not user_exists:
            # Proceed if none
            status = mysqldb.createUser(
                new_user,
                request.form['password'],
                request.form['csrf_token']
            )

        if status == 0:
            # Successful register
            new_user = mysqldb.getUser(new_user['id'])

            # Audit changes
            mysqldb.auditChanges(
                session['user'], "created-user", f"User \'{session['user']['username']}\' created a \'{new_user['role']['name']}\' account."
            )

            flash("Account successfully created.", 'success')
            return redirect('/')
        
        elif status == 1:
            # User exists
            flash(f"Account '{new_user['username']}' already exists.", 'error')
            return redirect('/register')            

@app.route('/profile')
@app.route('/profile/<int:id>')
def profile(id: int):
    """Profile page endpoint"""
    if request.method == 'GET':
        if id == None:
            id = session['user']['id']

        profile = mysqldb.getUser(id)
        return render_template('profile.html', user = session['user'], profile = profile)

@app.route('/preferences', methods=['GET', 'POST'])
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id:int = None):
    """Preferences endpoint (for users)"""
    if request.method == 'GET':
        if 'edit' in session['role']['perms']:
            # Check if user has perms to edit endpoint.
            if request.path == '/preferences':
                # Proceed to their preferences page
                return render_template("preferences.html", user=session['user'], edit_user=session['user'])
            else:
                # Get user they are editing
                user = mysqldb.getUser(id)
                if user == None:
                    # Show 'user not found' error to user.
                    return render_template("preferences.html", user=session['user'], edit_user=user, id=id)
                else:
                    # Proceed to edit the user.
                    return render_template("preferences.html", user=session['user'], edit_user=user)
        else:
            # Proceed to preferences.
            return render_template("preferences.html", user=session['user'])

    elif request.method == 'POST':
        if "modify" in request.args:
            modify_type = request.args['modify']
            match modify_type:
                case "details":
                    # Edit profile details
                    if 'edit' in request.path:
                        # from edit endpoint
                        current_user = mysqldb.getUser(int(request.form['user_id']))
                        edited_user = current_user.copy()

                    elif 'preferences' in request.path:
                        # from preferences endpoint
                        current_user = session['user']
                        edited_user = current_user.copy()
                    
                    # Change anything new to edited user
                    edited_user['name'] = current_user['name'] if '' else request.form['displayname']
                    edited_user['username'] = current_user['username'] if '' else request.form['usernamee']
                    edited_user['address'] = current_user['address'] if '' else request.form['address']
                    edited_user['contact'] = current_user['contact'] if '' else request.form['contact']
                    edited_user['bio'] = current_user['bio'] if '' else request.form['bio']
                    edited_user['theme'] = current_user['theme'] if request.form['theme'] == current_user['theme'] else request.form['theme']

                    if 'edit' in request.path:
                        # Set role
                        edited_user['role'] = current_user['role'] if request.form['role'] == current_user['role']['id'] else mysqldb.getRole(int(request.form['role']))

                    # Edit user info into database
                    status = mysqldb.editUserInfo(current_user, edited_user)

                    if status > 0:
                        # successful edit
                        if 'edit' in request.path:
                            flash("Account details successfully edited.", 'success')

                            # Audit changes (edit)
                            mysqldb.auditChanges(
                                session['user'], "edited-profile", f"User \'{session['user']['username']}\' edited user \'{session['user']['username']}\' details: " + str([attr for attr in edited_user.keys() if edited_user[attr] != current_user[attr] and edited_user[attr] != '']).lstrip("[").rstrip("]")
                            )
                        
                        elif 'preferences' in request.path:
                            flash("Account details successfully updated.", 'success')

                            # Audit changes (preferences)
                            mysqldb.auditChanges(
                                session['user'], "updated-profile", f"User \'{session['user']['username']}\' updated their profile details: " + str([attr for attr in edited_user.keys() if edited_user[attr] != current_user[attr] and edited_user[attr] != '']).lstrip("[").rstrip("]")
                            )
                        
                        # Update current user with new changes
                        session['user'] = mysqldb.getUser(session['user']['id'])

                    else:
                        flash("Nothing was changed.", 'info')

                    return redirect(request.base_url)
                
                case "password":
                    # Password changed
                    user = mysqldb.getUser(int(request.form['user_id']))

                    if 'edit' in request.path:
                        # User edited someone's password
                        currentPassword = mysqldb.getPassword(mysqldb.getUser(id), request.form['csrf_token'])
                    else:
                        # User updated their password
                        currentPassword = request.form['currentPassword']
                    
                    # encrypt new password with SHA-256 hashing
                    newPassword = utils.encrypt_password(request.form['newPassword'])

                    # Update password from database
                    status = mysqldb.updateUserPassword(user, currentPassword, newPassword, request.form['csrf_token'])

                    if status == 0:
                        # successful update
                        if 'edit' in request.path:
                            flash("Password has been successfully changed.", 'success')

                            # Audit changes (edit)
                            mysqldb.auditChanges(
                                session['user'], "edited-password", f"User \'{session['user']['username']}\' changed the account password for user \'{user['username']}\'."
                            )
                            
                        elif 'preferences' in request.path:
                            flash("Password has been successfully updated.", 'success')

                            # Audit changes (preferences)
                            mysqldb.auditChanges(
                                session['user'], "edited-password", f"User \'{session['user']['username']}\' updated their password."
                            )
                    
                    else:
                        # (for preferences) old password is incorrect
                        flash("Old password entered is incorrect. Input your old password in correctly and try again.", 'danger')

                    return redirect(request.base_url)
                
                case "pfp":
                    # Update profile picture
                    pfp = request.files['pfp']
                    
                    if pfp.filename == '':
                        # Return if no image selected
                        flash("No image selected. Please select one.", 'warning')
                        return redirect(request.base_url)
                    
                    if pfp and utils.allowed_file(pfp.filename):
                        if len(pfp.read()) <= 16777216:
                            # Check if file exceeds 16 MB.

                            # reset file cursor
                            pfp.seek(0)

                            if 'edit' in request.path:
                                current_user = mysqldb.getUser(id)
                                edited_user = current_user.copy()
                                edited_user['pfp'] = utils.ProfilePicture(edited_user['username'], pfp.read())

                            elif 'preferences' in request.path:
                                current_user = session['user']
                                edited_user = current_user.copy()
                                edited_user['pfp'] = utils.ProfilePicture(edited_user['username'], pfp.read())
                            
                            # Update profile picture from database
                            status = mysqldb.updateUserPfp(current_user, edited_user)

                            if status:
                                # successful change
                                if 'edit' in request.path:
                                    flash("Changed user's profile picture!", 'success')

                                    # Audit changes (edit)
                                    mysqldb.auditChanges(
                                        session['user'], "edited-pfp", f"User \'{session['user']['username']}\' changed user \'{edited_user['username']}\' profile picture."
                                    )
                                
                                elif 'preferences' in request.path:
                                    flash("Updated profile picture!", 'success')

                                    # Audit changes (preferences)
                                    mysqldb.auditChanges(
                                        session['user'], "updated-pfp", f"User \'{session['user']['username']}\' updated their profile picture."
                                    )

                                    session['user'] = mysqldb.getUser(int(session['user']['id']))
                            
                            else:
                                # Profile picture was the same as before.
                                flash("Nothing to update.", "info")

                            return redirect(request.base_url)
                        
                        else:
                            # Profile picture uploaded was larger than 16MB.
                            flash("Image uploaded exceeded upload size limit of 16MB. Please select a smaller image.", 'error')
                            return redirect(request.base_url)
                    
                    else:
                        # Unsupported image format
                        flash("Invalid image file uploaded. Please upload a valid photo image.", 'error')
                        return redirect(request.base_url)
                
                case _:
                    # Unknown modify parameter
                    flash(f"Unknown modify parameter value: '{modify_type}'.", 'error')
                    return redirect(request.base_url)
                
        else:
            # Nothing changed
            flash("Nothing to modify or update.", 'info')
            return redirect(request.base_url)

@app.route("/fetch")
def fetch():
    """Fetch endpoint for javascript functions."""
    if request.method == 'GET':
        match list(request.args.keys())[0]:
            case "users":
                # Fetch users
                users = mysqldb.getUsers()
                return jsonify(users)
            
            case "roles":
                # Fetch roles
                roles = mysqldb.getRoles()
                return jsonify(roles)
            
            case "perms":
                # Fetch available permissions
                perms = [perm.rule.lstrip("/").split("/")[0] for perm in app.url_map.iter_rules()]
                perms.remove("")
                perms.remove("static")
                return jsonify({"perms": perms})

@app.route("/delete", methods=['POST'])
def delete():
    """Delete endpoint. Requires CSRF token."""
    if request.method == 'POST':
        match list(request.args.keys())[0]:
            case "user":
                # Delete user with id
                user = mysqldb.getUser(int(request.args['user']))

                # Delete user from database
                status = mysqldb.deleteUser(
                    user, request.form['csrf_token']
                )

                # Audit deletion
                mysqldb.auditChanges(
                    session['user'], "deleted-user", f"User \'{session['user']['username']}\' deleted user account \'{user['username']}\'"
                )

                return jsonify({'status': status})

            case "role":
                # Delete role with id
                role = mysqldb.getRole(int(request.args['role']))

                # Delete role from database
                status = mysqldb.removeRole(
                    role, request.form['csrf_token']
                )

                # Audit deletion
                mysqldb.auditChanges(
                    session['user'], "deleted-role", f"User '{session['user']['username']}' deleted role {role['name']}."
                )

                return jsonify({'status': status})

@app.route("/logs")
def logs():
    """Audit logs webpage (for admin and higher)"""
    if request.method == 'GET':
        # Fetch logs from database
        logs = mysqldb.getAuditLogs()
        return render_template("logs.html", logs=logs, user=session['user'])

# Backup DB Loop =============================================
def backup_loop(loop):
    loop.run_forever()

def backup_start(loop):
    loop.create_task(mysqldb.backupDB())
    bkdb_thread = threading.Thread(target = backup_loop, args=(loop,))
    bkdb_thread.start()

loop = asyncio.get_event_loop()
backup_start(loop)

# Make sure 'use_reloader' is disabled (set to False) to prevent 'double loading' on the backup process.
app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)

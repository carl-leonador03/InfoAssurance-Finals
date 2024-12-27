from re import escape
from flask import Flask, request, render_template, redirect, session, flash, url_for, jsonify
from flask_wtf import CSRFProtect

import utils    # utils.py
import asyncio, threading   # for running the auto-backup system for the database.
import copy

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
        session['role'] = utils.getRole(2)
        flash("You must be logged in before proceeding.", 'warning')
        return redirect('login')
    
    elif session['user'] != utils.User(): # session has a user logged in
        session_user = session['user']
        if isinstance(session_user, dict):
            if 'static' not in request.path and request.path != '/' and request.path != '/favicon.ico':
                if not any([perm in request.path for perm in session['role']['perms']]):
                    if request.endpoint in ['fetch', 'delete']:
                        return jsonify({'error_code': 403, 'reason': 'Unauthorized'})
                    else:
                        if request.endpoint not in ['static']:
                            flash("Access denied. You lack permissions to access this.", "error")
                            return redirect('/')
        
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    
    elif request.method == 'POST':
        users = mysqldb.getUsers()

        username = request.form['username']
        password = request.form['password']

        if username in [x['username'] for x in users]:
            user_found = mysqldb.getUser(username)

            if user_found:
                if utils.check_password(mysqldb.getPassword(user_found, request.form['csrf_token']), password):                    
                    session['user'] = user_found
                    session['role'] = user_found['role']
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
    mysqldb.auditChanges(
        session['user'], "logged-out", f"User \'{session['user']['username']}\' logged out."
    )

    session['user'] = utils.User()

    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        roles = utils.ROLES
        return render_template('register.html', roles=roles)
    
    elif request.method == 'POST':
        new_user = utils.User(
            name =      request.form['name'],
            username =  request.form['username'],
            role_id =   request.form['role_id']
        )

        user_exists = mysqldb.getUser(new_user['username'])

        if not user_exists:
            status = mysqldb.createUser(
                new_user,
                request.form['password'],
                request.form['csrf_token']
            )

        if status == 0:
            new_user = mysqldb.getUser(new_user['id'])

            mysqldb.auditChanges(
                session['user'], "created-user", f"User \'{session['user']['username']}\' created a \'{new_user['role']['name']}\' account."
            )

            flash("Account successfully created.", 'success')
            return redirect('/')
        
        elif status == 1:
            flash(f"Account '{new_user['username']}' already exists.", 'error')
            return redirect('/register')            

@app.route('/profile/<int:id>')
def profile(id: int):
    if request.method == 'GET':
        profile = mysqldb.getUser(id)
        return render_template('profile.html', user = session['user'], profile = profile)

@app.route('/preferences', methods=['GET', 'POST'])
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id:int = None):
    """Preferences endpoint (for users)"""
    if request.method == 'GET':
        if session['role']['id'] == 1:
            if request.path == '/preferences':
                return render_template("preferences.html", user=session['user'], edit_user=session['user'])
            else:
                user = mysqldb.getUser(id)
                if user == None:
                    return render_template("preferences.html", user=session['user'], edit_user=user, id=id)
                else:
                    return render_template("preferences.html", user=session['user'], edit_user=user)
        else:
            print(session['user'])
            return render_template("preferences.html", user=session['user'])

    elif request.method == 'POST':
        if "modify" in request.args:
            modify_type = request.args['modify']
            match modify_type:
                case "details":
                    if 'edit' in request.path:
                        current_user = mysqldb.getUser(int(request.form['user_id']))
                        edited_user = current_user.copy()
                    elif 'preferences' in request.path:
                        current_user = session['user']
                        edited_user = current_user.copy()
                    edited_user['name'] = current_user['name'] if '' else request.form['displayname']
                    edited_user['username'] = current_user['username'] if '' else request.form['usernamee']
                    edited_user['address'] = current_user['address'] if '' else request.form['address']
                    edited_user['contact'] = current_user['contact'] if '' else request.form['contact']
                    edited_user['bio'] = current_user['bio'] if '' else request.form['bio']
                    edited_user['theme'] = current_user['theme'] if request.form['theme'] == current_user['theme'] else request.form['theme']

                    if 'edit' in request.path:
                        edited_user['role'] = current_user['role'] if request.form['role'] == current_user['role']['id'] else utils.getRole(int(request.form['role']))

                    status = mysqldb.editUserInfo(current_user, edited_user)

                    if status > 0:
                        if 'edit' in request.path:
                            flash("Account details successfully edited.", 'success')
                            mysqldb.auditChanges(
                                session['user'], "edited-profile", f"User \'{session['user']['username']}\' edited user \'{session['user']['username']}\' details: " + str([attr for attr in edited_user.keys() if edited_user[attr] != current_user[attr] and edited_user[attr] != '']).lstrip("[").rstrip("]")
                            )
                        elif 'preferences' in request.path:
                            flash("Account details successfully updated.", 'success')
                            mysqldb.auditChanges(
                                session['user'], "updated-profile", f"User \'{session['user']['username']}\' updated their profile details: " + str([attr for attr in edited_user.keys() if edited_user[attr] != current_user[attr] and edited_user[attr] != '']).lstrip("[").rstrip("]")
                            )
                        
                        # Update current user with new changes
                        session['user'] = mysqldb.getUser(session['user']['id'])

                    else:
                        flash("Nothing was changed.", 'info')

                    return redirect(request.base_url)
                
                case "password":
                    user = mysqldb.getUser(int(request.form['user_id']))

                    if 'edit' in request.path:
                        currentPassword = mysqldb.getPassword(mysqldb.getUser(id), request.form['csrf_token'])
                    else:
                        currentPassword = request.form['currentPassword']
                    
                    newPassword = utils.encrypt_password(request.form['newPassword'])

                    status = mysqldb.updateUserPassword(user, currentPassword, newPassword, request.form['csrf_token'])

                    if status == 0:
                        if 'edit' in request.path:
                            flash("Password has been successfully changed.", 'success')
                            mysqldb.auditChanges(
                                session['user'], "edited-password", f"User \'{session['user']['username']}\' changed the account password for user \'{user['username']}\'."
                            )
                        elif 'preferences' in request.path:
                            flash("Password has been successfully updated.", 'success')
                            mysqldb.auditChanges(
                                session['user'], "edited-password", f"User \'{session['user']['username']}\' updated their password."
                            )
                    
                    else:
                        flash("Old password entered is incorrect. Input your old password in correctly and try again.", 'danger')

                    return redirect(request.base_url)
                
                case "pfp":
                    pfp = request.files['pfp']
                    print(pfp.filename)
                    
                    if pfp.filename == '':
                        flash("No image selected. Please select one.", 'warning')
                        return redirect(request.base_url)
                    
                    if pfp and utils.allowed_file(pfp.filename):
                        if len(pfp.read()) <= 16777216:
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
                            
                            status = mysqldb.updateUserPfp(current_user, edited_user)

                            if status:
                                if 'edit' in request.path:
                                    flash("Changed user's profile picture!", 'success')
                                    mysqldb.auditChanges(
                                        session['user'], "edited-pfp", f"User \'{session['user']['username']}\' changed user \'{edited_user['username']}\' profile picture."
                                    )
                                
                                elif 'preferences' in request.path:
                                    flash("Updated profile picture!", 'success')
                                    mysqldb.auditChanges(
                                        session['user'], "updated-pfp", f"User \'{session['user']['username']}\' updated their profile picture."
                                    )

                                    session['user'] = mysqldb.getUser(int(session['user']['id']))
                            
                            else:
                                flash("Nothing to update.", "info")

                            return redirect(request.base_url)
                        
                        else:
                            flash("Image uploaded exceeded upload size limit of 16MB. Please select a smaller image.", 'error')
                            return redirect(request.base_url)
                    
                    else:
                        flash("Invalid image file uploaded. Please upload a valid photo image.", 'error')
                        return redirect(request.base_url)
                
                case _:
                    flash(f"Unknown modify parameter value: '{modify_type}'.", 'error')
                    return redirect(request.base_url)
                
        else:
            flash("Nothing to modify or update.", 'info')
            return redirect(request.base_url)

@app.route("/fetch")
def fetch():
    if request.method == 'GET':
        match list(request.args.keys())[0]:
            case "users":
                users = mysqldb.getUsers()
                return jsonify(users)

@app.route("/delete", methods=['POST'])
def delete():
    if request.method == 'POST':
        match list(request.args.keys())[0]:
            case "user":
                user = mysqldb.getUser(int(request.args['user']))

                status = mysqldb.deleteUser(
                    user, request.form['csrf_token']
                )

                mysqldb.auditChanges(
                    session['user'], "deleted-user", f"User \'{session['user']['username']}\' deleted user account \'{user['username']}\'"
                )

                return jsonify({'status': status})

@app.route("/logs")
def logs():
    if request.method == 'GET':
        logs = mysqldb.getAuditLogs()
        return render_template("logs.html", logs=logs, user=session['user'])

def backup_loop(loop):
    loop.run_forever()

def backup_start(loop):
    loop.create_task(mysqldb.backupDB())
    bkdb_thread = threading.Thread(target = backup_loop, args=(loop,))
    bkdb_thread.start()

loop = asyncio.get_event_loop()
backup_start(loop)
app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)

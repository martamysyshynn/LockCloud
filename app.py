from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from flask_mail import Mail, Message
import random
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import re

UPLOAD_FOLDER = 'uploads'

app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def generate_otp():
    return str(random.randint(100000, 999999))

def get_db_connection():
    return mysql.connector.connect(
        host = app.config['MYSQL_HOST'],
        user = app.config['MYSQL_USER'],
        password = app.config['MYSQL_PASSWORD'],
        database = app.config['MYSQL_DB']
    )

def get_user_upload_folder(user_id):
    path = os.path.join(app.config['UPLOAD_FOLDER'], str(user_id))
    os.makedirs(path, exist_ok=True)
    return path

@app.route('/')
def home():
    return render_template('home_page.html')

def validate_password(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long"

    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter"

    if not re.search(r"[0-9]", password):
        return "Password must contain at least one digit"

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Password must contain at least one special character"

    return None

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form['full_name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        two_factor_enabled = 1 if 'two_factor' in request.form else 0
        
        if password != confirm_password:            
            flash("Passwords do not match", "danger")
            return render_template('sign_up_page.html')
        
        error = validate_password(password)
        if error:
            flash(error, "danger")
            return render_template('sign_up_page.html')
        
        hashed_password = generate_password_hash(password)

        connection = get_db_connection()
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO users (full_name, email, password, two_factor_enabled)
                VALUES (%s, %s, %s, %s)
                """,
                (full_name, email, hashed_password, two_factor_enabled)
            )
            connection.commit() 
            flash("Registration successful!", "success")
            return redirect(url_for('signin'))
        except mysql.connector.errors.IntegrityError:
            flash("A user with this email address already exists.", "danger")
        finally:
            cursor.close()
            connection.close()
            return render_template('sign_up_page.html')

    return render_template('sign_up_page.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        if not user:
            flash("Invalid email or password", "danger")
            cursor.close()
            connection.close()
            return redirect(url_for('signin'))

        if user.get('blocked_until') and user['blocked_until'] > datetime.now():
            flash(f"Account temporarily blocked until {user['blocked_until']}", "danger")
            cursor.close()
            connection.close()
            return redirect(url_for('signin'))

        if not check_password_hash(user['password'], password):
            failed_attempts = user['failed_attempts'] + 1
            blocked_until = None

            if failed_attempts >= 3 and user['block_after_failed_logins']:
                blocked_until = datetime.now() + timedelta(minutes=15)
                flash("Account temporarily blocked due to multiple failed login attempts", "danger")
                failed_attempts = 0
            else:
                flash("Invalid email or password", "danger")

            cursor.execute(
                "UPDATE users SET failed_attempts=%s, blocked_until=%s WHERE id=%s",
                (failed_attempts, blocked_until, user['id'])
            )
            connection.commit()
            cursor.close()
            connection.close()
            return redirect(url_for('signin'))

        cursor.execute(
            "UPDATE users SET failed_attempts=0, blocked_until=NULL WHERE id=%s",
            (user['id'],)
        )
        connection.commit()

        if user.get('two_factor_enabled') and user.get('role') != 'admin':
            otp = generate_otp()
            session['temp_user_id'] = user['id']
            session['otp'] = otp

            msg = Message('Your 2FA Code', recipients=[user['email']])
            msg.body = f"Your verification code is: {otp}"
            mail.send(msg)

            cursor.close()
            connection.close()
            return redirect(url_for('two_factor'))

        session['user_id'] = user['id']
        session['user_name'] = user['full_name']
        session['role'] = user['role']

        cursor.execute(
            "INSERT INTO audit_logs (user_id, action, ip_address) VALUES (%s, %s, %s)",
            (user['id'], 'Login', request.remote_addr)
        )
        connection.commit()
        cursor.close()
        connection.close()

        analyze_security(user['id'])

        flash(f"Welcome, {user['full_name']}!", "success")
        return redirect(url_for('admin') if user['role'] == 'admin' else url_for('storage'))

    return render_template('sign_in_page.html')

@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if 'temp_user_id' not in session:
        return redirect(url_for('signin'))
    
    if request.method == 'POST':
        entered_otp = request.form['otp']

        if entered_otp == session.get('otp'):

            user_id = session.pop('temp_user_id')

            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)
            cursor.execute("SELECT role, full_name FROM users WHERE id=%s", (user_id,))
            user = cursor.fetchone()

            cursor_log = connection.cursor()
            cursor_log.execute(
                "INSERT INTO audit_logs (user_id, action, ip_address) VALUES (%s, %s, %s)",
                (user_id, 'Login (2FA)', request.remote_addr)
            )
            connection.commit()

            cursor_log.close()
            cursor.close()
            connection.close()

            session['user_id'] = user_id
            session['role'] = user['role']
            session['user_name'] = user['full_name']

            session.pop('otp')

            flash("2FA verification successful", "success")

            if user['role'] == 'admin':
                return redirect(url_for('admin'))

            return redirect(url_for('storage'))

        else:
            flash("Invalid verification code", "danger")

    return render_template('two_factor.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    connection.close()

    return render_template('profile_page.html', user=user)

@app.route('/profile/update-phone', methods=['POST'])
def update_phone():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    phone = request.form.get('phone')

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "UPDATE users SET phone=%s WHERE id=%s",
        (phone if phone else None, session['user_id'])
    )
    connection.commit()
    cursor.close()
    connection.close()

    flash("Phone number updated", "success")
    return redirect(url_for('profile'))

@app.route('/notifications')
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()

    cursor.execute(
        "SELECT * FROM notifications WHERE user_id=%s ORDER BY created_at DESC",
        (session['user_id'],)
    )
    notifications = cursor.fetchall()

    cursor.close()
    connection.close()
    
    return render_template(
        'profile_notifications_page.html',
        user=user,  
        notifications=notifications
    )

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()
    connection.close()
    
    return render_template('profile_settings_page.html', user=user)

@app.route('/settings/change-password', methods=['POST'])
def change_password():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        flash("New passwords do not match", "danger")
        return redirect(url_for('settings'))
    
    error = validate_password(new_password)
    if error:
        flash(error, "danger")
        return redirect(url_for('settings'))
    
    connection = get_db_connection()

    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT password, email FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()
    cursor.close()  

    if not user or not check_password_hash(user['password'], current_password):
        flash("Current password is incorrect", "danger")
        connection.close()
        return redirect(url_for('settings'))

    hashed_password = generate_password_hash(new_password)

    update_cursor = connection.cursor()
    update_cursor.execute(
        "UPDATE users SET password=%s WHERE id=%s",
        (hashed_password, int(session['user_id']))  # ✅ явний int
    )
    connection.commit()
    update_cursor.close()
    connection.close()

    msg = Message("Password changed", recipients=[user['email']])
    msg.body = "Your password was successfully changed. If this wasn't you, please contact support immediately."
    mail.send(msg)

    flash("Password successfully changed", "success")
    return redirect(url_for('settings'))

@app.route('/settings/change-email', methods=['POST'])
def change_email():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    new_email = request.form['new_email']
    otp = generate_otp()

    session['email_change_otp'] = otp
    session['new_email'] = new_email

    msg = Message(
        "Confirm your new email",
        recipients=[new_email]
    )

    msg.body = f"Your confirmation code is: {otp}"
    mail.send(msg)

    flash("Confirmation code sent to new email", "info")
    return redirect(url_for('confirm_email'))

@app.route('/settings/confirm-email', methods=['GET', 'POST'])
def confirm_email():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    if request.method == 'POST':
        entered_otp = request.form['otp']

        if entered_otp == session.get('email_change_otp'):
            connection = get_db_connection()
            cursor = connection.cursor()
            cursor.execute(
                "UPDATE users SET email=%s WHERE id=%s",
                (session['new_email'], session['user_id'])
            )
            connection.commit()
            cursor.close()
            connection.close()

            session.pop('email_change_otp')
            session.pop('new_email')

            flash("Email successfully updated", "success")
            return redirect(url_for('settings'))

        else:
            flash("Invalid confirmation code", "danger")

    return render_template('confirm_email_page.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT id, email FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()

        cursor.close()
        connection.close()

        if user:
            otp = generate_otp()
            session['reset_otp'] = otp
            session['reset_user_id'] = user['id']

            msg = Message("Password reset code", recipients=[user['email']])
            msg.body = f"Your password reset code is: {otp}"
            mail.send(msg)

        flash("If this email exists, a reset code was sent", "info")
        return redirect(url_for('reset_password'))

    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if 'reset_user_id' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match", "danger")
            return redirect(url_for('reset_password'))
        
        error = validate_password(new_password)
        if error:
            flash(error, "danger")
            return redirect(url_for('reset_password'))

        if otp != session.get('reset_otp'):
            flash("Invalid reset code", "danger")
            return redirect(url_for('reset_password'))

        hashed_password = generate_password_hash(new_password)

        connection = get_db_connection()
        cursor = connection.cursor()
        cursor.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_password, session['reset_user_id']))
        connection.commit()
        cursor.close()
        connection.close()

        session.pop('reset_otp')
        session.pop('reset_user_id')

        flash("Password successfully reset. You can sign in now.", "success")
        return redirect(url_for('signin'))

    return render_template('reset_password.html')

@app.route('/storage/create-folder', methods=['POST'])
def create_folder():
    if 'user_id' not in session:
        return redirect(url_for('signin'))
    
    folder_name = request.form['folder_name']
    folder_id = request.form.get('parent_id')
    if folder_id in (None, '', 'None'):
        folder_id = None
    else:
        folder_id = int(folder_id)

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO folders (name, parent_id, user_id) VALUES (%s, %s, %s)",
        (folder_name, folder_id, session['user_id'])
    )

    connection.commit()
    cursor.close()
    connection.close()

    flash("Folder created", "success")

    return redirect(url_for('storage', folder_id=folder_id))

@app.route('/storage/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    file = request.files['file']
    folder_id = request.form.get('folder_id')
    if folder_id in (None, '', 'None'):
        folder_id = None
    else:
        folder_id = int(folder_id)

    if file.filename == '':
        flash("No file selected", "danger")
        return redirect(url_for('storage'))

    filename = secure_filename(file.filename)
    stored_name = f"{random.randint(100000,999999)}_{filename}"

    user_folder = get_user_upload_folder(session['user_id'])
    file_path = os.path.join(user_folder, stored_name)

    file.save(file_path)

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        INSERT INTO files (filename, stored_name, size, user_id, folder_id)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            filename,
            stored_name,
            os.path.getsize(file_path),
            session['user_id'],
            folder_id
        )
    )

    connection.commit()
    cursor.close()
    connection.close()

    flash("File uploaded", "success")

    return redirect(url_for('storage', folder_id=folder_id))

@app.route('/storage')
def storage():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    folder_id = request.args.get('folder_id')
    search = request.args.get('search')

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if folder_id:

        if search:
            cursor.execute(
                """
                SELECT * FROM folders
                WHERE user_id=%s
                AND parent_id=%s
                AND name LIKE %s
                AND is_deleted=0
                """,
                (session['user_id'], folder_id, f"%{search}%")
            )
        else:
            cursor.execute(
                """
                SELECT * FROM folders
                WHERE user_id=%s
                AND parent_id=%s
                AND is_deleted=0
                """,
                (session['user_id'], folder_id)
            )

        folders = cursor.fetchall()

        if search:
            cursor.execute(
                """
                SELECT * FROM files
                WHERE user_id=%s
                AND folder_id=%s
                AND filename LIKE %s
                AND is_deleted=0
                """,
                (session['user_id'], folder_id, f"%{search}%")
            )
        else:
            cursor.execute(
                """
                SELECT * FROM files
                WHERE user_id=%s
                AND folder_id=%s
                AND is_deleted=0
                """,
                (session['user_id'], folder_id)
            )

        files = cursor.fetchall()

    else:

        if search:
            cursor.execute(
                """
                SELECT * FROM folders
                WHERE user_id=%s
                AND parent_id IS NULL
                AND name LIKE %s
                AND is_deleted=0
                """,
                (session['user_id'], f"%{search}%")
            )
        else:
            cursor.execute(
                """
                SELECT * FROM folders
                WHERE user_id=%s
                AND parent_id IS NULL
                AND is_deleted=0
                """,
                (session['user_id'],)
            )

        folders = cursor.fetchall()

        if search:
            cursor.execute(
                """
                SELECT * FROM files
                WHERE user_id=%s
                AND filename LIKE %s
                AND is_deleted=0
                """,
                (session['user_id'], f"%{search}%")
            )
        else:
            cursor.execute(
                """
                SELECT * FROM files
                WHERE user_id=%s
                AND folder_id IS NULL
                AND is_deleted=0
                """,
                (session['user_id'],)
            )

        files = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        'storage_page.html',
        folders=folders,
        files=files,
        current_folder_id=folder_id
    )

@app.route('/storage/file/<int:file_id>')
def open_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM files WHERE id=%s AND user_id=%s",
        (file_id, session['user_id'])
    )
    file = cursor.fetchone()

    cursor.close()
    connection.close()

    if not file:
        flash("File not found", "danger")
        return redirect(url_for('storage'))

    file_path = os.path.join(
        app.config['UPLOAD_FOLDER'],
        str(session['user_id']),
        file['stored_name']
    )

    return send_file(file_path)

@app.route('/storage/delete-folder/<int:folder_id>', methods=['POST'])
def delete_folder(folder_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "UPDATE folders SET is_deleted=1 WHERE id=%s AND user_id=%s",
        (folder_id, session['user_id'])
    )

    cursor.execute(
        "UPDATE files SET is_deleted=1 WHERE folder_id=%s AND user_id=%s",
        (folder_id, session['user_id'])
    )
    
    cursor.execute(
        "INSERT INTO audit_logs (user_id, action, ip_address) VALUES (%s, %s, %s)",
        (session['user_id'], 'Delete folder', request.remote_addr)
    )

    connection.commit()
    cursor.close()
    connection.close()

    flash("Folder moved to trash", "success")
    return redirect(url_for('storage'))

@app.route('/storage/delete-file/<int:file_id>', methods=['POST'])
def delete_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    folder_id = request.form.get('folder_id')
    if folder_id in (None, '', 'None'):
        folder_id = None
    else:
        folder_id = int(folder_id)

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "UPDATE files SET is_deleted=1 WHERE id=%s AND user_id=%s",
        (file_id, session['user_id'])
    )
    cursor.execute(
        "INSERT INTO audit_logs (user_id, action, ip_address) VALUES (%s, %s, %s)",
        (session['user_id'], 'Delete file', request.remote_addr)
    )

    connection.commit()
    cursor.close()
    connection.close()

    flash("File moved to trash", "success")
    return redirect(url_for('storage', folder_id=folder_id))

@app.route('/trash')
def trash():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM folders WHERE user_id=%s AND is_deleted=1",
        (session['user_id'],)
    )
    folders = cursor.fetchall()

    cursor.execute(
        "SELECT * FROM files WHERE user_id=%s AND is_deleted=1",
        (session['user_id'],)
    )
    files = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template("trash_page.html", files=files, folders=folders)

@app.route('/restore-folder/<int:folder_id>', methods=['POST'])
def restore_folder(folder_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE folders SET is_deleted=0 WHERE id=%s AND user_id=%s",
        (folder_id, session['user_id'])
    )

    cursor.execute(
        "UPDATE files SET is_deleted=0 WHERE folder_id=%s AND user_id=%s",
        (folder_id, session['user_id'])
    )
    connection.commit()
    cursor.close()
    connection.close()

    flash("Folder restored", "success")
    return redirect(url_for('trash'))


@app.route('/delete-folder-permanently/<int:folder_id>', methods=['POST'])
def delete_folder_permanently(folder_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM files WHERE folder_id=%s AND user_id=%s",
        (folder_id, session['user_id'])
    )
    files_in_folder = cursor.fetchall()
    cursor.close()

    delete_cursor = connection.cursor()
    for file in files_in_folder:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']), file['stored_name'])
        if os.path.exists(file_path):
            os.remove(file_path)
        delete_cursor.execute("DELETE FROM files WHERE id=%s", (file['id'],))

    delete_cursor.execute(
        "DELETE FROM folders WHERE id=%s AND user_id=%s",
        (folder_id, session['user_id'])
    )
    connection.commit()
    delete_cursor.close()
    connection.close()

    flash("Folder permanently deleted", "success")
    return redirect(url_for('trash'))

@app.route('/restore-file/<int:file_id>', methods=['POST'])
def restore_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "UPDATE files SET is_deleted=0 WHERE id=%s AND user_id=%s",
        (file_id, session['user_id'])
    )

    connection.commit()
    cursor.close()
    connection.close()

    flash("File restored", "success")
    return redirect(url_for('trash'))


@app.route('/delete-file-permanently/<int:file_id>', methods=['POST'])
def delete_file_permanently(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute(
        "SELECT * FROM files WHERE id=%s AND user_id=%s",
        (file_id, session['user_id'])
    )
    file = cursor.fetchone()
    cursor.close()

    if file:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']), file['stored_name'])
        if os.path.exists(file_path):
            os.remove(file_path)

        delete_cursor = connection.cursor()
        delete_cursor.execute("DELETE FROM files WHERE id=%s", (file_id,))
        connection.commit()
        delete_cursor.close()

    connection.close()

    flash("File permanently deleted", "success")
    return redirect(url_for('trash'))


@app.route('/storage/share-file/<int:file_id>', methods=['POST'])
def share_file(file_id):
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    email = request.form['email']

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
    user = cursor.fetchone()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('storage'))

    cursor.execute(
        """
        INSERT INTO shared_files (file_id, owner_id, shared_with_user_id)
        VALUES (%s, %s, %s)
        """,
        (file_id, session['user_id'], user['id'])
    )

    connection.commit()
    cursor.close()
    connection.close()

    flash("File shared successfully", "success")
    return redirect(url_for('storage'))

@app.route('/shared')
def shared():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT files.*
        FROM files
        JOIN shared_files ON files.id = shared_files.file_id
        WHERE shared_files.shared_with_user_id = %s
    """, (session['user_id'],))

    files = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template("shared_page.html", files=files)

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been signed out", "info")
    return redirect(url_for('signin'))

@app.route('/admin')
def admin():

    if 'user_id' not in session:
        return redirect(url_for('signin'))

    if session.get('role') != 'admin':
        return redirect(url_for('storage'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT id, full_name, email FROM users")
    users = cursor.fetchall()

    return render_template('admin_page.html', users=users)

@app.route('/admin/user/<int:user_id>')
def user_details(user_id):

    if 'user_id' not in session:
        return redirect(url_for('signin'))

    if session.get('role') != 'admin':
        return redirect(url_for('storage'))

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, full_name, email,
               block_after_failed_logins,
               temporary_block,
               notify_on_suspicious,
               blocked_until
        FROM users
        WHERE id=%s
    """, (user_id,))
    user = cursor.fetchone()

    cursor.execute("""
        SELECT created_at, action, ip_address
        FROM audit_logs
        WHERE user_id=%s
        ORDER BY created_at DESC
        LIMIT 10
    """, (user_id,))
    logs = cursor.fetchall()

    cursor.close()
    connection.close()

    alerts = analyze_security(user_id)

    return render_template('user_details.html', user=user, logs=logs, alerts=alerts)

@app.route('/admin/update-security/<int:user_id>', methods=['POST'])
def update_security_rules(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('signin'))

    block_after = 1 if 'block_after_failed_logins' in request.form else 0
    temp_block = 1 if 'temporary_block' in request.form else 0
    notify = 1 if 'notify_on_suspicious' in request.form else 0

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("""
        UPDATE users
        SET block_after_failed_logins=%s,
            temporary_block=%s,
            notify_on_suspicious=%s
        WHERE id=%s
    """, (block_after, temp_block, notify, user_id))

    connection.commit()
    cursor.close()
    connection.close()

    flash("Security rules updated", "success")
    return redirect(url_for('user_details', user_id=user_id))

@app.route('/admin/unblock-user/<int:user_id>', methods=['POST'])
def unlock_user(user_id):
    if 'user_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('signin'))

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "UPDATE users SET failed_attempts=0, blocked_until=NULL WHERE id=%s",
        (user_id,)
    )
    connection.commit()
    cursor.close()
    connection.close()

    flash("User has been unblocked", "success")
    return redirect(url_for('user_details', user_id=user_id))

def analyze_security(user_id):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT action, ip_address, created_at
        FROM audit_logs
        WHERE user_id=%s
        ORDER BY created_at DESC
        LIMIT 20
    """, (user_id,))
    
    logs = cursor.fetchall()

    alerts = []

    if not logs:
        return alerts

    last_ip = logs[0]['ip_address']
    for log in logs[1:]:
        if log['ip_address'] != last_ip:
            alerts.append({
                "type": "ip",
                "message": "Login from new IP address",
                "details": log['ip_address']
            })
            break

    for log in logs:
        hour = log['created_at'].hour
        if hour >= 0 and hour <= 6:
            alerts.append({
                "type": "time",
                "message": "Unusual login time",
                "details": f"{hour}:00"
            })
            break

    delete_count = 0
    for log in logs:
        if log['action'] in ['Delete file', 'Delete folder']:
            delete_count += 1

    if delete_count >= 5:
        alerts.append({
            "type": "delete",
            "message": "Mass deletion detected",
            "details": f"{delete_count} actions"
        })

   
    cursor.execute("SELECT notify_on_suspicious FROM users WHERE id=%s", (user_id,))
    user_settings = cursor.fetchone()

    if user_settings and user_settings['notify_on_suspicious']:
        for alert in alerts:
            create_notification(user_id, alert['message'])

    cursor.close()
    connection.close()

    return alerts

def create_notification(user_id, message):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO notifications (user_id, message) VALUES (%s, %s)",
        (user_id, message)
    )

    connection.commit()
    cursor.close()
    connection.close()

if __name__ == '__main__':
    app.run(debug=True)

    


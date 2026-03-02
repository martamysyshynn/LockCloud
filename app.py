from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from flask_mail import Mail, Message
import random
import os
from werkzeug.utils import secure_filename

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

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        session.pop('otp', None)
        session.pop('temp_user_id', None)

        email = request.form['email']
        password = request.form['password']

        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        connection.close()

        if user and check_password_hash(user['password'], password):

            if user['two_factor_enabled']:
                if 'otp' not in session:
                    otp = generate_otp()
                    session['temp_user_id'] = user['id'] 
                    session['otp'] = otp

                    msg = Message('Your 2FA Code', recipients=[user['email']])
                    msg.body = f"Your verification code is: {otp}"
                    mail.send(msg)

                return redirect(url_for('two_factor'))
            
            session['user_id'] = user['id']
            session['user_name'] = user['full_name']
            flash(f"Welcome, {user['full_name']}!", "success")
            return redirect(url_for('home'))
 

    return render_template('sign_in_page.html')

@app.route('/two-factor', methods=['GET', 'POST'])
def two_factor():
    if 'temp_user_id' not in session:
        return redirect(url_for('signin'))
    
    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session.get('otp'):
            session['user_id'] = session.pop('temp_user_id')
            session.pop('otp')
            flash("2FA verification successful", "success")
            return redirect(url_for('profile'))
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
    cursor.close()
    connection.close()
    
    return render_template('profile_notifications_page.html', user=user)

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
    
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    cursor.execute("SELECT password, email FROM users WHERE id=%s", (session['user_id'],))
    user = cursor.fetchone()

    if not check_password_hash(user['password'], current_password):
        flash("Current password is incorrect", "danger")
        cursor.close()
        connection.close()
        return redirect(url_for('settings'))

    hashed_password = generate_password_hash(new_password)

    cursor.execute("UPDATE users SET password=%s WHERE id=%s", (hashed_password, session['user_id']))
    connection.commit()
    cursor.close()
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
    parent_id = request.form.get('parent_id')

    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO folders (name, parent_id, user_id) VALUES (%s, %s, %s)",
        (folder_name, parent_id, session['user_id'])
    )

    connection.commit()
    cursor.close()
    connection.close()

    flash("Folder created", "success")
    return redirect(url_for('storage'))

@app.route('/storage/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    file = request.files['file']
    folder_id = request.form.get('folder_id')

    if file.filename == '':
        flash("No file selected", "danger")
        return redirect(url_for('stoarge'))

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
    return redirect(url_for('storage'))

@app.route('/storage')
def storage():
    if 'user_id' not in session:
        return redirect(url_for('signin'))

    folder_id = request.args.get('folder_id')

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    if folder_id:
        cursor.execute(
            "SELECT * FROM folders WHERE user_id=%s AND parent_id=%s",
            (session['user_id'], folder_id)
        )
        folders = cursor.fetchall()

        cursor.execute(
            "SELECT * FROM files WHERE user_id=%s AND folder_id=%s",
            (session['user_id'], folder_id)
        )
        files = cursor.fetchall()
    else:
        cursor.execute(
            "SELECT * FROM folders WHERE user_id=%s AND parent_id IS NULL",
            (session['user_id'],)
        )
        folders = cursor.fetchall()

        cursor.execute(
            "SELECT * FROM files WHERE user_id=%s AND folder_id IS NULL",
            (session['user_id'],)
        )
        files = cursor.fetchall()

    cursor.close()
    connection.close()

    return render_template(
        'storage_page.html',
        folders=folders,
        files=files
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


if __name__ == '__main__':
    app.run(debug=False)

    


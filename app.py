from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from flask_mail import Mail, Message
import random


app = Flask(__name__)
app.config.from_object(Config)
mail = Mail(app)

def generate_otp():
    return str(random.randint(100000, 999999))

def get_db_connection():
    return mysql.connector.connect(
        host = app.config['MYSQL_HOST'],
        user = app.config['MYSQL_USER'],
        password = app.config['MYSQL_PASSWORD'],
        database = app.config['MYSQL_DB']
    )

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


if __name__ == '__main__':
    app.run(debug=True)

    


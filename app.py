from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
import requests
import json
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import os
from dotenv import load_dotenv
import re
import pyotp
import qrcode
from io import BytesIO
import base64 as b64
from email_validator import validate_email as email_validate, EmailNotValidError
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY','81e4d43525b60123b078435d6186c9a1c66ce2e406584f0da936178d8a8aecee')

# Database setup
DATABASE = 'passwords.db' 

def init_db():
    """Initialize the database with required tables"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    # Check if we need to migrate from old schema
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    users_table_exists = cursor.fetchone() is not None
    
    if not users_table_exists:
        # Check if accounts table exists with old schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='accounts'")
        accounts_exists = cursor.fetchone() is not None
        
        if accounts_exists:
            # Check if user_id column exists
            cursor.execute("PRAGMA table_info(accounts)")
            columns = [column[1] for column in cursor.fetchall()]
            if 'user_id' not in columns:
                # Migrate existing data
                migrate_to_multi_user(cursor)
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            master_pin TEXT NOT NULL,
            salt TEXT NOT NULL,
            otp_secret TEXT,
            otp_enabled INTEGER DEFAULT 0,
            security_question1 TEXT,
            security_answer1 TEXT,
            security_question2 TEXT,
            security_answer2 TEXT,
            security_question3 TEXT,
            security_answer3 TEXT,
            email_otp_code TEXT,
            email_otp_expires TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create accounts table with user_id foreign key
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()

def migrate_to_multi_user(cursor):
    """Migrate existing single-user data to multi-user schema"""
    try:
        # Backup existing accounts
        cursor.execute('SELECT * FROM accounts')
        old_accounts = cursor.fetchall()
        
        # Drop old table and recreate with new schema
        cursor.execute('DROP TABLE accounts')
        
        # Create users table first
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                master_pin TEXT NOT NULL,
                salt TEXT NOT NULL,
                otp_secret TEXT,
                otp_enabled INTEGER DEFAULT 0,
                security_question1 TEXT,
                security_answer1 TEXT,
                security_question2 TEXT,
                security_answer2 TEXT,
                security_question3 TEXT,
                security_answer3 TEXT,
                email_otp_code TEXT,
                email_otp_expires TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default user
        default_pin_encrypted, default_salt = encrypt_master_pin("1234")
        cursor.execute(
            'INSERT INTO users (username, email, name, master_pin, salt) VALUES (?, ?, ?, ?, ?)',
            ('admin', 'admin@example.com', 'Default User', default_pin_encrypted, default_salt)
        )
        default_user_id = cursor.lastrowid
        
        # Recreate accounts table with user_id
        cursor.execute('''
            CREATE TABLE accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                website TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                salt TEXT NOT NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Migrate old accounts to default user
        for account in old_accounts:
            try:
                cursor.execute(
                    'INSERT INTO accounts (user_id, website, username, password, salt, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (default_user_id, account[1], account[2], account[3], account[4], account[5] if len(account) > 5 else '', account[6] if len(account) > 6 else 'CURRENT_TIMESTAMP', account[7] if len(account) > 7 else 'CURRENT_TIMESTAMP')
                )
            except Exception:
                # Skip corrupted accounts
                continue
                
    except Exception:
        # If migration fails, just create empty tables
        pass

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_master_key():
    """Get or create master key for encryption"""
    if 'master_key' not in session:
        # For registration/migration, create a temporary key
        session['master_key'] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    return session['master_key']

def get_registration_master_key():
    """Get a consistent master key for user registration"""
    # Use a fixed key for encrypting master PINs during registration
    # This ensures all user PINs can be decrypted later
    return base64.urlsafe_b64encode(b'registration_master_key_v1_fixed').decode()

def validate_email(email):
    """Validate email format using email-validator library"""
    try:
        email_validate(email)
        return True
    except EmailNotValidError:
        return False

def send_email_otp(email, otp_code, name):
    """Send OTP via email"""
    try:
        # Check if email settings are configured
        smtp_server = os.environ.get('SMTP_SERVER')
        smtp_port = int(os.environ.get('SMTP_PORT', 587))
        smtp_username = os.environ.get('SMTP_USERNAME')
        smtp_password = os.environ.get('SMTP_PASSWORD')
        
        if not all([smtp_server, smtp_username, smtp_password]):
            print(f"📧 Email OTP for {name} ({email}): {otp_code}")
            print(f"This OTP will expire in 5 minutes.")
            print("⚠️  To enable real email sending, configure SMTP settings in .env file")
            return True
        
        # Real email sending
        msg = MIMEMultipart()
        msg['From'] = smtp_username
        msg['To'] = email
        msg['Subject'] = "Password Manager - Login OTP"
        
        body = f"""
Hello {name},

Your login OTP is: {otp_code}

This code will expire in 5 minutes.

If you didn't request this code, please ignore this email.

Best regards,
Password Manager Team
"""
        
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.send_message(msg)
        server.quit()
        
        print(f"✅ Email OTP sent successfully to {email}")
        return True
        
    except Exception as e:
        print(f"Failed to send email OTP: {e}")
        # Fallback to console output if email fails
        print(f"📧 FALLBACK - Email OTP for {name} ({email}): {otp_code}")
        return True

def generate_email_otp():
    """Generate a 6-digit OTP for email verification"""
    return str(random.randint(100000, 999999))

def generate_totp_secret():
    """Generate a new TOTP secret for authenticator app"""
    return pyotp.random_base32()

def get_totp_qr_code(secret, email, username):
    """Generate QR code for TOTP setup"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=f"Password Manager ({username})"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    
    return b64.b64encode(buffer.getvalue()).decode()

def verify_totp(secret, token):
    """Verify TOTP token"""
    totp = pyotp.TOTP(secret)
    return totp.verify(token, valid_window=1)

def get_security_questions():
    """Return predefined security questions"""
    return [
        "What was the name of your first pet?",
        "What city were you born in?",
        "What was your mother's maiden name?",
        "What was the name of your elementary school?",
        "What was your favorite childhood book?",
        "What was the make of your first car?",
        "What was your childhood nickname?",
        "What was the name of your favorite teacher?",
        "What street did you grow up on?",
        "What was your favorite food as a child?"
    ]

def encrypt_master_pin(pin: str) -> tuple:
    """Encrypt master PIN using AES-GCM with salt"""
    salt = os.urandom(16)
    
    master_password = get_registration_master_key().encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password)
    
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(pin.encode()) + encryptor.finalize()
    encrypted_data = iv + encryptor.tag + ciphertext
    
    return base64.urlsafe_b64encode(encrypted_data).decode(), base64.urlsafe_b64encode(salt).decode()

def verify_master_pin(identifier, pin):
    """Verify master PIN for user using email or username"""
    conn = get_db_connection()
    # Try to find user by email first, then by username
    user = conn.execute('SELECT * FROM users WHERE email = ? OR username = ?', (identifier, identifier)).fetchone()
    conn.close()
    
    if not user:
        return False
    
    try:
        # Decrypt stored PIN and compare
        master_password = get_registration_master_key().encode()
        salt = base64.urlsafe_b64decode(user['salt'].encode())
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(master_password)
        
        encrypted_data = base64.urlsafe_b64decode(user['master_pin'].encode())
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted_pin = plaintext.decode()
        
        return decrypted_pin == pin
    except Exception:
        return False

def require_auth(f):
    """Decorator to require authentication"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive encryption key from master password using PBKDF2"""
    master_password = get_master_key().encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(master_password)

def encrypt_password(password: str) -> tuple:
    """Encrypt password using AES-GCM with user's master PIN and salt"""
    # Generate a random salt for this password
    salt = os.urandom(16)
    
    # Get the user's master PIN from session
    if 'user_master_pin' not in session:
        raise Exception("No master PIN in session")
    
    # Derive key from user's master PIN and salt
    master_password = session['user_master_pin'].encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(master_password)
    
    # Generate random IV
    iv = os.urandom(12)
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt password
    ciphertext = encryptor.update(password.encode()) + encryptor.finalize()
    
    # Combine IV, tag, and ciphertext
    encrypted_data = iv + encryptor.tag + ciphertext
    
    return base64.urlsafe_b64encode(encrypted_data).decode(), base64.urlsafe_b64encode(salt).decode()

def decrypt_password(encrypted_password: str, salt_b64: str) -> str:
    """Decrypt password using AES-GCM with user's master PIN"""
    try:
        # Get the user's master PIN from session
        if 'user_master_pin' not in session:
            return "[No master PIN in session]"
        
        # Decode from base64
        encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        
        # Extract IV, tag, and ciphertext
        if len(encrypted_data) < 28:  # Minimum: 12 (IV) + 16 (tag)
            return "[Corrupted data]"
            
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        # Derive key using the user's master PIN
        master_password = session['user_master_pin'].encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(master_password)
        
        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode()
    except Exception as e:
        return f"[Decryption failed: {type(e).__name__}]"

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login and registration"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'login':
            identifier = request.form['identifier']  # Can be email or username
            pin = request.form['pin']
            
            if verify_master_pin(identifier, pin):
                conn = get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE email = ? OR username = ?', (identifier, identifier)).fetchone()
                conn.close()
                
                # Generate email OTP for verification
                otp_code = generate_email_otp()
                otp_expires = datetime.now() + timedelta(minutes=5)
                
                # Store OTP in database
                conn = get_db_connection()
                conn.execute('UPDATE users SET email_otp_code = ?, email_otp_expires = ? WHERE id = ?',
                           (otp_code, otp_expires, user['id']))
                conn.commit()
                conn.close()
                
                # Send OTP via email
                if send_email_otp(user['email'], otp_code, user['name']):
                    session['temp_user_id'] = user['id']
                    session['temp_username'] = user['username']
                    session['temp_email'] = user['email']
                    session['temp_name'] = user['name']
                    session['temp_pin'] = pin
                    
                    flash('OTP sent to your email. Please check your email and enter the code.', 'success')
                    return render_template('otp_verification.html')
                else:
                    flash('Failed to send OTP. Please try again.', 'error')
            else:
                flash('Invalid email/username or PIN!', 'error')
                
        elif action == 'register':
            username = request.form['new_username']
            email = request.form['email']
            name = request.form['name']
            pin = request.form['new_pin']
            
            # Security questions
            security_q1 = request.form['security_question1']
            security_a1 = request.form['security_answer1'].lower().strip()
            security_q2 = request.form['security_question2']
            security_a2 = request.form['security_answer2'].lower().strip()
            security_q3 = request.form['security_question3']
            security_a3 = request.form['security_answer3'].lower().strip()
            
            # Validation
            if not validate_email(email):
                flash('Please enter a valid email address!', 'error')
                return render_template('login.html', security_questions=get_security_questions())
                
            if len(pin) < 4 or len(pin) > 6:
                flash('PIN must be 4-6 digits!', 'error')
                return render_template('login.html', security_questions=get_security_questions())
                
            if not all([security_a1, security_a2, security_a3]):
                flash('Please answer all security questions!', 'error')
                return render_template('login.html', security_questions=get_security_questions())
            
            conn = get_db_connection()
            
            # Check if username already exists
            existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if existing_user:
                flash('Username already exists!', 'error')
                conn.close()
                return render_template('login.html', security_questions=get_security_questions())
                
            # Check if email already exists
            existing_email = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if existing_email:
                flash('Email already exists!', 'error')
                conn.close()
                return render_template('login.html', security_questions=get_security_questions())
            
            # Create new user with security questions
            encrypted_pin, salt = encrypt_master_pin(pin)
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO users (username, email, name, master_pin, salt, 
                   security_question1, security_answer1, security_question2, security_answer2, 
                   security_question3, security_answer3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                (username, email, name, encrypted_pin, salt,
                 security_q1, security_a1, security_q2, security_a2, security_q3, security_a3)
            )
            conn.commit()
            
            user_id = cursor.lastrowid
            conn.close()
            
            session['user_id'] = user_id
            session['username'] = username
            session['email'] = email
            session['name'] = name
            session['user_master_pin'] = pin
            
            flash(f'Welcome, {name}! Your account has been created.', 'success')
            return redirect(url_for('index'))
    
    return render_template('login.html', security_questions=get_security_questions())

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    """Verify OTP for login"""
    if 'temp_user_id' not in session:
        flash('Session expired. Please login again.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        entered_otp = request.form['otp_code']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['temp_user_id'],)).fetchone()
        
        if user and user['email_otp_code'] == entered_otp:
            # Check if OTP has not expired
            otp_expires = datetime.strptime(user['email_otp_expires'], '%Y-%m-%d %H:%M:%S.%f')
            if datetime.now() <= otp_expires:
                # Clear OTP from database
                conn.execute('UPDATE users SET email_otp_code = NULL, email_otp_expires = NULL WHERE id = ?',
                           (session['temp_user_id'],))
                conn.commit()
                conn.close()
                
                # Complete login
                session['user_id'] = session.pop('temp_user_id')
                session['username'] = session.pop('temp_username')
                session['email'] = session.pop('temp_email')
                session['name'] = session.pop('temp_name')
                session['user_master_pin'] = session.pop('temp_pin')
                
                flash(f'Welcome back, {session["name"]}!', 'success')
                return redirect(url_for('index'))
            else:
                flash('OTP has expired. Please login again.', 'error')
                conn.close()
                session.clear()
                return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
            conn.close()
    
    return render_template('otp_verification.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Password recovery using security questions"""
    if request.method == 'POST':
        if 'step' not in request.form:
            # Step 1: Verify email/username
            identifier = request.form['identifier']
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE email = ? OR username = ?', (identifier, identifier)).fetchone()
            
            if user and user['security_question1']:
                conn.close()
                session['recovery_user_id'] = user['id']
                return render_template('security_questions.html', 
                                     questions=[user['security_question1'], user['security_question2'], user['security_question3']])
            else:
                conn.close()
                flash('User not found or security questions not set up.', 'error')
        else:
            # Step 2: Verify security questions
            if 'recovery_user_id' not in session:
                flash('Session expired. Please try again.', 'error')
                return redirect(url_for('forgot_password'))
            
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE id = ?', (session['recovery_user_id'],)).fetchone()
            
            answer1 = request.form['answer1'].lower().strip()
            answer2 = request.form['answer2'].lower().strip()
            answer3 = request.form['answer3'].lower().strip()
            
            if (user['security_answer1'] == answer1 and 
                user['security_answer2'] == answer2 and 
                user['security_answer3'] == answer3):
                
                conn.close()
                return render_template('reset_pin.html')
            else:
                conn.close()
                flash('Incorrect answers to security questions.', 'error')
                session.pop('recovery_user_id', None)
                return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

@app.route('/reset_pin', methods=['POST'])
def reset_pin():
    """Reset master PIN after security question verification"""
    if 'recovery_user_id' not in session:
        flash('Session expired. Please try again.', 'error')
        return redirect(url_for('forgot_password'))
    
    new_pin = request.form['new_pin']
    confirm_pin = request.form['confirm_pin']
    
    if len(new_pin) < 4 or len(new_pin) > 6:
        flash('PIN must be 4-6 digits!', 'error')
        return render_template('reset_pin.html')
    
    if new_pin != confirm_pin:
        flash('PINs do not match!', 'error')
        return render_template('reset_pin.html')
    
    # Update PIN in database
    encrypted_pin, salt = encrypt_master_pin(new_pin)
    conn = get_db_connection()
    conn.execute('UPDATE users SET master_pin = ?, salt = ? WHERE id = ?',
                (encrypted_pin, salt, session['recovery_user_id']))
    conn.commit()
    conn.close()
    
    session.pop('recovery_user_id', None)
    flash('Master PIN has been reset successfully! Please login with your new PIN.', 'success')
    return redirect(url_for('login'))

@app.route('/setup_totp')
@require_auth
def setup_totp():
    """Setup TOTP (Authenticator app) for the user"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if not user['otp_secret']:
        # Generate new secret
        secret = generate_totp_secret()
        conn.execute('UPDATE users SET otp_secret = ? WHERE id = ?', (secret, session['user_id']))
        conn.commit()
    else:
        secret = user['otp_secret']
    
    conn.close()
    
    # Generate QR code
    qr_code = get_totp_qr_code(secret, session['email'], session['username'])
    
    return render_template('setup_totp.html', qr_code=qr_code, secret=secret)

@app.route('/enable_totp', methods=['POST'])
@require_auth
def enable_totp():
    """Enable TOTP after verification"""
    token = request.form['totp_token']
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    if verify_totp(user['otp_secret'], token):
        conn.execute('UPDATE users SET otp_enabled = 1 WHERE id = ?', (session['user_id'],))
        conn.commit()
        conn.close()
        flash('TOTP enabled successfully!', 'success')
    else:
        conn.close()
        flash('Invalid TOTP token. Please try again.', 'error')
    
    return redirect(url_for('settings'))

@app.route('/disable_totp', methods=['POST'])
@require_auth
def disable_totp():
    """Disable TOTP for the user"""
    conn = get_db_connection()
    conn.execute('UPDATE users SET otp_enabled = 0 WHERE id = ?', (session['user_id'],))
    conn.commit()
    conn.close()
    
    flash('Two-factor authentication has been disabled.', 'success')
    return redirect(url_for('settings'))

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/settings', methods=['GET', 'POST'])
@require_auth
def settings():
    """User settings page"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_profile':
            new_username = request.form['username']
            new_email = request.form['email']
            new_name = request.form['name']
            
            # Validate email
            if not validate_email(new_email):
                flash('Please enter a valid email address!', 'error')
                conn = get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                totp_enabled = bool(user['otp_enabled']) if user else False
                return render_template('settings.html', 
                                     totp_enabled=totp_enabled,
                                     security_questions=get_security_questions(),
                                     user_security_q1=user['security_question1'] if user else '',
                                     user_security_q2=user['security_question2'] if user else '',
                                     user_security_q3=user['security_question3'] if user else '')
            
            conn = get_db_connection()
            
            # Check if new username is taken by another user
            if new_username != session['username']:
                existing_user = conn.execute('SELECT * FROM users WHERE username = ? AND id != ?', 
                                           (new_username, session['user_id'])).fetchone()
                if existing_user:
                    flash('Username already taken!', 'error')
                    conn.close()
                    conn = get_db_connection()
                    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                    conn.close()
                    totp_enabled = bool(user['otp_enabled']) if user else False
                    return render_template('settings.html', 
                                         totp_enabled=totp_enabled,
                                         security_questions=get_security_questions(),
                                         user_security_q1=user['security_question1'] if user else '',
                                         user_security_q2=user['security_question2'] if user else '',
                                         user_security_q3=user['security_question3'] if user else '')
            
            # Check if new email is taken by another user
            if new_email != session['email']:
                existing_email = conn.execute('SELECT * FROM users WHERE email = ? AND id != ?', 
                                            (new_email, session['user_id'])).fetchone()
                if existing_email:
                    flash('Email already taken!', 'error')
                    conn.close()
                    conn = get_db_connection()
                    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                    conn.close()
                    totp_enabled = bool(user['otp_enabled']) if user else False
                    return render_template('settings.html', 
                                         totp_enabled=totp_enabled,
                                         security_questions=get_security_questions(),
                                         user_security_q1=user['security_question1'] if user else '',
                                         user_security_q2=user['security_question2'] if user else '',
                                         user_security_q3=user['security_question3'] if user else '')
            
            # Update user profile
            conn.execute('UPDATE users SET username = ?, email = ?, name = ? WHERE id = ?',
                        (new_username, new_email, new_name, session['user_id']))
            conn.commit()
            conn.close()
            
            # Update session
            session['username'] = new_username
            session['email'] = new_email
            session['name'] = new_name
            
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('settings'))
            
        elif action == 'change_pin':
            current_pin = request.form['current_pin']
            new_pin = request.form['new_pin']
            confirm_pin = request.form['confirm_pin']
            otp_code = request.form.get('otp_code', '')
            
            # Verify current PIN
            if session['user_master_pin'] != current_pin:
                flash('Current PIN is incorrect!', 'error')
                conn = get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                totp_enabled = bool(user['otp_enabled']) if user else False
                return render_template('settings.html', totp_enabled=totp_enabled, 
                                     security_questions=get_security_questions(),
                                     user_security_q1=user['security_question1'],
                                     user_security_q2=user['security_question2'],
                                     user_security_q3=user['security_question3'])
            
            # Validate new PIN
            if len(new_pin) < 4 or len(new_pin) > 6:
                flash('PIN must be 4-6 digits!', 'error')
                conn = get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                totp_enabled = bool(user['otp_enabled']) if user else False
                return render_template('settings.html', totp_enabled=totp_enabled,
                                     security_questions=get_security_questions(),
                                     user_security_q1=user['security_question1'],
                                     user_security_q2=user['security_question2'],
                                     user_security_q3=user['security_question3'])
            
            if new_pin != confirm_pin:
                flash('New PINs do not match!', 'error')
                conn = get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                totp_enabled = bool(user['otp_enabled']) if user else False
                return render_template('settings.html', totp_enabled=totp_enabled,
                                     security_questions=get_security_questions(),
                                     user_security_q1=user['security_question1'],
                                     user_security_q2=user['security_question2'],
                                     user_security_q3=user['security_question3'])
            
            # Check if OTP verification is required
            skip_email_otp = os.environ.get('SKIP_EMAIL_OTP', 'False').lower() == 'true'
            
            if not skip_email_otp:
                if not otp_code:
                    # Generate and send OTP for PIN change
                    conn = get_db_connection()
                    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                    
                    otp_code_generated = generate_email_otp()
                    otp_expires = datetime.now() + timedelta(minutes=5)
                    
                    conn.execute('UPDATE users SET email_otp_code = ?, email_otp_expires = ? WHERE id = ?',
                               (otp_code_generated, otp_expires, session['user_id']))
                    conn.commit()
                    conn.close()
                    
                    if send_email_otp(user['email'], otp_code_generated, user['name']):
                        session['pending_pin_change'] = {
                            'current_pin': current_pin,
                            'new_pin': new_pin,
                            'confirm_pin': confirm_pin
                        }
                        flash('OTP sent to your email for PIN change verification.', 'success')
                        return render_template('pin_change_otp.html')
                    else:
                        flash('Failed to send OTP. Please try again.', 'error')
                        conn = get_db_connection()
                        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                        conn.close()
                        totp_enabled = bool(user['otp_enabled']) if user else False
                        return render_template('settings.html', totp_enabled=totp_enabled,
                                             security_questions=get_security_questions(),
                                             user_security_q1=user['security_question1'],
                                             user_security_q2=user['security_question2'],
                                             user_security_q3=user['security_question3'])
                else:
                    # Verify OTP
                    conn = get_db_connection()
                    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                    
                    if user and user['email_otp_code'] == otp_code:
                        otp_expires = datetime.strptime(user['email_otp_expires'], '%Y-%m-%d %H:%M:%S.%f')
                        if datetime.now() <= otp_expires:
                            # Clear OTP
                            conn.execute('UPDATE users SET email_otp_code = NULL, email_otp_expires = NULL WHERE id = ?',
                                       (session['user_id'],))
                            
                            # Get pending PIN change data
                            if 'pending_pin_change' in session:
                                new_pin = session['pending_pin_change']['new_pin']
                                session.pop('pending_pin_change')
                            else:
                                flash('PIN change session expired. Please try again.', 'error')
                                conn.close()
                                return redirect(url_for('settings'))
                        else:
                            flash('OTP has expired. Please try again.', 'error')
                            conn.close()
                            session.pop('pending_pin_change', None)
                            return redirect(url_for('settings'))
                    else:
                        flash('Invalid OTP. Please try again.', 'error')
                        conn.close()
                        return render_template('pin_change_otp.html')
            
            # Update PIN in database
            encrypted_pin, salt = encrypt_master_pin(new_pin)
            conn = get_db_connection()
            conn.execute('UPDATE users SET master_pin = ?, salt = ? WHERE id = ?',
                        (encrypted_pin, salt, session['user_id']))
            conn.commit()
            conn.close()
            
            # Update session
            session['user_master_pin'] = new_pin
            session.pop('pending_pin_change', None)
            
            flash('Master PIN changed successfully!', 'success')
            return redirect(url_for('settings'))
        
        elif action == 'update_security_questions':
            security_q1 = request.form['security_question1']
            security_a1 = request.form['security_answer1'].lower().strip()
            security_q2 = request.form['security_question2']
            security_a2 = request.form['security_answer2'].lower().strip()
            security_q3 = request.form['security_question3']
            security_a3 = request.form['security_answer3'].lower().strip()
            
            if not all([security_a1, security_a2, security_a3]):
                flash('Please answer all security questions!', 'error')
                conn = get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
                conn.close()
                totp_enabled = bool(user['otp_enabled']) if user else False
                return render_template('settings.html', totp_enabled=totp_enabled,
                                     security_questions=get_security_questions(),
                                     user_security_q1=user['security_question1'],
                                     user_security_q2=user['security_question2'],
                                     user_security_q3=user['security_question3'])
            
            # Update security questions
            conn = get_db_connection()
            conn.execute('''UPDATE users SET security_question1 = ?, security_answer1 = ?, 
                           security_question2 = ?, security_answer2 = ?, 
                           security_question3 = ?, security_answer3 = ? WHERE id = ?''',
                        (security_q1, security_a1, security_q2, security_a2, 
                         security_q3, security_a3, session['user_id']))
            conn.commit()
            conn.close()
            
            flash('Security questions updated successfully!', 'success')
            return redirect(url_for('settings'))
    
    # Get current user's 2FA status and security questions
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    conn.close()
    
    totp_enabled = bool(user['otp_enabled']) if user else False
    
    return render_template('settings.html', 
                         totp_enabled=totp_enabled,
                         security_questions=get_security_questions(),
                         user_security_q1=user['security_question1'] if user else '',
                         user_security_q2=user['security_question2'] if user else '',
                         user_security_q3=user['security_question3'] if user else '')

@app.route('/')
@require_auth
def index():
    """Main page showing all stored accounts with search functionality"""
    search_query = request.args.get('q', '')
    conn = get_db_connection()
    
    if search_query:
        accounts = conn.execute(
            'SELECT * FROM accounts WHERE user_id = ? AND (website LIKE ? OR username LIKE ?) ORDER BY website',
            (session['user_id'], f'%{search_query}%', f'%{search_query}%')
        ).fetchall()
    else:
        accounts = conn.execute('SELECT * FROM accounts WHERE user_id = ? ORDER BY website', (session['user_id'],)).fetchall()
    
    conn.close()
    return render_template('index.html', accounts=accounts, search_query=search_query)

@app.route('/add', methods=['GET', 'POST'])
@require_auth
def add_account():
    """Add new account"""
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        notes = request.form.get('notes', '')
        
        if not website or not username or not password:
            flash('Website, username, and password are required!', 'error')
            return render_template('add.html')
        
        # Encrypt password with salt
        encrypted_password, salt = encrypt_password(password)
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO accounts (user_id, website, username, password, salt, notes) VALUES (?, ?, ?, ?, ?, ?)',
            (session['user_id'], website, username, encrypted_password, salt, notes)
        )
        conn.commit()
        conn.close()
        
        flash('Account added successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add.html')

@app.route('/edit/<int:account_id>', methods=['GET', 'POST'])
@require_auth
def edit_account(account_id):
    """Edit existing account"""
    conn = get_db_connection()
    
    if request.method == 'POST':
        website = request.form['website']
        username = request.form['username']
        password = request.form['password']
        notes = request.form.get('notes', '')
        
        if not website or not username:
            flash('Website and username are required!', 'error')
            return redirect(url_for('edit_account', account_id=account_id))
        
        # If password field is not empty, encrypt the new password
        if password:
            encrypted_password, salt = encrypt_password(password)
            conn.execute(
                'UPDATE accounts SET website = ?, username = ?, password = ?, salt = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                (website, username, encrypted_password, salt, notes, account_id, session['user_id'])
            )
        else:
            conn.execute(
                'UPDATE accounts SET website = ?, username = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
                (website, username, notes, account_id, session['user_id'])
            )
        
        conn.commit()
        conn.close()
        
        flash('Account updated successfully!', 'success')
        return redirect(url_for('index'))
    
    account = conn.execute('SELECT * FROM accounts WHERE id = ? AND user_id = ?', (account_id, session['user_id'])).fetchone()
    conn.close()
    
    if account is None:
        flash('Account not found!', 'error')
        return redirect(url_for('index'))
    
    return render_template('edit.html', account=account)

@app.route('/delete/<int:account_id>')
@require_auth
def delete_account(account_id):
    """Delete account"""
    conn = get_db_connection()
    conn.execute('DELETE FROM accounts WHERE id = ? AND user_id = ?', (account_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Account deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/view_password/<int:account_id>')
@require_auth
def view_password(account_id):
    """View decrypted password for an account"""
    conn = get_db_connection()
    account = conn.execute('SELECT * FROM accounts WHERE id = ? AND user_id = ?', (account_id, session['user_id'])).fetchone()
    conn.close()
    
    if account is None:
        return {'error': 'Account not found'}, 404
    
    try:
        decrypted_password = decrypt_password(account['password'], account['salt'])
        return {'password': decrypted_password}
    except Exception:
        return {'password': '[Decryption failed]'}

@app.route('/get_password/<int:account_id>')
@require_auth
def get_password(account_id):
    """Get decrypted password for display"""
    conn = get_db_connection()
    
    account = conn.execute('SELECT password, salt FROM accounts WHERE id = ? AND user_id = ?', 
                   (account_id, session['user_id'])).fetchone()
    conn.close()
    
    if not account:
        return {'error': 'Account not found'}, 404
    
    try:
        decrypted_password = decrypt_password(account['password'], account['salt'])
        return {'password': decrypted_password}
    except Exception as e:
        return {'password': '[Decryption failed]'}

@app.route('/generate_themed_password', methods=['POST'])
@require_auth
def generate_themed_password():
    """Generate a themed password using LLM API"""
    data = request.get_json()
    theme = data.get('theme', 'strong')
    
    # API configuration - get API key from environment variable
    api_key = os.environ.get('HACKCLUB_API_KEY')
    api_url = "https://ai.hackclub.com/proxy/v1/chat/completions"
    
    # Dynamic prompt generation based on any theme
    prompt = f"""Generate a single password inspired by the theme "{theme}".

REQUIREMENTS:
- Exactly 10-16 characters long
- Must contain: letters, numbers, and symbols (@#$%^&*)
- Theme-inspired but still secure
- Output ONLY the password, no explanations

EXAMPLES:
Theme "ocean": Wave2024@
Theme "space": Star#Light9
Theme "coffee": Brew!Cup7

Theme "{theme}":"""
    
    headers = {
        'Authorization': f'Bearer {api_key}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'model': 'google/gemini-2.5-flash',
        'messages': [
            {'role': 'user', 'content': prompt}
        ],
        'max_tokens': 50,
        'temperature': 0.8
    }
    
    try:
        # Try with retry logic
        for attempt in range(3):
            try:
                response = requests.post(api_url, headers=headers, json=payload, timeout=30)
                response.raise_for_status()
                
                result = response.json()
                original_password = result['choices'][0]['message']['content'].strip()
                break  # Success, exit retry loop
                
            except requests.Timeout:
                if attempt == 2:  # Last attempt
                    raise
                continue
            except requests.RequestException as e:
                if attempt == 2:
                    raise
        
        # Clean up the password (remove any extra text)
        password = original_password.split('\n')[0].strip()
        # Remove quotes if present
        password = password.strip('"\'')
        # Remove common prefixes that LLMs might add
        password = password.replace('Password:', '').replace('password:', '').strip()
        
        # Extract just the password if there's extra text
        import re
        # Look for password-like patterns (letters, numbers, special chars, 8-20 chars)
        password_match = re.search(r'[A-Za-z0-9@#$%^&*()_+\-=\[\]{}|;:,.<>?!~`]{8,20}', password)
        if password_match:
            password = password_match.group()
        
        # Validate password length (more lenient range)
        if len(password) < 6 or len(password) > 30:
            # Generate a fallback password if the LLM output is unusable
            import string
            import secrets
            chars = string.ascii_letters + string.digits + '@#$%^&*'
            fallback = ''.join(secrets.choice(chars) for _ in range(12))
            # Add theme prefix if short enough
            if len(theme) <= 4:
                fallback = theme.capitalize() + fallback[:8]
            password = fallback
            
        return {'password': password, 'theme': theme}
        
    except requests.RequestException as e:
        return {'error': f'API request failed: {str(e)}'}, 500
    except Exception as e:
        return {'error': f'Password generation failed: {str(e)}'}, 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

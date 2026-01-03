from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
from datetime import datetime
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
import os

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
            name TEXT NOT NULL,
            master_pin TEXT NOT NULL,
            salt TEXT NOT NULL,
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
                name TEXT NOT NULL,
                master_pin TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create default user
        default_pin_encrypted, default_salt = encrypt_master_pin("1234")
        cursor.execute(
            'INSERT INTO users (username, name, master_pin, salt) VALUES (?, ?, ?, ?)',
            ('admin', 'Default User', default_pin_encrypted, default_salt)
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

def verify_master_pin(username, pin):
    """Verify master PIN for user"""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
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
    except Exception as e:
        print(f"Authentication error: {e}")
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
    """Encrypt password using AES-GCM with salt"""
    # Generate a random salt for this password
    salt = os.urandom(16)
    
    # Derive key from master password and salt
    master_password = get_master_key().encode()
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
    """Decrypt password using AES-GCM"""
    try:
        # Decode from base64
        encrypted_data = base64.urlsafe_b64decode(encrypted_password.encode())
        salt = base64.urlsafe_b64decode(salt_b64.encode())
        
        # Extract IV, tag, and ciphertext
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        
        # Derive key using the same method as encryption
        master_password = get_master_key().encode()
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
    except Exception:
        return "[Encrypted]"

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login and registration"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'login':
            username = request.form['username']
            pin = request.form['pin']
            
            if verify_master_pin(username, pin):
                conn = get_db_connection()
                user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
                conn.close()
                
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['name'] = user['name']
                
                flash(f'Welcome back, {user["name"]}!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Invalid username or PIN!', 'error')
                
        elif action == 'register':
            username = request.form['new_username']
            name = request.form['name']
            pin = request.form['new_pin']
            
            if len(pin) < 4 or len(pin) > 6:
                flash('PIN must be 4-6 digits!', 'error')
                return render_template('login.html')
            
            conn = get_db_connection()
            
            # Check if username already exists
            existing_user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if existing_user:
                flash('Username already exists!', 'error')
                conn.close()
                return render_template('login.html')
            
            # Create new user
            encrypted_pin, salt = encrypt_master_pin(pin)
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, name, master_pin, salt) VALUES (?, ?, ?, ?)',
                (username, name, encrypted_pin, salt)
            )
            conn.commit()
            
            user_id = cursor.lastrowid
            conn.close()
            
            session['user_id'] = user_id
            session['username'] = username
            session['name'] = name
            
            flash(f'Welcome, {name}! Your account has been created.', 'success')
            return redirect(url_for('index'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

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

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

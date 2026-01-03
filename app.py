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
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_master_key():
    """Get or create master key for encryption"""
    if 'master_key' not in session:
        # Not for production
        session['master_key'] = base64.urlsafe_b64encode(os.urandom(32)).decode()
    return session['master_key']

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

@app.route('/')
def index():
    """Main page showing all stored accounts with search functionality"""
    search_query = request.args.get('q', '')
    conn = get_db_connection()
    
    if search_query:
        accounts = conn.execute(
            'SELECT * FROM accounts WHERE website LIKE ? OR username LIKE ? ORDER BY website',
            (f'%{search_query}%', f'%{search_query}%')
        ).fetchall()
    else:
        accounts = conn.execute('SELECT * FROM accounts ORDER BY website').fetchall()
    
    conn.close()
    return render_template('index.html', accounts=accounts, search_query=search_query)

@app.route('/add', methods=['GET', 'POST'])
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
            'INSERT INTO accounts (website, username, password, salt, notes) VALUES (?, ?, ?, ?, ?)',
            (website, username, encrypted_password, salt, notes)
        )
        conn.commit()
        conn.close()
        
        flash('Account added successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add.html')

@app.route('/edit/<int:account_id>', methods=['GET', 'POST'])
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
                'UPDATE accounts SET website = ?, username = ?, password = ?, salt = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                (website, username, encrypted_password, salt, notes, account_id)
            )
        else:
            conn.execute(
                'UPDATE accounts SET website = ?, username = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                (website, username, notes, account_id)
            )
        
        conn.commit()
        conn.close()
        
        flash('Account updated successfully!', 'success')
        return redirect(url_for('index'))
    
    account = conn.execute('SELECT * FROM accounts WHERE id = ?', (account_id,)).fetchone()
    conn.close()
    
    if account is None:
        flash('Account not found!', 'error')
        return redirect(url_for('index'))
    
    return render_template('edit.html', account=account)

@app.route('/delete/<int:account_id>')
def delete_account(account_id):
    """Delete account"""
    conn = get_db_connection()
    conn.execute('DELETE FROM accounts WHERE id = ?', (account_id,))
    conn.commit()
    conn.close()
    
    flash('Account deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/view_password/<int:account_id>')
def view_password(account_id):
    """View decrypted password for an account"""
    conn = get_db_connection()
    account = conn.execute('SELECT * FROM accounts WHERE id = ?', (account_id,)).fetchone()
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

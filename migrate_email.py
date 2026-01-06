#!/usr/bin/env python3
"""
Database migration script to add email field to existing users table
"""

import sqlite3
import os

DATABASE = 'passwords.db'

def migrate_database():
    """Add email field to existing users table"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Check if email column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'email' not in columns:
            print("Adding email column to users table...")
            
            # Add email column with a default value
            cursor.execute("ALTER TABLE users ADD COLUMN email TEXT")
            
            # Update existing users with placeholder emails
            cursor.execute("SELECT id, username FROM users")
            users = cursor.fetchall()
            
            for user_id, username in users:
                placeholder_email = f"{username}@placeholder.com"
                cursor.execute("UPDATE users SET email = ? WHERE id = ?", (placeholder_email, user_id))
            
            # Now add UNIQUE constraint by recreating the table
            print("Recreating table with UNIQUE constraint on email...")
            
            # Create new table with proper constraints
            cursor.execute('''
                CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    master_pin TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Copy data from old table
            cursor.execute('''
                INSERT INTO users_new (id, username, email, name, master_pin, salt, created_at)
                SELECT id, username, email, name, master_pin, salt, created_at FROM users
            ''')
            
            # Drop old table and rename new one
            cursor.execute("DROP TABLE users")
            cursor.execute("ALTER TABLE users_new RENAME TO users")
            
            conn.commit()
            print("✅ Database migration completed successfully!")
            print("⚠️  Note: Existing users have placeholder emails (username@placeholder.com)")
            print("   They can update their emails by creating a new account or you can manually update them.")
            
        else:
            print("✅ Email column already exists. No migration needed.")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    if os.path.exists(DATABASE):
        migrate_database()
    else:
        print("✅ No existing database found. Email support will be included in new database creation.")
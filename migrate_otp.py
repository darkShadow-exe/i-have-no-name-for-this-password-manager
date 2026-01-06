#!/usr/bin/env python3
"""
Database migration script to add OTP and security question fields
"""

import sqlite3
import os

DATABASE = 'passwords.db'

def migrate_database_otp():
    """Add OTP and security question fields to existing users table"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Check what columns exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add missing columns
        new_columns = {
            'otp_secret': 'TEXT',
            'otp_enabled': 'INTEGER DEFAULT 0',
            'security_question1': 'TEXT',
            'security_answer1': 'TEXT',
            'security_question2': 'TEXT',
            'security_answer2': 'TEXT',
            'security_question3': 'TEXT',
            'security_answer3': 'TEXT',
            'email_otp_code': 'TEXT',
            'email_otp_expires': 'TIMESTAMP'
        }
        
        for column_name, column_type in new_columns.items():
            if column_name not in columns:
                print(f"Adding {column_name} column...")
                cursor.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
        
        conn.commit()
        print("✅ OTP and Security Questions migration completed successfully!")
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    if os.path.exists(DATABASE):
        migrate_database_otp()
    else:
        print("✅ No existing database found. New features will be included in new database creation.")
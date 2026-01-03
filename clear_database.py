#!/usr/bin/env python3
"""
Database Clearing Script for Password Manager

This script clears all users and passwords from the database.
Run this script from the command line when you need to reset the database.

Usage:
    python clear_database.py

WARNING: This action is irreversible!
"""

import sqlite3
import os

DATABASE = 'passwords.db'

def clear_database():
    """Clear all data from the password manager database"""
    
    # Check if database exists
    if not os.path.exists(DATABASE):
        print(f"Database file '{DATABASE}' not found!")
        print("Make sure you're running this script from the correct directory.")
        return False
    
    # Get confirmation from user
    print("⚠️  WARNING: This will permanently delete ALL users and passwords!")
    print("This action cannot be undone!")
    print("")
    confirmation = input("Type 'DELETE ALL' to confirm (case sensitive): ").strip()
    
    if confirmation != "DELETE ALL":
        print("Operation cancelled. Database was not modified.")
        return False
    
    try:
        # Connect to database
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Get current data count for reporting
        try:
            cursor.execute("SELECT COUNT(*) FROM accounts")
            account_count = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            account_count = 0
        
        try:
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
        except sqlite3.OperationalError:
            user_count = 0
        
        print(f"\nFound {user_count} users and {account_count} accounts in database...")
        
        # Clear all data
        print("Clearing all accounts...")
        cursor.execute("DELETE FROM accounts")
        
        print("Clearing all users...")
        cursor.execute("DELETE FROM users")
        
        # Reset auto-increment counters
        try:
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='accounts'")
            cursor.execute("DELETE FROM sqlite_sequence WHERE name='users'")
        except sqlite3.OperationalError:
            # sqlite_sequence might not exist
            pass
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print("✅ Database cleared successfully!")
        print(f"Deleted {user_count} users and {account_count} accounts.")
        print("\nThe password manager will now start with a clean database.")
        
        return True
        
    except Exception as e:
        print(f"❌ Error clearing database: {e}")
        return False

def main():
    """Main function"""
    print("Password Manager Database Cleaner")
    print("=" * 40)
    print("")
    
    success = clear_database()
    
    if success:
        print("\nYou can now restart the password manager application.")
    else:
        print("\nDatabase clearing failed or was cancelled.")

if __name__ == "__main__":
    main()
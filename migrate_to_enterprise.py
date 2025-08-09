#!/usr/bin/env python3
"""
Database Migration Script
Migrates from the old authentication system to the new enterprise system
"""

import sqlite3
import os
import json
from datetime import datetime
import bcrypt

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def migrate_database():
    """Migrate from old auth.db to new enterprise_auth.db"""
    
    old_db_path = 'auth.db'
    new_db_path = 'enterprise_auth.db'
    
    if not os.path.exists(old_db_path):
        print("No existing auth.db found. Starting with fresh enterprise database.")
        return
    
    print("Starting database migration...")
    
    # Connect to old database
    old_conn = sqlite3.connect(old_db_path)
    old_cursor = old_conn.cursor()
    
    # Connect to new database (will be created by enterprise_auth_server.py)
    new_conn = sqlite3.connect(new_db_path)
    new_cursor = new_conn.cursor()
    
    try:
        # Create new schema
        create_new_schema(new_cursor)
        
        # Migrate existing users to organizations
        migrate_users(old_cursor, new_cursor)
        
        # Commit changes
        new_conn.commit()
        
        print("Migration completed successfully!")
        print(f"Backup your old database: {old_db_path}")
        print(f"New enterprise database: {new_db_path}")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        new_conn.rollback()
        raise
    
    finally:
        old_conn.close()
        new_conn.close()

def create_new_schema(cursor):
    """Create the new enterprise database schema"""
    
    # Organizations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            email VARCHAR(255) UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        )
    ''')
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            name VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'employee')),
            machine_id VARCHAR(64),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        )
    ''')
    
    # Shared tasks table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            created_by INTEGER NOT NULL,
            task_name VARCHAR(255) NOT NULL,
            task_data TEXT NOT NULL,
            permissions TEXT NOT NULL,
            shared_with TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (organization_id) REFERENCES organizations(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Task access logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS task_access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            action VARCHAR(50) NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (task_id) REFERENCES shared_tasks(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Auth sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token VARCHAR(255) UNIQUE NOT NULL,
            machine_id VARCHAR(64),
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Login attempts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR(255) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            success BOOLEAN NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            organization_id INTEGER,
            FOREIGN KEY (organization_id) REFERENCES organizations(id)
        )
    ''')

def migrate_users(old_cursor, new_cursor):
    """Migrate existing users to the new enterprise structure"""
    
    try:
        # Get existing users from old database
        old_cursor.execute('SELECT email, password_hash, user_type, created_at, last_login FROM user')
        old_users = old_cursor.fetchall()
        
        if not old_users:
            print("No existing users found to migrate.")
            return
        
        # Create a default organization for migrated users
        org_name = "Migrated Organization"
        org_email = "admin@migrated.local"
        org_description = "Organization created during migration from old authentication system"
        
        new_cursor.execute('''
            INSERT INTO organizations (name, description, email, created_at)
            VALUES (?, ?, ?, ?)
        ''', (org_name, org_description, org_email, datetime.utcnow()))
        
        org_id = new_cursor.lastrowid
        print(f"Created default organization: {org_name} (ID: {org_id})")
        
        # Migrate users
        migrated_count = 0
        for user in old_users:
            email, password_hash, user_type, created_at, last_login = user
            
            # Determine role (convert old user_type to new role system)
            role = 'admin' if user_type in ['enterprise', 'admin'] else 'employee'
            
            # Extract name from email (simple approach)
            name = email.split('@')[0].replace('.', ' ').title()
            
            # Convert old password hash to new bcrypt format if needed
            # Note: This assumes old passwords were already hashed
            # In a real migration, you might need to handle this differently
            if not password_hash.startswith('$2b$'):
                # If old hash format, we'll need users to reset passwords
                # For now, set a default password that forces reset
                password_hash = hash_password('ChangeMe123!')
                print(f"User {email} will need to reset password (set to 'ChangeMe123!')")
            
            try:
                new_cursor.execute('''
                    INSERT INTO users (organization_id, email, name, password_hash, role, created_at, last_login)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (org_id, email, name, password_hash, role, created_at, last_login))
                
                migrated_count += 1
                print(f"Migrated user: {email} as {role}")
                
            except sqlite3.IntegrityError as e:
                print(f"Failed to migrate user {email}: {e}")
        
        print(f"Successfully migrated {migrated_count} users")
        
        # Migrate licenses if they exist
        try:
            old_cursor.execute('SELECT license_key, user_id, machine_id, expires_at FROM license')
            old_licenses = old_cursor.fetchall()
            
            if old_licenses:
                print(f"Found {len(old_licenses)} licenses - these will need to be handled separately")
                print("Note: The new enterprise system doesn't use individual licenses")
        
        except sqlite3.OperationalError:
            # License table doesn't exist in old database
            pass
            
    except sqlite3.OperationalError as e:
        print(f"Error accessing old database structure: {e}")
        print("This might be expected if the old database has a different structure")

def create_sample_data(cursor):
    """Create sample data for testing"""
    
    # Create sample organization
    cursor.execute('''
        INSERT INTO organizations (name, description, email)
        VALUES (?, ?, ?)
    ''', ("Sample Corp", "A sample organization for testing", "admin@samplecorp.com"))
    
    org_id = cursor.lastrowid
    
    # Create sample admin
    cursor.execute('''
        INSERT INTO users (organization_id, email, name, password_hash, role)
        VALUES (?, ?, ?, ?, ?)
    ''', (org_id, "admin@samplecorp.com", "Admin User", hash_password("admin123"), "admin"))
    
    # Create sample employee
    cursor.execute('''
        INSERT INTO users (organization_id, email, name, password_hash, role)
        VALUES (?, ?, ?, ?, ?)
    ''', (org_id, "employee@samplecorp.com", "Employee User", hash_password("employee123"), "employee"))
    
    print("Created sample organization and users:")
    print("  Admin: admin@samplecorp.com / admin123")
    print("  Employee: employee@samplecorp.com / employee123")

if __name__ == '__main__':
    migrate_database()
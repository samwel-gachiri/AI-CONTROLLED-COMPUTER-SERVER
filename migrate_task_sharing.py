#!/usr/bin/env python3
"""
Database Migration for Task Sharing Enhancement
Adds message field to SharedTask model
"""

import sqlite3
import os

def migrate_database():
    """Add message field to shared_tasks table"""
    db_path = 'server/instance/enterprise_auth.db'
    
    if not os.path.exists(db_path):
        print("Database not found. Creating new database with updated schema.")
        return
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if message column already exists
        cursor.execute("PRAGMA table_info(shared_tasks)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'message' not in columns:
            print("Adding message column to shared_tasks table...")
            cursor.execute("ALTER TABLE shared_tasks ADD COLUMN message TEXT")
            conn.commit()
            print("✅ Migration completed successfully")
        else:
            print("✅ Message column already exists")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Migration failed: {e}")

if __name__ == "__main__":
    migrate_database()
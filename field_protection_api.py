#!/usr/bin/env python3
"""
Field Protection API
Server-side endpoints for managing field protection and access requests
"""

from flask import Blueprint, request, jsonify, g, current_app
from datetime import datetime, timedelta
import sqlite3
import json
import os
from functools import wraps

field_protection_bp = Blueprint('field_protection', __name__)

def get_db_connection():
    """Get database connection using the same path logic as enterprise_auth_server"""
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check for database in server/instance directory (relative to script)
    server_instance_db = os.path.join(script_dir, 'instance', 'enterprise_auth.db')
    
    # Check for database in root/server/instance directory (when run from root)
    root_server_instance_db = os.path.join(os.getcwd(), 'server', 'instance', 'enterprise_auth.db')
    
    if os.path.exists(server_instance_db):
        db_path = server_instance_db
    elif os.path.exists(root_server_instance_db):
        db_path = root_server_instance_db
    else:
        # Create instance directory relative to server script
        instance_dir = os.path.join(script_dir, 'instance')
        os.makedirs(instance_dir, exist_ok=True)
        db_path = os.path.join(instance_dir, 'enterprise_auth.db')
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_field_protection_tables():
    """Initialize field protection tables"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Protected fields table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS protected_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            field_id TEXT NOT NULL,
            field_name TEXT NOT NULL,
            task_id TEXT,
            protected_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (protected_by) REFERENCES users (id),
            UNIQUE(field_id, task_id)
        )
    ''')
    
    # Field access requests table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS field_access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            field_id TEXT NOT NULL,
            field_name TEXT NOT NULL,
            task_id TEXT,
            requested_by INTEGER NOT NULL,
            current_value TEXT,
            reason TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reviewed_by INTEGER,
            reviewed_at TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (requested_by) REFERENCES users (id),
            FOREIGN KEY (reviewed_by) REFERENCES users (id)
        )
    ''')
    
    # Temporary field access table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS temporary_field_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            field_id TEXT NOT NULL,
            task_id TEXT,
            user_id INTEGER NOT NULL,
            granted_by INTEGER NOT NULL,
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (granted_by) REFERENCES users (id),
            UNIQUE(field_id, task_id, user_id)
        )
    ''')
    
    # Field edit history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS field_edit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            field_id TEXT NOT NULL,
            task_id TEXT,
            user_id INTEGER NOT NULL,
            original_value TEXT,
            new_value TEXT,
            edited_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            access_request_id INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (access_request_id) REFERENCES field_access_requests (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        
        # Verify token and get user using the same table structure as enterprise_auth_server
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.email, u.name, u.role 
            FROM users u 
            JOIN auth_sessions s ON u.id = s.user_id 
            WHERE s.session_token = ? AND s.expires_at > datetime('now') AND s.is_active = 1
        ''', (token,))
        
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401
        
        g.current_user = dict(user)
        return f(*args, **kwargs)
    
    return decorated_function

@field_protection_bp.route('/field-protection/protect', methods=['POST'])
@require_auth
def protect_field():
    """Protect a field"""
    data = request.get_json()
    field_id = data.get('field_id')
    field_name = data.get('field_name')
    task_id = data.get('task_id')
    
    if not field_id or not field_name:
        return jsonify({'success': False, 'error': 'field_id and field_name are required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insert or update protected field
        cursor.execute('''
            INSERT OR REPLACE INTO protected_fields 
            (field_id, field_name, task_id, protected_by, is_active)
            VALUES (?, ?, ?, ?, 1)
        ''', (field_id, field_name, task_id, g.current_user['id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Field "{field_name}" is now protected'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/unprotect', methods=['POST'])
@require_auth
def unprotect_field():
    """Remove protection from a field"""
    data = request.get_json()
    field_id = data.get('field_id')
    task_id = data.get('task_id')
    
    if not field_id:
        return jsonify({'success': False, 'error': 'field_id is required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user owns this protection or is admin
        cursor.execute('''
            SELECT protected_by FROM protected_fields 
            WHERE field_id = ? AND task_id = ? AND is_active = 1
        ''', (field_id, task_id))
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'error': 'Field is not protected'}), 404
        
        if result['protected_by'] != g.current_user['id'] and g.current_user['role'] != 'admin':
            return jsonify({'success': False, 'error': 'Permission denied'}), 403
        
        # Remove protection
        cursor.execute('''
            UPDATE protected_fields 
            SET is_active = 0 
            WHERE field_id = ? AND task_id = ?
        ''', (field_id, task_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Field protection removed'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/request-access', methods=['POST'])
@require_auth
def request_field_access():
    """Request temporary access to a protected field"""
    data = request.get_json()
    print(f"🔍 Field access request received: {data}")
    
    field_id = data.get('field_id')
    field_name = data.get('field_name')
    current_value = data.get('current_value', '')
    reason = data.get('reason')
    task_id = data.get('task_id')
    
    print(f"🔍 Parsed: field_id='{field_id}', task_id='{task_id}', field_name='{field_name}', reason='{reason}'")
    
    if not field_id or not field_name or not reason:
        return jsonify({'success': False, 'error': 'field_id, field_name, and reason are required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if field is actually protected
        cursor.execute('''
            SELECT id FROM protected_fields 
            WHERE field_id = ? AND task_id = ? AND is_active = 1
        ''', (field_id, task_id))
        
        protected_field = cursor.fetchone()
        
        if not protected_field:
            # Check what protected fields exist for debugging
            cursor.execute('SELECT field_id, task_id FROM protected_fields WHERE is_active = 1')
            all_protected = cursor.fetchall()
            protected_list = [f"{row['field_id']}:{row['task_id']}" for row in all_protected]
            
            error_msg = f'Field "{field_id}" in task "{task_id}" is not protected. Protected fields: {protected_list}'
            print(f"❌ {error_msg}")
            
            return jsonify({
                'success': False, 
                'error': error_msg
            }), 400
        
        # Insert access request
        cursor.execute('''
            INSERT INTO field_access_requests 
            (field_id, field_name, task_id, requested_by, current_value, reason)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (field_id, field_name, task_id, g.current_user['id'], current_value, reason))
        
        request_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'request_id': request_id,
            'message': 'Access request submitted successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/my-requests', methods=['GET'])
@require_auth
def get_my_requests():
    """Get user's field access requests"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, field_id, field_name, task_id, current_value, reason, 
                   status, requested_at, reviewed_at, expires_at
            FROM field_access_requests 
            WHERE requested_by = ?
            ORDER BY requested_at DESC
        ''', (g.current_user['id'],))
        
        requests = []
        for row in cursor.fetchall():
            requests.append(dict(row))
        
        conn.close()
        
        return jsonify({
            'success': True,
            'requests': requests
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/pending-requests', methods=['GET'])
@require_auth
def get_pending_requests():
    """Get pending access requests for fields protected by current user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get requests for fields protected by current user or if user is admin
        if g.current_user['role'] == 'admin':
            cursor.execute('''
                SELECT r.id, r.field_id, r.field_name, r.task_id, r.current_value, 
                       r.reason, r.requested_at, u.name as requested_by_name, u.email as requested_by_email
                FROM field_access_requests r
                JOIN users u ON r.requested_by = u.id
                WHERE r.status = 'pending'
                ORDER BY r.requested_at ASC
            ''')
        else:
            cursor.execute('''
                SELECT r.id, r.field_id, r.field_name, r.task_id, r.current_value, 
                       r.reason, r.requested_at, u.name as requested_by_name, u.email as requested_by_email
                FROM field_access_requests r
                JOIN users u ON r.requested_by = u.id
                JOIN protected_fields p ON r.field_id = p.field_id AND r.task_id = p.task_id
                WHERE r.status = 'pending' AND p.protected_by = ? AND p.is_active = 1
                ORDER BY r.requested_at ASC
            ''', (g.current_user['id'],))
        
        requests = []
        for row in cursor.fetchall():
            requests.append(dict(row))
        
        conn.close()
        
        return jsonify({
            'success': True,
            'requests': requests
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/approve-request', methods=['POST'])
@require_auth
def approve_request():
    """Approve a field access request"""
    data = request.get_json()
    request_id = data.get('request_id')
    duration_hours = data.get('duration_hours', 1)  # Default 1 hour
    
    if not request_id:
        return jsonify({'success': False, 'error': 'request_id is required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get request details and verify permission
        if g.current_user['role'] == 'admin':
            cursor.execute('''
                SELECT r.*, p.protected_by
                FROM field_access_requests r
                JOIN protected_fields p ON r.field_id = p.field_id AND r.task_id = p.task_id
                WHERE r.id = ? AND r.status = 'pending' AND p.is_active = 1
            ''', (request_id,))
        else:
            cursor.execute('''
                SELECT r.*, p.protected_by
                FROM field_access_requests r
                JOIN protected_fields p ON r.field_id = p.field_id AND r.task_id = p.task_id
                WHERE r.id = ? AND r.status = 'pending' AND p.protected_by = ? AND p.is_active = 1
            ''', (request_id, g.current_user['id']))
        
        request_info = cursor.fetchone()
        if not request_info:
            return jsonify({'success': False, 'error': 'Request not found or permission denied'}), 404
        
        # Calculate expiration time
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        # Update request status
        cursor.execute('''
            UPDATE field_access_requests 
            SET status = 'approved', reviewed_by = ?, reviewed_at = datetime('now'), expires_at = ?
            WHERE id = ?
        ''', (g.current_user['id'], expires_at.isoformat(), request_id))
        
        # Grant temporary access
        cursor.execute('''
            INSERT OR REPLACE INTO temporary_field_access 
            (field_id, task_id, user_id, granted_by, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (request_info['field_id'], request_info['task_id'], request_info['requested_by'], 
              g.current_user['id'], expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Access granted for {duration_hours} hour(s)',
            'expires_at': expires_at.isoformat()
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/deny-request', methods=['POST'])
@require_auth
def deny_request():
    """Deny a field access request"""
    data = request.get_json()
    request_id = data.get('request_id')
    reason = data.get('reason', '')
    
    if not request_id:
        return jsonify({'success': False, 'error': 'request_id is required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verify permission and update request
        if g.current_user['role'] == 'admin':
            cursor.execute('''
                UPDATE field_access_requests 
                SET status = 'denied', reviewed_by = ?, reviewed_at = datetime('now')
                WHERE id = ? AND status = 'pending'
            ''', (g.current_user['id'], request_id))
        else:
            cursor.execute('''
                UPDATE field_access_requests r
                SET status = 'denied', reviewed_by = ?, reviewed_at = datetime('now')
                FROM protected_fields p
                WHERE r.id = ? AND r.status = 'pending' 
                AND r.field_id = p.field_id AND r.task_id = p.task_id 
                AND p.protected_by = ? AND p.is_active = 1
            ''', (g.current_user['id'], request_id, g.current_user['id']))
        
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'error': 'Request not found or permission denied'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Access request denied'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/permissions', methods=['GET'])
@require_auth
def get_permissions():
    """Get current field permissions and temporary access for user"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get protected fields
        cursor.execute('''
            SELECT field_id, field_name, task_id, protected_by
            FROM protected_fields 
            WHERE is_active = 1
        ''')
        
        protected_fields = {}
        for row in cursor.fetchall():
            key = f"{row['task_id']}:{row['field_id']}" if row['task_id'] else row['field_id']
            protected_fields[key] = {
                'field_id': row['field_id'],
                'field_name': row['field_name'],
                'task_id': row['task_id'],
                'protected_by': row['protected_by']
            }
        
        # Get temporary access for current user
        cursor.execute('''
            SELECT field_id, task_id, expires_at
            FROM temporary_field_access 
            WHERE user_id = ? AND expires_at > datetime('now') AND is_active = 1
        ''', (g.current_user['id'],))
        
        temporary_access = {}
        for row in cursor.fetchall():
            key = f"{row['task_id']}:{row['field_id']}" if row['task_id'] else row['field_id']
            temporary_access[key] = {
                'field_id': row['field_id'],
                'task_id': row['task_id'],
                'expires_at': row['expires_at']
            }
        
        conn.close()
        
        return jsonify({
            'success': True,
            'protected_fields': protected_fields,
            'temporary_access': temporary_access
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@field_protection_bp.route('/field-protection/revoke-access', methods=['POST'])
@require_auth
def revoke_access():
    """Revoke temporary access to a field (called after editing)"""
    data = request.get_json()
    field_id = data.get('field_id')
    task_id = data.get('task_id')
    
    if not field_id:
        return jsonify({'success': False, 'error': 'field_id is required'}), 400
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Revoke access
        cursor.execute('''
            UPDATE temporary_field_access 
            SET is_active = 0 
            WHERE field_id = ? AND task_id = ? AND user_id = ? AND is_active = 1
        ''', (field_id, task_id, g.current_user['id']))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Access revoked'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Initialize tables when module is imported
init_field_protection_tables()
#!/usr/bin/env python3
"""
Enterprise Authentication Server API
Handles organization registration, employee management, and task sharing
"""

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timedelta
import secrets
import os
import bcrypt
from functools import wraps

# Import field protection API
try:
    from field_protection_api import field_protection_bp, init_field_protection_tables
    FIELD_PROTECTION_AVAILABLE = True
except ImportError:
    print("⚠️ Field protection API not available")
    FIELD_PROTECTION_AVAILABLE = False

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
# Configure database path - handle both running from root and server directory
db_path = os.getenv('DATABASE_URL')
if not db_path:
    # Get the directory where this script is located
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Check for database in server/instance directory (relative to script)
    server_instance_db = os.path.join(script_dir, 'instance', 'enterprise_auth.db')
    
    # Check for database in root/server/instance directory (when run from root)
    root_server_instance_db = os.path.join(os.getcwd(), 'server', 'instance', 'enterprise_auth.db')
    
    if os.path.exists(server_instance_db):
        db_path = f'sqlite:///{server_instance_db}'
        print(f"📍 Found database at: {server_instance_db}")
    elif os.path.exists(root_server_instance_db):
        db_path = f'sqlite:///{root_server_instance_db}'
        print(f"📍 Found database at: {root_server_instance_db}")
    else:
        # Create instance directory relative to server script
        instance_dir = os.path.join(script_dir, 'instance')
        os.makedirs(instance_dir, exist_ok=True)
        db_path = f'sqlite:///{os.path.join(instance_dir, "enterprise_auth.db")}'
        print(f"📍 Creating new database at: {os.path.join(instance_dir, 'enterprise_auth.db')}")

app.config['SQLALCHEMY_DATABASE_URI'] = db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

print(f"🗄️ Using database: {db_path}")

db = SQLAlchemy(app)

# Configure CORS to allow requests from frontend
CORS(app, 
     origins=[
         "http://localhost:3000",
         "http://127.0.0.1:3000",
         "http://localhost:5173",  # Vite default port
         "http://127.0.0.1:5173",
         "https://ai-controlled-computer-frontend-ehy.vercel.app/"
     ],
     allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     supports_credentials=True)

# Register field protection blueprint
if FIELD_PROTECTION_AVAILABLE:
    app.register_blueprint(field_protection_bp, url_prefix='/api')
    print("✅ Field protection API registered")
else:
    print("⚠️ Field protection API not registered - endpoints will return 404")

# App secret for HMAC signatures (must match client)
APP_SECRET = os.getenv('APP_SECRET', 'your-app-secret-key-here')



# Database Models
class Organization(db.Model):
    __tablename__ = 'organizations'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    email = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    users = db.relationship('User', backref='organization', lazy=True, cascade='all, delete-orphan')
    shared_tasks = db.relationship('SharedTask', backref='organization', lazy=True, cascade='all, delete-orphan')

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'employee', name='user_roles'), nullable=False)
    machine_id = db.Column(db.String(64))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    created_tasks = db.relationship('SharedTask', foreign_keys='SharedTask.created_by', backref='creator', lazy=True)
    auth_sessions = db.relationship('AuthSession', backref='user', lazy=True, cascade='all, delete-orphan')
    access_logs = db.relationship('TaskAccessLog', backref='user', lazy=True)

class SharedTask(db.Model):
    __tablename__ = 'shared_tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    task_name = db.Column(db.String(255), nullable=False)
    task_data = db.Column(db.Text, nullable=False)  # JSON string
    permissions = db.Column(db.Text, nullable=False)  # JSON string
    shared_with = db.Column(db.Text)  # JSON array of user IDs, null for all employees
    message = db.Column(db.Text)  # Optional message from the sharer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    access_logs = db.relationship('TaskAccessLog', backref='task', lazy=True)

class TaskAccessLog(db.Model):
    __tablename__ = 'task_access_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('shared_tasks.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class AuthSession(db.Model):
    __tablename__ = 'auth_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    machine_id = db.Column(db.String(64))
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

class LoginAttempt(db.Model):
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    organization_id = db.Column(db.Integer, db.ForeignKey('organizations.id'))

# Helper Functions
def verify_signature(data, signature):
    """Verify HMAC signature"""
    try:
        # Use same JSON formatting as JavaScript (no spaces)
        expected_signature = hmac.new(
            APP_SECRET.encode(),
            json.dumps(data, sort_keys=True, separators=(',', ':')).encode(),
            hashlib.sha256
        ).hexdigest()
        
        # Debug logging
        print(f"DEBUG - Data: {json.dumps(data, sort_keys=True, separators=(',', ':'))}")
        print(f"DEBUG - APP_SECRET: {APP_SECRET}")
        print(f"DEBUG - Received signature: {signature}")
        print(f"DEBUG - Expected signature: {expected_signature}")
        
        return hmac.compare_digest(signature, expected_signature)
    except Exception as e:
        print(f"DEBUG - Signature verification error: {e}")
        return False

def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_session_token():
    """Generate secure session token"""
    return secrets.token_urlsafe(32)

def check_rate_limit(email, ip_address, max_attempts=5, window_minutes=15):
    """Check if user/IP is rate limited"""
    cutoff_time = datetime.utcnow() - timedelta(minutes=window_minutes)
    
    attempts = LoginAttempt.query.filter(
        LoginAttempt.email == email,
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.timestamp > cutoff_time,
        LoginAttempt.success == False
    ).count()
    
    return attempts < max_attempts

def log_login_attempt(email, ip_address, success, organization_id=None):
    """Log login attempt"""
    attempt = LoginAttempt(
        email=email,
        ip_address=ip_address,
        success=success,
        organization_id=organization_id
    )
    db.session.add(attempt)
    db.session.commit()

def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'success': False, 'error': 'No authorization token provided'}), 401
        
        if token.startswith('Bearer '):
            token = token[7:]
        
        session = AuthSession.query.filter_by(
            session_token=token,
            is_active=True
        ).first()
        
        if not session or session.expires_at < datetime.utcnow():
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401
        
        request.current_user = session.user
        return f(*args, **kwargs)
    
    return decorated_function

def require_admin(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not hasattr(request, 'current_user') or request.current_user.role != 'admin':
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    
    return decorated_function

# Desktop integration storage
desktop_auth_sessions = {}

# API Routes

# Authentication Verification
@app.route('/api/auth/verify', methods=['GET'])
def verify_auth():
    """Verify authentication token"""
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'success': False, 'error': 'No valid authorization header'}), 401
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Find active session with this token
        session = AuthSession.query.filter_by(
            session_token=token,
            is_active=True
        ).first()
        
        if not session or session.expires_at < datetime.utcnow():
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 401
        
        # Return user info
        user = session.user
        return jsonify({
            'success': True,
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'organization': {
                    'id': user.organization.id,
                    'name': user.organization.name,
                    'email': user.organization.email
                } if user.organization else None
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Desktop Integration
@app.route('/api/desktop/auth/status', methods=['GET'])
def desktop_auth_status():
    """Check desktop authentication status"""
    app_id = request.args.get('app_id')
    if not app_id:
        return jsonify({'success': False, 'error': 'Missing app_id'}), 400
    
    session_data = desktop_auth_sessions.get(app_id)
    if session_data:
        return jsonify({
            'authenticated': True,
            'user': session_data['user'],
            'token': session_data['token']
        })
    else:
        return jsonify({'authenticated': False})

@app.route('/api/desktop/auth/complete', methods=['POST'])
def desktop_auth_complete():
    """Complete desktop authentication"""
    try:
        data = request.get_json()
        app_id = data.get('app_id')
        user_data = data.get('user')
        token = data.get('token')
        
        if not all([app_id, user_data, token]):
            return jsonify({'success': False, 'error': 'Missing required data'}), 400
        
        # Store authentication data for desktop app
        desktop_auth_sessions[app_id] = {
            'user': user_data,
            'token': token,
            'timestamp': datetime.utcnow()
        }
        
        return jsonify({'success': True})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Organization Management
@app.route('/api/organization/register', methods=['POST'])
def register_organization():
    """Register new organization"""
    try:
        data = request.get_json()
        
        # Verify signature
        signature = data.pop('signature', '')
        if not verify_signature(data, signature):
            return jsonify({'success': False, 'error': 'Invalid signature'}), 400
        
        org_name = data.get('organization_name')
        org_description = data.get('organization_description', '')
        org_email = data.get('organization_email')
        admin_name = data.get('admin_name')
        admin_email = data.get('admin_email')
        admin_password = data.get('admin_password')
        
        # Validate input
        if not all([org_name, org_email, admin_name, admin_email, admin_password]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Check if organization already exists
        if Organization.query.filter_by(email=org_email).first():
            return jsonify({'success': False, 'error': 'Organization email already registered'}), 400
        
        # Check if admin email already exists
        if User.query.filter_by(email=admin_email).first():
            return jsonify({'success': False, 'error': 'Admin email already registered'}), 400
        
        # Create organization
        organization = Organization(
            name=org_name,
            description=org_description,
            email=org_email
        )
        db.session.add(organization)
        db.session.flush()  # Get organization ID
        
        # Create admin user
        admin_user = User(
            organization_id=organization.id,
            email=admin_email,
            name=admin_name,
            password_hash=hash_password(admin_password),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Organization registered successfully',
            'organization': {
                'id': organization.id,
                'name': organization.name,
                'email': organization.email
            },
            'admin': {
                'id': admin_user.id,
                'name': admin_user.name,
                'email': admin_user.email,
                'role': admin_user.role
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Authenticate user login"""
    try:
        data = request.get_json()
        ip_address = request.remote_addr
        
        # Verify signature
        signature = data.pop('signature', '')
        if not verify_signature(data, signature):
            return jsonify({'success': False, 'error': 'Invalid signaturer'}), 400
        
        email = data.get('email')
        password = data.get('password')
        machine_id = data.get('machine_id')
        
        # Check rate limiting
        if not check_rate_limit(email, ip_address):
            return jsonify({'success': False, 'error': 'Too many failed attempts. Try again later.'}), 429
        
        # Find user
        user = User.query.filter_by(email=email, is_active=True).first()
        if not user or not verify_password(password, user.password_hash):
            log_login_attempt(email, ip_address, False)
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Check if organization is active
        if not user.organization.is_active:
            log_login_attempt(email, ip_address, False, user.organization_id)
            return jsonify({'success': False, 'error': 'Organization account is disabled'}), 401
        
        # Update machine ID if provided
        if machine_id:
            user.machine_id = machine_id
        
        # Update last login
        user.last_login = datetime.utcnow()
        
        # Create session
        session_token = generate_session_token()
        expires_at = datetime.utcnow() + timedelta(hours=24)  # 24 hour session
        
        session = AuthSession(
            user_id=user.id,
            session_token=session_token,
            machine_id=machine_id,
            expires_at=expires_at
        )
        db.session.add(session)
        db.session.commit()
        
        log_login_attempt(email, ip_address, True, user.organization_id)
        
        return jsonify({
            'success': True,
            'token': session_token,
            'expires_at': int(expires_at.timestamp()),
            'user': {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role,
                'organization': {
                    'id': user.organization.id,
                    'name': user.organization.name
                }
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """Logout user"""
    try:
        token = request.headers.get('Authorization')
        if token.startswith('Bearer '):
            token = token[7:]
        
        session = AuthSession.query.filter_by(session_token=token).first()
        if session:
            session.is_active = False
            db.session.commit()
        
        return jsonify({'success': True, 'message': 'Logged out successfully'})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/auth/verify-token', methods=['POST'])
def verify_token():
    """Verify authentication token"""
    try:
        data = request.get_json()
        token = data.get('token')
        
        if not token:
            return jsonify({'valid': False, 'error': 'No token provided'})
        
        session = AuthSession.query.filter_by(
            session_token=token,
            is_active=True
        ).first()
        
        if not session or session.expires_at < datetime.utcnow():
            return jsonify({'valid': False, 'error': 'Invalid or expired token'})
        
        return jsonify({
            'valid': True,
            'user': {
                'id': session.user.id,
                'name': session.user.name,
                'email': session.user.email,
                'role': session.user.role,
                'organization': {
                    'id': session.user.organization.id,
                    'name': session.user.organization.name
                }
            }
        })
        
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)})

# Employee Management
@app.route('/api/organization/employees', methods=['GET'])
@require_auth
@require_admin
def get_employees():
    """Get organization employees"""
    try:
        organization_id = request.current_user.organization_id
        
        employees = User.query.filter_by(
            organization_id=organization_id,
            is_active=True
        ).all()
        
        employee_list = []
        for employee in employees:
            employee_list.append({
                'id': employee.id,
                'name': employee.name,
                'email': employee.email,
                'role': employee.role,
                'created_at': employee.created_at.isoformat(),
                'last_login': employee.last_login.isoformat() if employee.last_login else None
            })
        
        return jsonify({
            'success': True,
            'employees': employee_list
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/organization/employees', methods=['POST'])
@require_auth
@require_admin
def add_employee():
    """Add new employee to organization"""
    try:
        data = request.get_json()
        organization_id = request.current_user.organization_id
        
        name = data.get('name')
        email = data.get('email')
        role = data.get('role', 'employee')
        password = data.get('password')
        
        # Validate input
        if not all([name, email, password]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        if role not in ['admin', 'employee']:
            return jsonify({'success': False, 'error': 'Invalid role'}), 400
        
        # Check if email already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Create employee
        employee = User(
            organization_id=organization_id,
            email=email,
            name=name,
            password_hash=hash_password(password),
            role=role
        )
        db.session.add(employee)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Employee added successfully',
            'employee': {
                'id': employee.id,
                'name': employee.name,
                'email': employee.email,
                'role': employee.role
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/organization/employees/<int:employee_id>', methods=['DELETE'])
@require_auth
@require_admin
def remove_employee(employee_id):
    """Remove employee from organization"""
    try:
        organization_id = request.current_user.organization_id
        
        employee = User.query.filter_by(
            id=employee_id,
            organization_id=organization_id
        ).first()
        
        if not employee:
            return jsonify({'success': False, 'error': 'Employee not found'}), 404
        
        # Prevent removing self
        if employee.id == request.current_user.id:
            return jsonify({'success': False, 'error': 'Cannot remove yourself'}), 400
        
        # Deactivate employee instead of deleting
        employee.is_active = False
        
        # Deactivate all sessions
        AuthSession.query.filter_by(user_id=employee.id).update({'is_active': False})
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Employee removed successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Task Sharing (placeholder endpoints)
@app.route('/api/tasks/share', methods=['POST'])
@require_auth
def share_task():
    """Share task with employees"""
    try:
        data = request.get_json()
        print(f"DEBUG: Received data: {data}")  # Debug logging
        organization_id = request.current_user.organization_id
        
        task_id = data.get('task_id')
        task_name = data.get('task_name')
        task_data = data.get('task_data')
        share_with_organization = data.get('share_with_organization', False)
        user_ids = data.get('user_ids', [])
        
        # Handle both old and new permission formats for backward compatibility
        permissions_data = data.get('permissions')
        print(f"DEBUG: Permissions data: {permissions_data}")  # Debug logging
        if permissions_data and isinstance(permissions_data, dict):
            # New format with step-level permissions
            permissions = permissions_data
            print(f"DEBUG: Using new format: {permissions}")
        else:
            # Old format - just a permission string
            permission = data.get('permission', 'view')
            permissions = {'permission': permission}
            print(f"DEBUG: Using old format: {permissions}")
        
        message = data.get('message', '')
        
        # If task_id is provided, we're sharing an existing task
        # Otherwise, we're creating a new shared task
        if not task_name and not task_id:
            return jsonify({'success': False, 'error': 'Missing task name or task ID'}), 400
        
        # If sharing with specific users, validate they exist in the organization
        if not share_with_organization and user_ids:
            valid_users = User.query.filter(
                User.id.in_(user_ids),
                User.organization_id == organization_id
            ).count()
            if valid_users != len(user_ids):
                return jsonify({'success': False, 'error': 'Some users not found in organization'}), 400
        
        print(f"DEBUG: About to create SharedTask with permissions: {permissions}")
        shared_task = SharedTask(
            organization_id=organization_id,
            created_by=request.current_user.id,
            task_name=task_name or f"Shared Task {task_id}",
            task_data=json.dumps(task_data) if task_data else json.dumps({}),
            permissions=json.dumps(permissions),
            shared_with=None if share_with_organization else json.dumps(user_ids),
            message=message
        )
        print(f"DEBUG: SharedTask created, adding to session")
        db.session.add(shared_task)
        print(f"DEBUG: Committing to database")
        db.session.commit()
        print(f"DEBUG: Successfully committed")
        
        return jsonify({
            'success': True,
            'message': 'Task shared successfully',
            'task_id': shared_task.id
        })
        
    except Exception as e:
        print(f"DEBUG: Exception in share_task: {str(e)}")
        import traceback
        traceback.print_exc()
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tasks/shared', methods=['GET'])
@require_auth
def get_shared_tasks():
    """Get shared tasks for current user"""
    try:
        user_id = request.current_user.id
        organization_id = request.current_user.organization_id
        
        # Get tasks shared with this user or all employees
        tasks = SharedTask.query.filter(
            SharedTask.organization_id == organization_id,
            SharedTask.is_active == True,
            db.or_(
                SharedTask.shared_with == None,  # Shared with all
                SharedTask.shared_with.contains(str(user_id))  # Shared with specific user
            )
        ).all()
        
        task_list = []
        for task in tasks:
            try:
                # Get creator info
                creator = User.query.get(task.created_by)
                
                # Handle message field safely (might not exist in older databases)
                try:
                    message = task.message if hasattr(task, 'message') else ''
                except:
                    message = ''
                
                task_list.append({
                    'id': task.id,
                    'name': task.task_name,
                    'created_by': creator.name if creator else 'Unknown',
                    'created_by_email': creator.email if creator else '',
                    'created_at': task.created_at.isoformat(),
                    'updated_at': task.updated_at.isoformat(),
                    'permissions': json.loads(task.permissions) if task.permissions else {'permission': 'view'},
                    'message': message,
                    'task_data': json.loads(task.task_data) if task.task_data else {},
                    'shared_with_all': task.shared_with is None,
                    'shared_with_users': json.loads(task.shared_with) if task.shared_with else []
                })
            except Exception as task_error:
                print(f"❌ Error processing task {task.id}: {task_error}")
                continue
        
        return jsonify({
            'success': True,
            'tasks': task_list
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@require_auth
def delete_shared_task(task_id):
    """Delete a shared task (only creator or admin can delete)"""
    try:
        user_id = request.current_user.id
        organization_id = request.current_user.organization_id
        is_admin = request.current_user.role == 'admin'
        
        # Find the task
        task = SharedTask.query.filter(
            SharedTask.id == task_id,
            SharedTask.organization_id == organization_id,
            SharedTask.is_active == True
        ).first()
        
        if not task:
            return jsonify({'success': False, 'error': 'Task not found'}), 404
        
        # Check if user can delete (creator or admin)
        if task.created_by != user_id and not is_admin:
            return jsonify({'success': False, 'error': 'Permission denied. Only the task creator or admin can delete this task.'}), 403
        
        # Soft delete the task
        task.is_active = False
        task.updated_at = datetime.utcnow()
        
        # Log the deletion
        log_entry = TaskAccessLog(
            task_id=task_id,
            user_id=user_id,
            action='delete',
            details=f'Task "{task.task_name}" deleted by {request.current_user.name}'
        )
        db.session.add(log_entry)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': f'Task "{task.task_name}" has been deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/organization/users', methods=['GET'])
@require_auth
def get_organization_users():
    """Get all users in the current organization for sharing tasks"""
    try:
        organization_id = request.current_user.organization_id
        current_user_id = request.current_user.id
        
        # Get all active users in the organization except the current user
        users = User.query.filter(
            User.organization_id == organization_id,
            User.id != current_user_id,
            User.is_active == True
        ).all()
        
        user_list = []
        for user in users:
            user_list.append({
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'role': user.role
            })
        
        return jsonify({
            'success': True,
            'users': user_list
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/tasks/my-shared', methods=['GET'])
@require_auth
def get_my_shared_tasks():
    """Get tasks created by the current user"""
    try:
        user_id = request.current_user.id
        organization_id = request.current_user.organization_id
        
        # Get tasks created by this user
        tasks = SharedTask.query.filter(
            SharedTask.organization_id == organization_id,
            SharedTask.created_by == user_id,
            SharedTask.is_active == True
        ).all()
        
        task_list = []
        for task in tasks:
            try:
                # Get shared with users info
                shared_with_users = []
                if task.shared_with:
                    user_ids = json.loads(task.shared_with)
                    users = User.query.filter(User.id.in_(user_ids)).all()
                    shared_with_users = [{'id': u.id, 'name': u.name, 'email': u.email} for u in users]
                
                task_list.append({
                    'id': task.id,
                    'name': task.task_name,
                    'created_at': task.created_at.isoformat(),
                    'updated_at': task.updated_at.isoformat(),
                    'permissions': json.loads(task.permissions) if task.permissions else {'permission': 'view'},
                    'message': task.message if hasattr(task, 'message') else '',
                    'shared_with_all': task.shared_with is None,
                    'shared_with_users': shared_with_users,
                    'task_data': json.loads(task.task_data) if task.task_data else {}
                })
            except Exception as task_error:
                print(f"❌ Error processing task {task.id}: {task_error}")
                continue
        
        return jsonify({
            'success': True,
            'tasks': task_list
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Web Routes
@app.route('/')
def index():
    """Root page"""
    return '''
    <html>
    <head><title>Enterprise Authentication Server</title></head>
    <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>🏢 Enterprise Authentication Server</h1>
        <p>Server is running successfully!</p>
        <p><a href="/admin" style="color: #667eea; text-decoration: none;">Access Admin Panel</a></p>
    </body>
    </html>
    '''

if __name__ == '__main__':
    # Create tables
    with app.app_context():
        db.create_all()
        
        # Initialize field protection tables
        if FIELD_PROTECTION_AVAILABLE:
            try:
                init_field_protection_tables()
                print("✅ Field protection tables initialized")
            except Exception as e:
                print(f"❌ Error initializing field protection tables: {e}")
        
        # Create sample organization if none exist
        if Organization.query.count() == 0:
            sample_org = Organization(
                name='Sample Corporation',
                description='A sample organization for testing',
                email='admin@samplecorp.com'
            )
            db.session.add(sample_org)
            db.session.flush()
            
            sample_admin = User(
                organization_id=sample_org.id,
                email='admin@samplecorp.com',
                name='Admin User',
                password_hash=hash_password('admin123'),
                role='admin'
            )
            db.session.add(sample_admin)
            
            sample_employee = User(
                organization_id=sample_org.id,
                email='employee@samplecorp.com',
                name='Employee User',
                password_hash=hash_password('employee123'),
                role='employee'
            )
            db.session.add(sample_employee)
            
            db.session.commit()
            
            print("Sample organization created:")
            print(f"  Organization: {sample_org.name} ({sample_org.email})")
            print(f"  Admin: {sample_admin.name} ({sample_admin.email}) - Password: admin123")
            print(f"  Employee: {sample_employee.name} ({sample_employee.email}) - Password: employee123")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
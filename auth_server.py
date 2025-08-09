#!/usr/bin/env python3
"""
Authentication Server API
Handles user registration, login, and license verification
"""

from flask import Flask, request, jsonify
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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
CORS(app)

# Your app secret (must match client)
APP_SECRET = "your-app-secret-key-here"

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(64), nullable=False)
    user_type = db.Column(db.String(20), nullable=False, default='personal')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)

class License(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    license_key = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    license_type = db.Column(db.String(20), nullable=False)
    machine_id = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('licenses', lazy=True))

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    success = db.Column(db.Boolean, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class LicenseKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    license_type = db.Column(db.String(20), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    used_at = db.Column(db.DateTime)

# Helper Functions
def verify_signature(data, signature):
    """Verify HMAC signature"""
    expected_signature = hmac.new(
        APP_SECRET.encode(),
        json.dumps(data, sort_keys=True).encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, expected_signature)

def generate_license_key():
    """Generate a unique license key"""
    return secrets.token_hex(32).upper()

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

def log_login_attempt(email, ip_address, success):
    """Log login attempt"""
    attempt = LoginAttempt(
        email=email,
        ip_address=ip_address,
        success=success
    )
    db.session.add(attempt)
    db.session.commit()

# API Routes
@app.route('/api/register', methods=['POST'])
def register():
    """Register new user"""
    try:
        data = request.get_json()
        
        # Verify signature
        signature = data.pop('signature', '')
        if not verify_signature(data, signature):
            return jsonify({'success': False, 'error': 'Invalid signature'}), 400
        
        email = data.get('email')
        password_hash = data.get('password_hash')
        license_key = data.get('license_key')
        machine_id = data.get('machine_id')
        user_type = data.get('user_type', 'personal')
        
        # Validate input
        if not all([email, password_hash, license_key, machine_id]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
        
        # Verify license key
        license_record = LicenseKey.query.filter_by(key=license_key, is_used=False).first()
        if not license_record:
            return jsonify({'success': False, 'error': 'Invalid or already used license key'}), 400
        
        if license_record.license_type != user_type:
            return jsonify({'success': False, 'error': 'License type mismatch'}), 400
        
        # Create user
        user = User(
            email=email,
            password_hash=password_hash,
            user_type=user_type
        )
        db.session.add(user)
        db.session.flush()  # Get user ID
        
        # Create license
        expires_at = datetime.utcnow() + timedelta(days=365)  # 1 year
        license = License(
            license_key=license_key,
            user_id=user.id,
            license_type=user_type,
            machine_id=machine_id,
            expires_at=expires_at
        )
        db.session.add(license)
        
        # Mark license key as used
        license_record.is_used = True
        license_record.used_at = datetime.utcnow()
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'license_data': {
                'license_key': license_key,
                'machine_id': machine_id,
                'expires_at': int(expires_at.timestamp()),
                'user_type': user_type
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Authenticate user login"""
    try:
        data = request.get_json()
        ip_address = request.remote_addr
        
        # Verify signature
        signature = data.pop('signature', '')
        if not verify_signature(data, signature):
            return jsonify({'success': False, 'error': 'Invalid signature'}), 400
        
        email = data.get('email')
        password_hash = data.get('password_hash')
        machine_id = data.get('machine_id')
        
        # Check rate limiting
        if not check_rate_limit(email, ip_address):
            return jsonify({'success': False, 'error': 'Too many failed attempts. Try again later.'}), 429
        
        # Find user
        user = User.query.filter_by(email=email, is_active=True).first()
        if not user or user.password_hash != password_hash:
            log_login_attempt(email, ip_address, False)
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
        
        # Check license
        license = License.query.filter_by(
            user_id=user.id,
            machine_id=machine_id,
            is_active=True
        ).first()
        
        if not license:
            log_login_attempt(email, ip_address, False)
            return jsonify({'success': False, 'error': 'No valid license for this machine'}), 401
        
        if datetime.utcnow() > license.expires_at:
            log_login_attempt(email, ip_address, False)
            return jsonify({'success': False, 'error': 'License expired'}), 401
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.session.commit()
        
        log_login_attempt(email, ip_address, True)
        
        return jsonify({
            'success': True,
            'user_type': user.user_type,
            'license_valid': True,
            'expires_at': int(license.expires_at.timestamp())
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/verify', methods=['POST'])
def verify_license():
    """Verify license validity"""
    try:
        data = request.get_json()
        
        # Verify signature
        signature = data.pop('signature', '')
        if not verify_signature(data, signature):
            return jsonify({'valid': False, 'error': 'Invalid signature'}), 400
        
        license_key = data.get('license_key')
        machine_id = data.get('machine_id')
        
        # Find license
        license = License.query.filter_by(
            license_key=license_key,
            machine_id=machine_id,
            is_active=True
        ).first()
        
        if not license:
            return jsonify({'valid': False, 'error': 'License not found'})
        
        if datetime.utcnow() > license.expires_at:
            return jsonify({'valid': False, 'error': 'License expired'})
        
        # Check if user is active
        if not license.user.is_active:
            return jsonify({'valid': False, 'error': 'User account disabled'})
        
        return jsonify({'valid': True})
        
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 500

@app.route('/api/generate-keys', methods=['POST'])
def generate_keys():
    """Generate license keys (admin only)"""
    try:
        data = request.get_json()
        admin_key = data.get('admin_key')
        
        # Simple admin authentication (enhance this in production)
        if admin_key != 'your-admin-key-here':
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401
        
        license_type = data.get('license_type', 'personal')
        count = data.get('count', 1)
        
        keys = []
        for _ in range(count):
            key = generate_license_key()
            license_key = LicenseKey(
                key=key,
                license_type=license_type
            )
            db.session.add(license_key)
            keys.append(key)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'keys': keys,
            'license_type': license_type
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

# Web Routes
@app.route('/')
def index():
    """Root page - redirect to admin"""
    return '''
    <html>
    <head><title>Authentication Server</title></head>
    <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h1>🔐 Authentication Server</h1>
        <p>Server is running successfully!</p>
        <p><a href="/admin" style="color: #667eea; text-decoration: none;">Access Admin Panel</a></p>
    </body>
    </html>
    '''

@app.route('/admin')
def admin_login():
    """Admin login page"""
    from flask import render_template_string
    
    # Simple admin login form
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Login</title>
        <style>
            body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 50px; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #5a6fd8; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>🔐 Admin Login</h2>
            <form method="POST" action="/admin/login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    '''

@app.route('/admin/login', methods=['POST'])
def admin_login_post():
    """Handle admin login"""
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Simple admin check (in production, use proper authentication)
    if username == 'admin' and password == 'admin123':  # Change this!
        return admin_dashboard()
    else:
        return '''
        <script>
        alert('Invalid credentials');
        window.location.href = '/admin';
        </script>
        '''

@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin dashboard"""
    # Get statistics
    total_users = User.query.count()
    active_licenses = License.query.filter_by(is_active=True).count()
    unused_keys = LicenseKey.query.filter_by(is_used=False).count()
    
    return f'''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }}
            .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
            .stat-card {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
            .actions {{ background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .btn {{ padding: 10px 20px; background: #667eea; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }}
            .btn:hover {{ background: #5a6fd8; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛠️ Admin Dashboard</h1>
        </div>
        <div class="container">
            <div class="stats">
                <div class="stat-card">
                    <h3>Total Users</h3>
                    <div class="stat-number">{total_users}</div>
                </div>
                <div class="stat-card">
                    <h3>Active Licenses</h3>
                    <div class="stat-number">{active_licenses}</div>
                </div>
                <div class="stat-card">
                    <h3>Unused Keys</h3>
                    <div class="stat-number">{unused_keys}</div>
                </div>
            </div>
            <div class="actions">
                <h2>Quick Actions</h2>
                <button class="btn" onclick="generateKeys()">Generate License Keys</button>
                <button class="btn" onclick="viewUsers()">View Users</button>
                <button class="btn" onclick="viewLicenses()">View Licenses</button>
            </div>
        </div>
        <script>
            function generateKeys() {{
                const type = prompt('License type (personal/enterprise):', 'personal');
                const count = prompt('Number of keys:', '5');
                if (type && count) {{
                    fetch('/api/generate-keys', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{license_type: type, count: parseInt(count)}})
                    }})
                    .then(r => r.json())
                    .then(data => {{
                        if (data.success) {{
                            alert('Generated keys:\\n\\n' + data.keys.join('\\n'));
                            location.reload();
                        }} else {{
                            alert('Error: ' + data.error);
                        }}
                    }});
                }}
            }}
            function viewUsers() {{ alert('User management coming soon!'); }}
            function viewLicenses() {{ alert('License management coming soon!'); }}
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    # Create tables
    with app.app_context():
        db.create_all()
        
        # Create sample keys if none exist
        if LicenseKey.query.count() == 0:
            sample_keys = [
                LicenseKey(key=generate_license_key(), license_type='personal'),
                LicenseKey(key=generate_license_key(), license_type='personal'),
                LicenseKey(key=generate_license_key(), license_type='enterprise'),
                LicenseKey(key=generate_license_key(), license_type='enterprise'),
            ]
            
            for key in sample_keys:
                db.session.add(key)
            
            db.session.commit()
            
            print("Sample license keys:")
            for key in sample_keys:
                print(f"  {key.license_type}: {key.key}")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
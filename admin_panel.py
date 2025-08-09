#!/usr/bin/env python3
"""
Admin Panel for License Management
Web interface for managing users, licenses, and system statistics
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from auth_server import app, db, User, License, LicenseKey, LoginAttempt, generate_license_key
from datetime import datetime, timedelta
import secrets

# Admin routes
@app.route('/admin')
def admin_dashboard():
    """Admin dashboard"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    # Get statistics
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_licenses = License.query.count()
    active_licenses = License.query.filter(
        License.is_active == True,
        License.expires_at > datetime.utcnow()
    ).count()
    
    recent_logins = LoginAttempt.query.filter(
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(days=7),
        LoginAttempt.success == True
    ).count()
    
    unused_keys = LicenseKey.query.filter_by(is_used=False).count()
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'total_licenses': total_licenses,
        'active_licenses': active_licenses,
        'recent_logins': recent_logins,
        'unused_keys': unused_keys
    }
    
    return render_template('admin_dashboard.html', stats=stats)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Admin login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Simple admin authentication (enhance this in production)
        if username == 'admin' and password == 'your-admin-password-here':
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template('admin_login.html', error='Invalid credentials')
    
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    """Admin logout"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/users')
def admin_users():
    """Manage users"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/licenses')
def admin_licenses():
    """Manage licenses"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    licenses = License.query.join(User).order_by(License.created_at.desc()).all()
    return render_template('admin_licenses.html', licenses=licenses)

@app.route('/admin/keys')
def admin_keys():
    """Manage license keys"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    keys = LicenseKey.query.order_by(LicenseKey.created_at.desc()).all()
    return render_template('admin_keys.html', keys=keys)

@app.route('/admin/generate-keys', methods=['POST'])
def admin_generate_keys():
    """Generate new license keys"""
    if not session.get('admin_logged_in'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    license_type = request.form.get('license_type', 'personal')
    count = int(request.form.get('count', 1))
    
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

@app.route('/admin/user/<int:user_id>/toggle')
def admin_toggle_user(user_id):
    """Toggle user active status"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    
    return redirect(url_for('admin_users'))

if __name__ == '__main__':
    app.secret_key = secrets.token_hex(32)
    app.run(debug=True, host='0.0.0.0', port=5000)
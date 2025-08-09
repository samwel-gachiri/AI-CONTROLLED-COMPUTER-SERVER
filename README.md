# Enterprise Authentication Server

## 📊 Data Storage Locations

### **Current Implementation (SQLite)**

**Test Environment:**

- **Location**: `enterprise_auth.db` (SQLite file)
- **Path**: Created in the `server/` directory when you run the server
- **Backup**: Easy to backup - just copy the `.db` file

**Production Considerations:**

- **Current**: SQLite (suitable for small-medium deployments)
- **Scalable Options**: Can easily migrate to PostgreSQL, MySQL, or other databases
- **Configuration**: Set via `DATABASE_URL` environment variable

### **Database Configuration Options**

The system is designed to be database-agnostic. You can configure it via environment variables:

```bash
# SQLite (current default)
DATABASE_URL=sqlite:///enterprise_auth.db

# PostgreSQL (for production)
DATABASE_URL=postgresql://user:password@localhost/enterprise_auth

# MySQL (alternative)
DATABASE_URL=mysql://user:password@localhost/enterprise_auth
```

## 🧪 How to Test Everything is Running Smoothly

### **Step 1: Quick System Check**

```bash
cd ..
python test_enterprise_simple.py
```

**Expected Output:**

```
✅ Enterprise auth server imports successfully
✅ All database tables created successfully
✅ Sample organization found: Sample Corporation
✅ Found 2 users in organization
🎉 All tests passed!
```

### **Step 2: Start the Server**

```bash
python enterprise_auth_server.py
```

**Expected Output:**

```
Sample organization created:
  Organization: Sample Corporation (admin@samplecorp.com)
  Admin: Admin User (admin@samplecorp.com) - Password: admin123
  Employee: Employee User (employee@samplecorp.com) - Password: employee123
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://[your-ip]:5000
```

### **Step 3: Comprehensive API Testing**

In a **new terminal** (keep server running):

```bash
cd ..
python test_enterprise_auth_system.py
```

**Expected Output:**

```
🏢 Testing Organization Registration
✅ Organization registration successful

🔐 Testing Admin Login
✅ Admin login successful

👥 Testing Employee Management
✅ Employee added successfully
✅ Employee list retrieved successfully

👤 Testing Employee Login
✅ Employee login successful

📋 Testing Task Sharing
✅ Task shared successfully
✅ Employee can access shared tasks

🔍 Testing Token Verification
✅ Token verification successful

🚫 Testing Rate Limiting
✅ Rate limiting activated after 5 failed attempts

🎉 All tests completed!
```

### **Step 4: Manual Browser Test**

1. **Open browser**: Go to `http://localhost:5000`
2. **Expected**: See "🏢 Enterprise Authentication Server" page
3. **API Test**: Try `http://localhost:5000/api/auth/verify-token` (should return error - this is expected)

## 🔍 Troubleshooting Commands

### **Check Database Contents**

```bash
python -c "
import sys; sys.path.append('.')
import enterprise_auth_server
with enterprise_auth_server.app.app_context():
    orgs = enterprise_auth_server.Organization.query.all()
    users = enterprise_auth_server.User.query.all()
    print(f'Organizations: {len(orgs)}')
    print(f'Users: {len(users)}')
    for org in orgs:
        print(f'  - {org.name} ({org.email})')
    for user in users:
        print(f'  - {user.name} ({user.email}) - {user.role}')
"
```

### **Reset Database (if needed)**

```bash
# Delete database file
rm enterprise_auth.db

# Recreate with sample data
cd ..
python create_sample_data.py
```

### **Check Dependencies**

```bash
pip list | grep -E "(Flask|bcrypt|SQLAlchemy)"
```

## 📁 File Structure Overview

```
server/
├── enterprise_auth_server.py     # Main server
├── enterprise_auth.db           # SQLite database (created when server runs)
├── requirements.txt             # Dependencies
├── migrate_to_enterprise.py     # Migration script
├── .env                         # Environment variables
└── README.md                    # This file

../
├── test_enterprise_simple.py        # Basic tests
├── test_enterprise_auth_system.py   # Full API tests
├── create_sample_data.py            # Sample data creation
└── ENTERPRISE_AUTH_IMPLEMENTATION_SUMMARY.md
```

## 🚀 Production Deployment Considerations

### **Environment Variables for Production**

Create a `.env` file in the server directory:

```bash
# Security
SECRET_KEY=your-very-secure-secret-key-here
APP_SECRET=your-app-hmac-secret-here

# Database (PostgreSQL recommended for production)
DATABASE_URL=postgresql://user:password@localhost/enterprise_auth

# Optional: Email notifications
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@company.com
SMTP_PASSWORD=your-app-password
```

### **Production Database Migration**

```bash
# Install PostgreSQL adapter
pip install psycopg2-binary

# Set environment variable
export DATABASE_URL=postgresql://user:password@localhost/enterprise_auth

# Run server (will create tables automatically)
python enterprise_auth_server.py
```

## ✅ Quick Health Check Script

Test everything in sequence:

```bash
cd ..
python test_enterprise_simple.py && echo "✅ Basic tests passed" || echo "❌ Basic tests failed"
```

## 🔐 Default Test Accounts

The system includes sample data for testing:

**Organization**: Sample Corporation  
**Admin**: admin@samplecorp.com / admin123  
**Employee**: employee@samplecorp.com / employee123

## 🏗️ Database Schema

The enterprise authentication system includes:

- **Organizations**: Company information and settings
- **Users**: Employees and admins with role-based access
- **Shared Tasks**: Tasks shared by admins with permission controls
- **Auth Sessions**: Secure session management
- **Task Access Logs**: Audit trail for compliance
- **Login Attempts**: Security monitoring and rate limiting

## 🔧 API Endpoints

### Organization Management

- `POST /api/organization/register` - Register new organization
- `GET /api/organization/employees` - List employees (admin only)
- `POST /api/organization/employees` - Add employee (admin only)
- `DELETE /api/organization/employees/{id}` - Remove employee (admin only)

### Authentication

- `POST /api/auth/login` - Employee/admin login
- `POST /api/auth/logout` - Secure logout
- `POST /api/auth/verify-token` - Token validation

### Task Sharing

- `POST /api/tasks/share` - Share tasks with permissions (admin only)
- `GET /api/tasks/shared` - Get shared tasks for user

## 🛡️ Security Features

- **HMAC Signature Validation**: All API requests require valid signatures
- **bcrypt Password Hashing**: Secure password storage
- **Session Management**: Secure tokens with expiration
- **Rate Limiting**: Protection against brute force attacks
- **Role-Based Access Control**: Admin/employee permissions
- **Audit Logging**: Comprehensive activity tracking

## 📞 Support

If you encounter issues:

1. Check the server logs for error messages
2. Verify database connectivity
3. Ensure all dependencies are installed
4. Run the test suite to identify specific problems
5. Check environment variables are properly set

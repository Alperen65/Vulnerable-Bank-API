# app.py - Main Flask Application with Multiple Vulnerabilities
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import sqlite3
import os

app = Flask(__name__)

# ZAFIYET 1: Hardcoded credentials ve weak secret
app.config['SECRET_KEY'] = 'secret123'  # Weak secret!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# =============================================================================
# DATABASE MODELS
# =============================================================================

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(100))
    ssn = db.Column(db.String(11))  # Sensitive data
    phone = db.Column(db.String(15))
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def to_dict(self):
        # ZAFIYET 2: Excessive Data Exposure - tüm veriler döndürülüyor
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'password': self.password,  # CRITICAL: Password exposed!
            'full_name': self.full_name,
            'ssn': self.ssn,  # CRITICAL: SSN exposed!
            'phone': self.phone,
            'role': self.role,
            'created_at': str(self.created_at)
        }

class Account(db.Model):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    balance = db.Column(db.Float, default=0.0)
    account_type = db.Column(db.String(20))  # 'checking', 'savings'
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'account_number': self.account_number,
            'balance': self.balance,
            'account_type': self.account_type,
            'created_at': str(self.created_at)
        }

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    from_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'))
    to_account_id = db.Column(db.Integer, db.ForeignKey('accounts.id'))
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'from_account_id': self.from_account_id,
            'to_account_id': self.to_account_id,
            'amount': self.amount,
            'description': self.description,
            'timestamp': str(self.timestamp)
        }

class ApiKey(db.Model):
    __tablename__ = 'api_keys'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    key = db.Column(db.String(100), unique=True)
    is_active = db.Column(db.Boolean, default=True)

# =============================================================================
# AUTHENTICATION DECORATORS (WITH VULNERABILITIES)
# =============================================================================

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # ZAFIYET 3: Multiple authentication methods without proper validation
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(' ')[1]
            except:
                token = auth_header
        
        # ZAFIYET 4: Token can be passed via query parameter (insecure)
        if not token and 'token' in request.args:
            token = request.args.get('token')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # ZAFIYET 5: No algorithm verification - algorithm confusion attack possible
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256', 'none'])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # ZAFIYET 6: Admin check relies only on JWT claim, no server-side verification
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            # Sadece JWT içindeki role claim'e bakıyor!
            if data.get('role') != 'admin':
                return jsonify({'message': 'Admin access required!'}), 403
        except:
            return jsonify({'message': 'Invalid token!'}), 401
        
        return f(*args, **kwargs)
    
    return decorated

# =============================================================================
# VULNERABLE ENDPOINTS
# =============================================================================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # ZAFIYET 7: No input validation
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name', '')
    ssn = data.get('ssn', '')
    
    # ZAFIYET 8: Weak password policy - no complexity requirements
    if not username or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400
    
    # ZAFIYET 9: Password stored with weak hashing (MD5-like)
    # In production, this should use bcrypt with proper salt
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=4)
    
    user = User(
        username=username,
        email=email,
        password=hashed_password,
        full_name=full_name,
        ssn=ssn,
        role='user'
    )
    
    try:
        db.session.add(user)
        db.session.commit()
        
        # Auto-create account for new user
        account = Account(
            user_id=user.id,
            account_number=f"ACC{str(user.id).zfill(8)}",
            balance=1000.0,  # Initial bonus
            account_type='checking'
        )
        db.session.add(account)
        db.session.commit()
        
        return jsonify({'message': 'User registered successfully', 'user_id': user.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 400

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    # ZAFIYET 10: SQL Injection via raw query
    try:
        conn = sqlite3.connect('instance/bank.db')
        cursor = conn.cursor()
        
        # CRITICAL SQL INJECTION VULNERABILITY
        query = f"SELECT * FROM users WHERE username = '{username}'"
        cursor.execute(query)
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            return jsonify({'message': 'Invalid credentials'}), 401
        
        # ZAFIYET 11: Password check bypassed if SQL injection successful
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            # ZAFIYET 12: JWT with sensitive data in payload
            token = jwt.encode({
                'user_id': user.id,
                'username': user.username,
                'role': user.role,
                'ssn': user.ssn,  # CRITICAL: SSN in JWT!
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'user': user.to_dict()  # ZAFIYET: All user data exposed
            }), 200
        else:
            return jsonify({'message': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
@token_required
def get_users(current_user):
    # ZAFIYET 13: No pagination - can cause DoS
    # ZAFIYET 14: All users visible to any authenticated user
    users = User.query.all()
    
    # ZAFIYET 15: Excessive data exposure - returns all fields including passwords
    return jsonify({
        'users': [user.to_dict() for user in users],
        'count': len(users)
    }), 200

@app.route('/api/user/<user_id>', methods=['GET'])
@token_required
def get_user(current_user, user_id):
    # ZAFIYET 16: SQL Injection via URL parameter
    try:
        conn = sqlite3.connect('instance/bank.db')
        cursor = conn.cursor()
        
        # CRITICAL SQL INJECTION
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        user_data = cursor.fetchone()
        conn.close()
        
        if user_data:
            return jsonify({
                'id': user_data[0],
                'username': user_data[1],
                'email': user_data[2],
                'password': user_data[3],  # EXPOSED!
                'full_name': user_data[4],
                'ssn': user_data[5],  # EXPOSED!
                'phone': user_data[6],
                'role': user_data[7]
            }), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': 'Error', 'error': str(e)}), 500

@app.route('/api/user/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_user, user_id):
    # ZAFIYET 17: IDOR - No authorization check
    # Any authenticated user can update any other user's data!
    data = request.get_json()
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    # ZAFIYET 18: Mass assignment vulnerability
    # User can change their own role to admin!
    if 'username' in data:
        user.username = data['username']
    if 'email' in data:
        user.email = data['email']
    if 'role' in data:  # CRITICAL: No validation!
        user.role = data['role']
    if 'ssn' in data:
        user.ssn = data['ssn']
    
    db.session.commit()
    return jsonify({'message': 'User updated', 'user': user.to_dict()}), 200

@app.route('/api/accounts', methods=['GET'])
@token_required
def get_accounts(current_user):
    # ZAFIYET 19: Returns all accounts in system, not just user's accounts
    accounts = Account.query.all()
    return jsonify({
        'accounts': [acc.to_dict() for acc in accounts]
    }), 200

@app.route('/api/account/<int:account_id>', methods=['GET'])
@token_required
def get_account(current_user, account_id):
    # ZAFIYET 20: IDOR - No ownership verification
    # Any user can view any account's balance!
    account = Account.query.get(account_id)
    
    if not account:
        return jsonify({'message': 'Account not found'}), 404
    
    return jsonify(account.to_dict()), 200

@app.route('/api/transfer', methods=['POST'])
@token_required
def transfer(current_user):
    data = request.get_json()
    
    from_account_id = data.get('from_account_id')
    to_account_id = data.get('to_account_id')
    amount = data.get('amount')
    
    # ZAFIYET 21: BOLA - No check if from_account belongs to current_user
    # User can transfer money from ANY account!
    from_account = Account.query.get(from_account_id)
    to_account = Account.query.get(to_account_id)
    
    if not from_account or not to_account:
        return jsonify({'message': 'Account not found'}), 404
    
    # ZAFIYET 22: No input validation on amount (negative number attack)
    if amount <= 0:
        return jsonify({'message': 'Invalid amount'}), 400
    
    # ZAFIYET 23: Race condition - no transaction locking
    if from_account.balance < amount:
        return jsonify({'message': 'Insufficient funds'}), 400
    
    from_account.balance -= amount
    to_account.balance += amount
    
    transaction = Transaction(
        from_account_id=from_account_id,
        to_account_id=to_account_id,
        amount=amount,
        description=data.get('description', 'Transfer')
    )
    
    db.session.add(transaction)
    db.session.commit()
    
    return jsonify({
        'message': 'Transfer successful',
        'transaction': transaction.to_dict()
    }), 200

@app.route('/api/transactions', methods=['GET'])
@token_required
def get_transactions(current_user):
    # ZAFIYET 24: Returns ALL transactions, not just user's transactions
    transactions = Transaction.query.all()
    return jsonify({
        'transactions': [t.to_dict() for t in transactions]
    }), 200

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    # ZAFIYET 25: Admin endpoint with weak authorization
    users = User.query.all()
    return jsonify({
        'users': [u.to_dict() for u in users]
    }), 200

@app.route('/api/admin/promote/<int:user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    # Admin endpoint to promote user to admin
    user = User.query.get(user_id)
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user.role = 'admin'
    db.session.commit()
    
    return jsonify({'message': f'User {user.username} promoted to admin'}), 200

@app.route('/api/search', methods=['GET'])
@token_required
def search_users(current_user):
    # ZAFIYET 26: SQL Injection via search parameter
    search_term = request.args.get('q', '')
    
    try:
        conn = sqlite3.connect('instance/bank.db')
        cursor = conn.cursor()
        
        # CRITICAL SQL INJECTION
        query = f"SELECT * FROM users WHERE username LIKE '%{search_term}%' OR email LIKE '%{search_term}%'"
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        users = []
        for row in results:
            users.append({
                'id': row[0],
                'username': row[1],
                'email': row[2],
                'password': row[3],  # EXPOSED
                'ssn': row[5]  # EXPOSED
            })
        
        return jsonify({'results': users}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/debug/config', methods=['GET'])
def debug_config():
    # ZAFIYET 27: Debug endpoint exposed in production
    # ZAFIYET 28: Sensitive config data exposed
    return jsonify({
        'SECRET_KEY': app.config['SECRET_KEY'],
        'DATABASE_URI': app.config['SQLALCHEMY_DATABASE_URI'],
        'DEBUG': app.debug,
        'ENV': os.environ.copy()  # Environment variables exposed!
    }), 200

@app.route('/api/file/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    # ZAFIYET 29: Unrestricted file upload
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400
    
    file = request.files['file']
    
    # ZAFIYET 30: No file type validation
    # ZAFIYET 31: No file size limit
    # ZAFIYET 32: Dangerous file path handling
    filename = file.filename  # Could contain ../../../etc/passwd
    
    upload_path = os.path.join('uploads', filename)
    file.save(upload_path)
    
    return jsonify({
        'message': 'File uploaded',
        'path': upload_path
    }), 200

@app.route('/api/exec', methods=['POST'])
@admin_required
def execute_command():
    # ZAFIYET 33: CRITICAL - Command injection vulnerability
    data = request.get_json()
    command = data.get('command', '')
    
    # NEVER DO THIS IN PRODUCTION!
    import subprocess
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return jsonify({
            'output': result.decode('utf-8')
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =============================================================================
# INITIALIZATION
# =============================================================================

def init_db():
    """Initialize database with sample data"""
    with app.app_context():
        db.create_all()
        
        # Check if data already exists
        if User.query.first():
            return
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@bank.com',
            password=generate_password_hash('admin123'),
            full_name='System Administrator',
            ssn='123-45-6789',
            phone='555-0001',
            role='admin'
        )
        
        # Create regular users
        user1 = User(
            username='alice',
            email='alice@email.com',
            password=generate_password_hash('password123'),
            full_name='Alice Johnson',
            ssn='987-65-4321',
            phone='555-0002',
            role='user'
        )
        
        user2 = User(
            username='bob',
            email='bob@email.com',
            password=generate_password_hash('pass456'),
            full_name='Bob Smith',
            ssn='456-78-9012',
            phone='555-0003',
            role='user'
        )
        
        db.session.add_all([admin, user1, user2])
        db.session.commit()
        
        # Create accounts
        accounts = [
            Account(user_id=admin.id, account_number='ACC00000001', balance=100000.0, account_type='checking'),
            Account(user_id=user1.id, account_number='ACC00000002', balance=5000.0, account_type='checking'),
            Account(user_id=user1.id, account_number='ACC00000003', balance=10000.0, account_type='savings'),
            Account(user_id=user2.id, account_number='ACC00000004', balance=3000.0, account_type='checking'),
        ]
        
        db.session.add_all(accounts)
        db.session.commit()
        
        print("Database initialized with sample data!")
        print("Admin credentials: admin / admin123")
        print("User credentials: alice / password123, bob / pass456")


@app.route('/')
def index():
    """API Ana Sayfa"""
    return jsonify({
        'message': 'Welcome to Vulnerable Bank API',
        'version': '1.0',
        'warning': '⚠️ This API contains intentional vulnerabilities for educational purposes',
        'endpoints': {
            'authentication': [
                'POST /api/register',
                'POST /api/login'
            ],
            'users': [
                'GET /api/users',
                'GET /api/user/<user_id>',
                'PUT /api/user/<user_id>',
                'GET /api/search?q=<term>'
            ],
            'accounts': [
                'GET /api/accounts',
                'GET /api/account/<account_id>'
            ],
            'transactions': [
                'POST /api/transfer',
                'GET /api/transactions'
            ],
            'admin': [
                'GET /api/admin/users',
                'POST /api/admin/promote/<user_id>'
            ],
            'debug': [
                'GET /api/debug/config'
            ],
            'other': [
                'POST /api/file/upload',
                'POST /api/exec'
            ]
        },
        'test_credentials': {
            'admin': {'username': 'admin', 'password': 'admin123'},
            'user1': {'username': 'alice', 'password': 'password123'},
            'user2': {'username': 'bob', 'password': 'pass456'}
        },
        'documentation': 'See README.md for exploitation guide'
    }), 200

@app.route('/api')
def api_info():
    """API Bilgi Endpoint'i"""
    return jsonify({
        'status': 'online',
        'message': 'Vulnerable Bank API v1.0',
        'endpoints': '/api/...',
        'docs': 'http://localhost:5000/'
    }), 200

if __name__ == '__main__':
    init_db()
    # ZAFIYET 34: Debug mode enabled in production
    app.run(debug=True, host='0.0.0.0', port=5000)
"""
Advanced Web Application Challenge - XSS to RCE Chain
Category: Web Exploitation (Expert)
Difficulty: Expert
Points: 900

Description:
A modern web application with multiple layers of security.
Exploit XSS -> CSRF -> Deserialization -> RCE chain.

Flag: JCOECTF{adv4nc3d_xss_t0_rc3_ch41n_pwn3d_h4rd_2024}

Vulnerabilities:
1. DOM-based XSS with CSP bypass
2. CSRF on admin endpoints
3. Insecure deserialization in session handler
4. SSRF in internal API
5. Command injection in admin panel

Tech Stack:
- Flask + Jinja2
- Redis for sessions
- Pickle for serialization (vulnerable!)
- JWT with weak secret
- Internal API proxy
"""

from flask import Flask, request, render_template_string, session, redirect, url_for, jsonify, make_response
import pickle
import base64
import hashlib
import hmac
import subprocess
import requests
import redis
import jwt
import os
import re
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'weak_secret_key_2024'  # Vulnerability: Weak secret
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Redis connection for sessions
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=False)

# JWT Secret (same as Flask secret - bad practice)
JWT_SECRET = app.config['SECRET_KEY']

# Flag location
FLAG = "JCOECTF{adv4nc3d_xss_t0_rc3_ch41n_pwn3d_h4rd_2024}"

# Simulated user database
users_db = {
    'admin': {
        'password': hashlib.sha256(b'admin_super_secret_pass_2024').hexdigest(),
        'role': 'admin',
        'api_key': 'ADMIN_API_KEY_SECRET'
    },
    'user': {
        'password': hashlib.sha256(b'user123').hexdigest(),
        'role': 'user',
        'api_key': 'USER_API_KEY'
    }
}

# Content Security Policy (but with bypass opportunity)
CSP_HEADER = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'"

class UserSession:
    """Custom session class - uses pickle (vulnerable!)"""
    def __init__(self, username, role, timestamp):
        self.username = username
        self.role = role
        self.timestamp = timestamp
        self.preferences = {}
    
    def __reduce__(self):
        # Vulnerability: Allows arbitrary code execution during unpickling
        return (self.__class__, (self.username, self.role, self.timestamp))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            # Vulnerability: JWT with weak secret
            payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.current_user = payload['username']
            request.user_role = payload['role']
        except:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.user_role != 'admin':
            return "Access Denied", 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Enterprise Portal</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
            .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .nav { margin-bottom: 20px; }
            .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
            input { padding: 8px; margin: 5px 0; width: 200px; }
            button { padding: 8px 16px; background: #007bff; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Secure Enterprise Portal</h1>
            <div class="nav">
                <a href="/login">Login</a>
                <a href="/search">Search</a>
                <a href="/profile">Profile</a>
                <a href="/admin">Admin Panel</a>
            </div>
            <p>Welcome to our secure web application!</p>
            <p>This system implements multiple security layers:</p>
            <ul>
                <li>Content Security Policy</li>
                <li>JWT Authentication</li>
                <li>CSRF Protection</li>
                <li>Input Validation</li>
                <li>Secure Session Management</li>
            </ul>
        </div>
    </body>
    </html>
    ''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        if username in users_db and users_db[username]['password'] == password_hash:
            # Create JWT token
            token = jwt.encode({
                'username': username,
                'role': users_db[username]['role'],
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, JWT_SECRET, algorithm='HS256')
            
            # Create session object (pickled - vulnerable!)
            user_session = UserSession(username, users_db[username]['role'], datetime.utcnow().isoformat())
            session_data = base64.b64encode(pickle.dumps(user_session)).decode()
            
            # Store in Redis
            redis_client.setex(f'session:{username}', 3600, session_data)
            
            session['token'] = token
            session['username'] = username
            
            return redirect(url_for('dashboard'))
        
        return "Invalid credentials", 401
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f0f0f0; }
            .container { background: white; padding: 30px; border-radius: 8px; max-width: 400px; margin: 0 auto; }
            input { width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Login</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            <p>Test Account: user / user123</p>
        </div>
    </body>
    </html>
    ''')

@app.route('/dashboard')
@login_required
def dashboard():
    username = request.current_user
    
    # Retrieve session from Redis (vulnerable to deserialization attacks)
    session_data = redis_client.get(f'session:{username}')
    if session_data:
        try:
            # Vulnerability: Unpickling user-controlled data
            user_session = pickle.loads(base64.b64decode(session_data))
            role = user_session.role
        except:
            role = 'unknown'
    else:
        role = 'unknown'
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Dashboard</title></head>
    <body>
        <h1>Dashboard</h1>
        <p>Welcome, {{ username }}!</p>
        <p>Role: {{ role }}</p>
        <a href="/logout">Logout</a>
    </body>
    </html>
    ''', username=username, role=role)

@app.route('/search')
def search():
    # Vulnerability: DOM-based XSS
    query = request.args.get('q', '')
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Search</title>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    </head>
    <body>
        <h1>Search</h1>
        <form>
            <input type="text" name="q" id="searchInput" placeholder="Search...">
            <button type="submit">Search</button>
        </form>
        <div id="results"></div>
        
        <script>
            // Vulnerability: DOM-based XSS
            const urlParams = new URLSearchParams(window.location.search);
            const query = urlParams.get('q');
            if (query) {
                // Unsafe: Directly inserting user input into DOM
                document.getElementById('results').innerHTML = '<p>Search results for: ' + query + '</p>';
            }
        </script>
    </body>
    </html>
    ''')

@app.route('/profile')
@login_required
def profile():
    username = request.current_user
    
    # Vulnerability: CSRF - no CSRF token validation
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Profile</title></head>
    <body>
        <h1>Profile Settings</h1>
        <form action="/api/update_profile" method="POST">
            <input type="text" name="email" placeholder="Email">
            <input type="text" name="preferences" placeholder="Preferences (JSON)">
            <button type="submit">Update</button>
        </form>
    </body>
    </html>
    ''')

@app.route('/api/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = request.current_user
    
    # Vulnerability: No CSRF protection
    # Vulnerability: Insecure deserialization
    preferences = request.form.get('preferences', '{}')
    
    # Get session
    session_data = redis_client.get(f'session:{username}')
    if session_data:
        user_session = pickle.loads(base64.b64decode(session_data))
        
        # Vulnerability: Unpickling user-provided data
        try:
            user_session.preferences = pickle.loads(base64.b64decode(preferences))
        except:
            user_session.preferences = {}
        
        # Save back to Redis
        new_session_data = base64.b64encode(pickle.dumps(user_session)).decode()
        redis_client.setex(f'session:{username}', 3600, new_session_data)
    
    return jsonify({'status': 'success'})

@app.route('/admin')
@login_required
@admin_required
def admin():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head><title>Admin Panel</title></head>
    <body>
        <h1>🔑 Admin Panel</h1>
        <h2>System Status</h2>
        <form action="/api/admin/check_service" method="POST">
            <input type="text" name="service_url" placeholder="Service URL to check">
            <button type="submit">Check Status</button>
        </form>
        
        <h2>Execute Command</h2>
        <form action="/api/admin/execute" method="POST">
            <input type="text" name="command" placeholder="Command">
            <button type="submit">Execute</button>
        </form>
        
        <h2>Flag</h2>
        <p>Flag is stored at: /tmp/flag.txt</p>
    </body>
    </html>
    ''')

@app.route('/api/admin/check_service', methods=['POST'])
@login_required
@admin_required
def check_service():
    # Vulnerability: SSRF
    service_url = request.form.get('service_url', '')
    
    try:
        # No URL validation - can access internal services
        response = requests.get(service_url, timeout=5)
        return jsonify({
            'status': 'success',
            'code': response.status_code,
            'content': response.text[:500]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/admin/execute', methods=['POST'])
@login_required
@admin_required
def execute_command():
    # Vulnerability: Command Injection
    command = request.form.get('command', '')
    
    # Weak validation
    if 'rm' in command or 'del' in command:
        return jsonify({'status': 'error', 'message': 'Dangerous command detected'})
    
    try:
        # Vulnerability: Direct command execution
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return jsonify({
            'status': 'success',
            'output': result.decode()
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/api/internal/system_info')
def internal_api():
    # Internal API - should not be accessible externally
    # But can be reached via SSRF
    api_key = request.headers.get('X-API-Key')
    
    if api_key == 'ADMIN_API_KEY_SECRET':
        return jsonify({
            'system': 'production',
            'flag_location': '/tmp/flag.txt',
            'admin_token': jwt.encode({'username': 'admin', 'role': 'admin'}, JWT_SECRET, algorithm='HS256')
        })
    
    return jsonify({'error': 'Invalid API key'}), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = CSP_HEADER
    # Vulnerability: X-Frame-Options not set (allows framing for CSRF)
    return response

if __name__ == '__main__':
    # Create flag file
    with open('/tmp/flag.txt', 'w') as f:
        f.write(FLAG)
    os.chmod('/tmp/flag.txt', 0o600)
    
    print("[*] Starting Advanced Web Challenge")
    print("[*] Flag written to /tmp/flag.txt")
    print("[*] Admin credentials: admin / admin_super_secret_pass_2024")
    print("[*] User credentials: user / user123")
    
    app.run(host='0.0.0.0', port=8888, debug=False)

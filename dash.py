from dotenv import load_dotenv
import re
import hashlib
from flask import flash
import secrets
from flask import Flask, send_file, render_template, request, redirect, url_for, session, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
import pandas as pd
import boto3
import time
import os
from datetime import datetime
from pytz import timezone
import mysql.connector
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from config import Config
from flask import jsonify
import json

# Load environment variables
load_dotenv()

# Set the data directory
DATA_DIR = os.path.join(os.getcwd(), "data")
os.makedirs(DATA_DIR, exist_ok=True)
DATA_FILE = os.path.join(DATA_DIR, 'user_access_data.csv')
LOG_FILE = os.path.join(DATA_DIR, 'user_access_log.txt')

# MySQL Configuration
MYSQL_HOST = Config.MYSQL_HOST
MYSQL_USER = Config.MYSQL_USER
MYSQL_PASSWORD = Config.MYSQL_PASSWORD

# Environment variables for APIs
ZOHO_PEOPLE_TOKEN = os.getenv("ZOHO_PEOPLE_TOKEN")
JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_TOKEN = os.getenv("JIRA_TOKEN")
CONFLUENCE_EMAIL = os.getenv("CONFLUENCE_EMAIL")
CONFLUENCE_TOKEN = os.getenv("CONFLUENCE_TOKEN")
APPSFLYER_TOKEN = os.getenv("APPSFLYER_TOKEN")

# Load API keys from environment with error handling
def load_api_keys():
    try:
        api_keys_json = os.getenv("DASH_API_KEYS", "{}").strip()
        if api_keys_json.startswith('"') and api_keys_json.endswith('"'):
            api_keys_json = api_keys_json[1:-1]
        
        keys_dict = json.loads(api_keys_json)
        
        api_keys = {}
        for name, key in keys_dict.items():
            api_keys[name] = {
                'original': key.strip(),
                'hashed': None
            }
        return api_keys
    except Exception as e:
        print(f"ERROR loading API keys: {str(e)}")
        return {}

DASH_API_KEYS = load_api_keys()
print(f"Loaded API keys: {[name for name in DASH_API_KEYS]}")

def validate_api_key(api_key):
    if not api_key:
        return False
        
    api_key = api_key.strip()
    
    for key_data in DASH_API_KEYS.values():
        if api_key == key_data['original']:
            return True
    return False
    
# IP Whitelist
ALLOWED_IPS = {
    '127.0.0.1',
    '192.168.1.1',
    '172.0.12.123',
    '172.0.13.30'
}

# Define API-based platforms and their endpoints
API_BASED_PLATFORMS = {
    "AppsFlyer": "https://hq1.appsflyer.com/api/user-management/v1.0/users",
    "Zoho": "https://people.zoho.in/people/api/forms/employee/getRecords",
    "Confluence": "https://octro.atlassian.net/wiki/rest/api/group/confluence-users/member",
    "JIRA": "https://octro.atlassian.net/rest/api/3/users/search",
}

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

# IP Restriction Decorator
def ip_restricted(f):
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        if request.headers.getlist("X-Forwarded-For"):
            client_ip = request.headers.getlist("X-Forwarded-For")[0].split(',')[0].strip()
        
        api_key = request.headers.get('X-API-KEY', '').strip()
        
        if not api_key:
            return jsonify({
                "message": "API key required",
                "status": "failed",
                "hint": "Include a valid X-API-KEY header"
            }), 403
        
        if not validate_api_key(api_key):
            return jsonify({
                "message": "Invalid API key",
                "status": "failed",
                "hint": "Check your API key or contact admin"
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

@app.route('/api/debug/keys', methods=['GET'])
def debug_keys():
    return jsonify({
        "loaded_keys": {name: data['original'] for name, data in DASH_API_KEYS.items()},
        "env_value": os.getenv("DASH_API_KEYS"),
        "note": "Keys are stored hashed for security"
    })

@app.route('/api/test_auth', methods=['POST'])
def test_auth():
    api_key = request.headers.get('X-API-KEY', '').strip()
    is_valid = validate_api_key(api_key)
    
    return jsonify({
        "api_key_provided": api_key,
        "is_valid": is_valid,
        "client_ip": request.remote_addr,
        "ip_allowed": request.remote_addr in ALLOWED_IPS
    })

@app.route('/api/debug/verify_key', methods=['POST'])
def verify_key():
    data = request.get_json()
    api_key = data.get('api_key', '').strip()
    is_valid = api_key in DASH_API_KEYS.values()
    return jsonify({
        "key_provided": api_key,
        "is_valid": is_valid,
        "matched_key": next((k for k, v in DASH_API_KEYS.items() if v == api_key), None)
    })

@login_manager.user_loader
def load_user(user_id):
    return User(user_id, session.get('email'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login/callback')
def callback():
    token = request.args.get('token')
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), app.config['GOOGLE_CLIENT_ID'])
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')
        user = User(idinfo['sub'], idinfo['email'])
        login_user(user)
        session['email'] = idinfo['email']
        return redirect(url_for('dashboard'))
    except ValueError:
        abort(403)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('email', None)
    return redirect(url_for('login'))

def log_user_access(email, platform, action):
    try:
        timestamp = datetime.now(timezone('Asia/Kolkata')).strftime('%Y-%m-%d %H:%M:%S %Z')
        log_entry = f"{timestamp} - {email} - {platform} - {action}\n"

        with open(LOG_FILE, 'a') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Failed to write to log file: {e}")

def get_databases():
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD
        )
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES")
        all_databases = [db[0] for db in cursor.fetchall()]
        
        system_dbs = {'information_schema', 'mysql', 'performance_schema', 'sys'}
        databases = [db for db in all_databases if db not in system_dbs]
        
        cursor.close()
        conn.close()
        return sorted(databases)
    except Exception as e:
        print(f"MySQL fetch failed: {e}")
        return []

def get_roles():
    try:
        roles = set()
        databases = get_databases()

        for db in databases:
            try:
                conn = mysql.connector.connect(
                    host=MYSQL_HOST,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    database=db
                )
                cursor = conn.cursor()
                
                cursor.execute(f"SHOW TABLES LIKE 'Platform'")
                if not cursor.fetchone():
                    continue
                
                cursor.execute("SELECT DISTINCT `Role/Permission` FROM Platform")
                db_roles = [role[0] for role in cursor.fetchall() if role[0]]
                roles.update(db_roles)
                cursor.close()
                conn.close()
                
            except mysql.connector.Error as err:
                print(f"Error accessing database {db}: {err}")
                continue

        return sorted(roles)
    except Exception as e:
        print(f"Failed to fetch roles: {e}")
        return []

def fetch_mysql_platform_data():
    try:
        platforms = get_databases()
        all_users = []
        
        for db in platforms:
            try:
                conn = mysql.connector.connect(
                    host=MYSQL_HOST,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    database=db
                )
                cursor = conn.cursor(dictionary=True)
                
                cursor.execute(f"SHOW TABLES LIKE 'Platform'")
                if not cursor.fetchone():
                    continue
                
                cursor.execute("SELECT * FROM Platform")
                for row in cursor.fetchall():
                    all_users.append({
                        "Platform": db,
                        "URL": row.get('URL', ''),
                        "Username / Email": row.get('Username/Email', ''),
                        "Role / Permission": row.get('Role/Permission', ''),
                        "Active/Inactive": row.get('Active/Inactive', ''),
                        "Created Time": row.get('created_time', ''),
                        "Updated Time": row.get('last_login_time', ''),
                        "Login Count": row.get('login_count', 0),
                        "IsBlocked": row.get('Active/Inactive', '') == 'Blocked'
                    })
                cursor.close()
                conn.close()
                
            except mysql.connector.Error as err:
                print(f"Error accessing database {db}: {err}")
                continue
                
        return all_users
    except Exception as e:
        print(f"MySQL data fetch failed: {e}")
        return []

@app.route('/block_user', methods=['POST'])
@login_required
def block_user():
    try:
        platform = request.form.get('platform')
        username = request.form.get('username')
        
        if not platform or not username:
            flash('Missing required fields!', 'error')
            return redirect(url_for('dashboard'))
            
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=platform
        )
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE Platform 
            SET `Active/Inactive` = 'Blocked',
                last_login_time = NOW()
            WHERE `Username/Email` = %s
        """, (username,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        log_user_access(username, platform, "blocked")
        flash(f'User {username} blocked on {platform} successfully!', 'success')
        return redirect(url_for('dashboard', platform=platform))
        
    except Exception as e:
        flash(f'Failed to block user: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/unblock_user', methods=['POST'])
@login_required
def unblock_user():
    try:
        platform = request.form.get('platform')
        username = request.form.get('username')
        
        if not platform or not username:
            flash('Missing required fields!', 'error')
            return redirect(url_for('dashboard'))
            
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=platform
        )
        cursor = conn.cursor()
        
        cursor.execute("""
            UPDATE Platform 
            SET `Active/Inactive` = 'Active',
                last_login_time = NOW()
            WHERE `Username/Email` = %s
        """, (username,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        log_user_access(username, platform, "unblocked")
        flash(f'User {username} unblocked on {platform} successfully!', 'success')
        return redirect(url_for('dashboard', platform=platform))
        
    except Exception as e:
        flash(f'Failed to unblock user: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/add_entry', methods=['POST'])
@login_required
def add_entry():
    try:
        platform = request.form.get('platform')
        url = request.form.get('url')
        username = request.form.get('username')
        role = request.form.get('role')
        status = request.form.get('last_activity', 'Active')

        if platform and url and username and role:
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=platform
            )
            cursor = conn.cursor()
            query = """
                INSERT INTO Platform (
                    URL, 
                    `Username/Email`, 
                    `Role/Permission`, 
                    `Active/Inactive`, 
                    created_time, 
                    last_login_time,
                    login_count
                ) VALUES (%s, %s, %s, %s, NOW(), NOW(), 0)
            """
            cursor.execute(query, (url, username, role, status))
            conn.commit()
            cursor.close()
            conn.close()
            
            log_user_access(username, platform, "added manually")
            flash('Entry added successfully!', 'success')
        else:
            flash('Missing required fields!', 'error')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'Failed to add record: {e}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/add_platform', methods=['POST'])
@login_required
def add_platform():
    try:
        platform_name = request.form.get('platform_name', '').strip()
        platform_url = request.form.get('platform_url', '').strip()

        if not platform_name or not platform_url:
            flash('Both platform name and URL are required', 'error')
            return redirect(url_for('dashboard'))

        if not re.match(r'^[a-zA-Z0-9_]+$', platform_name):
            flash('Platform name can only contain letters, numbers and underscores', 'error')
            return redirect(url_for('dashboard'))

        conn = None
        cursor = None
        try:
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD
            )
            cursor = conn.cursor()
            
            cursor.execute("SHOW DATABASES")
            databases = [db[0] for db in cursor.fetchall()]
            
            if platform_name in databases:
                flash(f'Platform {platform_name} already exists', 'error')
                return redirect(url_for('dashboard'))

            cursor.execute(f"CREATE DATABASE `{platform_name}`")
            
            cursor.execute(f"""
                CREATE TABLE `{platform_name}`.Platform (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    URL VARCHAR(255),
                    `Username/Email` VARCHAR(255),
                    `Role/Permission` VARCHAR(255),
                    `Active/Inactive` ENUM('Active', 'Inactive', 'Blocked') DEFAULT 'Active',
                    created_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login_time TIMESTAMP NULL,
                    login_count INT DEFAULT 0
                )
            """)
            
            flash(f'Platform {platform_name} added successfully!', 'success')
            time.sleep(1)
            return redirect(url_for('dashboard', platform=platform_name))
            
        except mysql.connector.Error as err:
            flash(f'Database error: {err}', 'error')
            return redirect(url_for('dashboard'))
            
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
                
    except Exception as e:
        flash(f'Failed to add platform: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/api_keys', methods=['GET', 'POST'])
@login_required
def api_keys():
    global DASH_API_KEYS
    
    api_keys = {}
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if line.startswith('DASH_API_KEYS='):
                    try:
                        json_str = line.split('=', 1)[1].strip().strip('"\'')
                        api_keys = json.loads(json_str)
                    except json.JSONDecodeError as e:
                        print(f"Error decoding API keys: {e}")
                        api_keys = {}
                    break

    if request.method == 'POST':
        action = request.form.get('action')
        platform_name = request.form.get('platform_name', '').strip()
        
        if action == 'generate':
            if not platform_name:
                flash('Platform name is required!', 'error')
            else:
                new_token = secrets.token_hex(32)
                api_keys[platform_name] = new_token
                update_env_file(env_path, api_keys)
                load_dotenv(env_path, override=True)
                DASH_API_KEYS = load_api_keys()
                flash(f'Token generated for platform: {platform_name}', 'success')
                return redirect(url_for('api_keys'))
        
        elif action == 'revoke':
            if platform_name in api_keys:
                del api_keys[platform_name]
                update_env_file(env_path, api_keys)
                load_dotenv(env_path, override=True)
                DASH_API_KEYS = load_api_keys()
                flash(f'Token revoked for platform: {platform_name}', 'success')
                return redirect(url_for('api_keys'))
            else:
                flash('Platform not found!', 'error')

    return render_template('api_keys.html', api_keys=api_keys)

def update_env_file(env_path, api_keys):
    env_lines = []
    key_updated = False

    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                if line.startswith('DASH_API_KEYS='):
                    env_lines.append(f'DASH_API_KEYS={json.dumps(api_keys)}\n')
                    key_updated = True
                else:
                    env_lines.append(line)
    
    if not key_updated:
        env_lines.append(f'DASH_API_KEYS={json.dumps(api_keys)}\n')

    with open(env_path, 'w') as f:
        f.writelines(env_lines)
    
    load_dotenv(env_path, override=True)

def fetch_all_users():
    all_users = []
    all_users.extend(fetch_mysql_platform_data())
    return all_users

@app.route('/', methods=['GET'])
@login_required
def dashboard():
    selected_platform = request.args.get("platform", "All")
    platforms = get_databases()
    all_users = fetch_all_users()
    df = pd.DataFrame(all_users)
    df.to_csv(DATA_FILE, index=False)

    urls = set()
    for user in all_users:
        urls.add(user.get("URL", ""))

    roles = get_roles()

    if selected_platform != "All":
        filtered_users = [u for u in all_users if u.get("Platform") == selected_platform]
    else:
        filtered_users = all_users

    return render_template("dashboard.html",
                         users=filtered_users,
                         platforms=platforms,
                         selected_platform=selected_platform,
                         urls=urls,
                         roles=roles)


@app.route('/api/login_user', methods=['POST'])
@ip_restricted
def login_user_api():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['platform', 'url', 'username', 'role', 'status']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    "status": "error",
                    "message": f"Missing required field: {field}"
                }), 400
        
        # Connect to MySQL
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=data['platform'].lower()
        )
        cursor = conn.cursor(dictionary=True)
        
        # Check if user exists
        cursor.execute("""
            SELECT * FROM Platform 
            WHERE `Username/Email` = %s
        """, (data['username'],))
        
        user = cursor.fetchone()
        
        if user:
            # Update existing user
            cursor.execute("""
                UPDATE Platform 
                SET 
                    URL = %s,
                    `Role/Permission` = %s,
                    `Active/Inactive` = %s,
                    last_login_time = NOW(),
                    login_count = login_count + 1
                WHERE `Username/Email` = %s
            """, (
                data['url'],
                data['role'],
                data['status'],
                data['username']
            ))
        else:
            # Create new user
            cursor.execute("""
                INSERT INTO Platform (
                    URL, 
                    `Username/Email`, 
                    `Role/Permission`, 
                    `Active/Inactive`, 
                    created_time, 
                    last_login_time,
                    login_count
                ) VALUES (%s, %s, %s, %s, NOW(), NOW(), 1)
            """, (
                data['url'],
                data['username'],
                data['role'],
                data['status']
            ))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        log_user_access(data['username'], data['platform'], "api login")
        
        return jsonify({
            "status": "success",
            "message": "User logged successfully",
            "user": {
                "platform": data['platform'],
                "username": data['username'],
                "role": data['role'],
                "status": data['status']
            }
        })
        
    except mysql.connector.Error as err:
        return jsonify({
            "status": "error",
            "message": f"Database error: {err}"
        }), 500
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Unexpected error: {str(e)}"
        }), 500


@app.route('/download_csv')
@login_required
def download_csv():
    return send_file(
        DATA_FILE,
        as_attachment=True,
        download_name="user_access_data.csv",
        mimetype="text/csv"
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

# alert_script.py
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import mysql.connector
from dotenv import load_dotenv
from config import Config

# Load environment variables
load_dotenv()

# Email configuration
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
ALERT_RECIPIENTS = os.getenv('ALERT_RECIPIENTS', '').split(',')
FROZEN_EMAILS = [email.strip().lower() for email in os.getenv('FROZEN_EMAILS', '').split(',') if email.strip()]

# MySQL Configuration from config.py
MYSQL_HOST = Config.MYSQL_HOST
MYSQL_USER = Config.MYSQL_USER
MYSQL_PASSWORD = Config.MYSQL_PASSWORD

def get_databases():
    """Fetch all non-system databases from MySQL"""
    try:
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD
        )
        cursor = conn.cursor()
        cursor.execute("SHOW DATABASES")
        all_databases = [db[0] for db in cursor.fetchall()]
        
        # Exclude system databases
        system_dbs = {'information_schema', 'mysql', 'performance_schema', 'sys'}
        databases = [db for db in all_databases if db not in system_dbs]
        
        cursor.close()
        conn.close()
        return sorted(databases)
    except Exception as e:
        print(f"Error fetching databases: {e}")
        return []

def get_inactive_users(threshold_days=1):
    """Get users who haven't logged in for more than threshold_days"""
    inactive_users = []
    threshold_date = datetime.now() - timedelta(days=threshold_days)
    
    databases = get_databases()
    
    for db in databases:
        try:
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=db
            )
            cursor = conn.cursor(dictionary=True)
            
            # Check if Platform table exists
            cursor.execute(f"SHOW TABLES LIKE 'Platform'")
            if not cursor.fetchone():
                continue
                
            # Query for inactive users
            query = """
                SELECT 
                    `Username/Email` as username,
                    `Role/Permission` as role,
                    `Active/Inactive` as status,
                    last_login_time,
                    DATEDIFF(NOW(), last_login_time) as days_inactive
                FROM Platform
                WHERE last_login_time < %s
                AND `Active/Inactive` != 'Blocked'
                ORDER BY days_inactive DESC
            """
            cursor.execute(query, (threshold_date,))
            
            for user in cursor.fetchall():
                # Skip frozen users (case-insensitive comparison)
                if user['username'].lower() in FROZEN_EMAILS:
                    print(f"Skipping frozen user: {user['username']}")
                    continue
                    
                inactive_users.append({
                    'platform': db,
                    'username': user['username'],
                    'role': user['role'],
                    'status': user['status'],
                    'last_login': user['last_login_time'].strftime('%Y-%m-%d') if user['last_login_time'] else 'Never',
                    'days_inactive': user['days_inactive']
                })
                
            cursor.close()
            conn.close()
            
        except mysql.connector.Error as err:
            print(f"Error accessing database {db}: {err}")
            continue
            
    return inactive_users

def get_blocked_users():
    """Get all blocked users across all platforms"""
    blocked_users = []
    
    databases = get_databases()
    
    for db in databases:
        try:
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=db
            )
            cursor = conn.cursor(dictionary=True)
            
            # Check if Platform table exists
            cursor.execute(f"SHOW TABLES LIKE 'Platform'")
            if not cursor.fetchone():
                continue
                
            # Query for blocked users
            query = """
                SELECT 
                    `Username/Email` as username,
                    `Role/Permission` as role,
                    `Active/Inactive` as status,
                    last_login_time,
                    created_time,
                    DATEDIFF(NOW(), last_login_time) as days_inactive
                FROM Platform
                WHERE `Active/Inactive` = 'Blocked'
                ORDER BY last_login_time DESC
            """
            cursor.execute(query)
            
            for user in cursor.fetchall():
                blocked_users.append({
                    'platform': db,
                    'username': user['username'],
                    'role': user['role'],
                    'status': user['status'],
                    'last_login': user['last_login_time'].strftime('%Y-%m-%d') if user['last_login_time'] else 'Never',
                    'created_date': user['created_time'].strftime('%Y-%m-%d') if user['created_time'] else 'Unknown',
                    'days_inactive': user['days_inactive']
                })
                
            cursor.close()
            conn.close()
            
        except mysql.connector.Error as err:
            print(f"Error accessing database {db}: {err}")
            continue
            
    return blocked_users

def send_email_alert(inactive_users, blocked_users):
    """Send email alert with inactive and blocked users report"""
    if not EMAIL_USER or not EMAIL_PASSWORD:
        print("Email credentials not configured. Skipping email alert.")
        return
        
    if not ALERT_RECIPIENTS:
        print("No recipients configured. Skipping email alert.")
        return
        
    # Create email content
    subject = "User Access Dashboard - Security Report"
    
    # HTML content
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            h1 {{ color: #2c3e50; }}
            h2 {{ color: #2c3e50; margin-top: 30px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #2c3e50; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .warning {{ color: #d35400; font-weight: bold; }}
            .danger {{ color: #c0392b; font-weight: bold; }}
            .frozen {{ color: #7f8c8d; font-style: italic; }}
            .summary {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        </style>
    </head>
    <body>
        <h1>User Access Security Report</h1>
        
        <div class="summary">
            <h3>Summary</h3>
            <p><strong>Inactive Users (>90 days):</strong> {len(inactive_users)}</p>
            <p><strong>Blocked Users:</strong> {len(blocked_users)}</p>
            <p><strong>Frozen Accounts (excluded):</strong> {len(FROZEN_EMAILS)}</p>
        </div>
    """
    
    # Inactive Users Section
    if inactive_users:
        html += """
            <h2>Inactive Users (90+ days without activity)</h2>
            <table>
                <tr>
                    <th>Platform</th>
                    <th>Username/Email</th>
                    <th>Role</th>
                    <th>Status</th>
                    <th>Last Login</th>
                    <th>Days Inactive</th>
                </tr>
        """
        
        for user in inactive_users:
            html += f"""
                <tr>
                    <td>{user['platform']}</td>
                    <td>{user['username']}</td>
                    <td>{user['role']}</td>
                    <td>{user['status']}</td>
                    <td>{user['last_login']}</td>
                    <td class="warning">{user['days_inactive']}</td>
                </tr>
            """
        
        html += "</table>"
    else:
        html += "<p>No inactive users found (last login > 90 days ago).</p>"
    
    # Blocked Users Section
    if blocked_users:
        html += """
            <h2>Blocked Users</h2>
            <table>
                <tr>
                    <th>Platform</th>
                    <th>Username/Email</th>
                    <th>Role</th>
                    <th>Account Created</th>
                    <th>Last Login</th>
                    <th>Days Inactive</th>
                </tr>
        """
        
        for user in blocked_users:
            html += f"""
                <tr>
                    <td>{user['platform']}</td>
                    <td class="danger">{user['username']}</td>
                    <td>{user['role']}</td>
                    <td>{user['created_date']}</td>
                    <td>{user['last_login']}</td>
                    <td class="danger">{user['days_inactive']}</td>
                </tr>
            """
        
        html += "</table>"
    else:
        html += "<p>No blocked users found.</p>"
    
    # Add frozen users section
    if FROZEN_EMAILS:
        html += """
            <h2>Frozen Users (Excluded from Alerts)</h2>
            <ul>
        """
        for email in sorted(FROZEN_EMAILS):
            html += f"<li>{email}</li>"
        html += "</ul>"
    
    html += """
        <p>Please review these accounts and take appropriate action if needed.</p>
        <p>This is an automated message from User Access Dashboard.</p>
    </body>
    </html>
    """
    
    # Create message
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = ", ".join(ALERT_RECIPIENTS)
    msg['Subject'] = subject
    
    # Attach HTML content
    msg.attach(MIMEText(html, 'html'))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USER, ALERT_RECIPIENTS, msg.as_string())
        print("Email alert sent successfully!")
    except Exception as e:
        print(f"Failed to send email alert: {e}")

def generate_report():
    """Generate and send the security report"""
    print("Generating security report...")
    print(f"Frozen emails: {FROZEN_EMAILS}")
    
    inactive_users = get_inactive_users()
    blocked_users = get_blocked_users()
    
    if not inactive_users and not blocked_users:
        print("No inactive or blocked users found.")
        return
        
    print(f"Found {len(inactive_users)} inactive users and {len(blocked_users)} blocked users (excluding {len(FROZEN_EMAILS)} frozen accounts).")
    
    # Print report to console
    print("\nSecurity Report:")
    print("=" * 120)
    print("INACTIVE USERS:")
    print("=" * 120)
    print(f"{'Platform':<20} {'Username':<30} {'Role':<20} {'Status':<10} {'Last Login':<15} {'Days':>5}")
    print("-" * 120)
    
    for user in inactive_users:
        print(f"{user['platform']:<20} {user['username']:<30} {user['role']:<20} {user['status']:<10} {user['last_login']:<15} {user['days_inactive']:>5}")
    
    print("\nBLOCKED USERS:")
    print("=" * 120)
    print(f"{'Platform':<20} {'Username':<30} {'Role':<20} {'Created':<15} {'Last Login':<15} {'Days':>5}")
    print("-" * 120)
    
    for user in blocked_users:
        print(f"{user['platform']:<20} {user['username']:<30} {user['role']:<20} {user['created_date']:<15} {user['last_login']:<15} {user['days_inactive']:>5}")
    
    # Send email alert
    send_email_alert(inactive_users, blocked_users)

if __name__ == "__main__":
    generate_report()

from flask import Flask, render_template_string, session, request, jsonify
from helpers import generate_public_ip, generate_user_agent
from datetime import datetime
import sqlite3
import time

app = Flask(__name__)
app.secret_key = "this is a local test :)"

USERS = {
    'admin': 'adminP@ssw0rd123',
    'user1': 'user1P@ssw0rd123',
    'user2': 'user2P@ssw0rd123'
}

DB_FILE = "auth_logs.db"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            user_agent TEXT,
            success INTEGER,
            failed_count INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

def save_log(entry):
    conn = get_db()
    conn.execute(
        """INSERT INTO auth_logs
        (timestamp, ip, user_agent, success, failed_count) 
        VALUES (?,?,?,?,?)
        """, 
        (
            entry['timestamp'],
            entry['ip'],
            entry['user_agent'],
            int(entry['success']),
            entry.get('failed_count')
        )
    )
    conn.commit()
    conn.close()

def get_logs():
    conn = get_db()
    logs = conn.execute("""
        SELECT * FROM auth_logs
        ORDER BY id DESC
    """).fetchall()
    conn.close()
    return logs

def get_failed_attempts_count(ip):
    conn = get_db()
    failed_count = conn.execute(
        """
            SELECT MAX(failed_count)
            FROM auth_logs
            WHERE ip = ?
        """, (ip,)
    ).fetchone()
    conn.close()

    return failed_count[0] if failed_count[0] is not None else 0

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'current_ip' not in session:
        session['current_ip'] = generate_public_ip()
    
    if 'current_user_agent' not in session:
        session['current_user_agent'] = generate_user_agent()

    ip = session['current_ip']
    user_agent = session['current_user_agent']

    if request.method == 'POST':
        ip = session['current_ip']
        user_agent = session['current_user_agent']

        username = request.form.get('username')
        password = request.form.get('password')

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'user_agent': user_agent,
            'success': False
        }

        if username in USERS and USERS[username] == password:
            log_entry['success'] = True
        else:
            last_failed = get_failed_attempts_count(ip)
            log_entry['failed_count'] = last_failed + 1

        save_log(log_entry)

        return render_template_string("""
        <html>
            <style>
                body { font-family: 'Roboto', Arial, sans-serif; }
            </style>
            <body>
                <h1>Test App</h1>
                <p>IP: {{ ip }}</p>
                <p>User-Agent: {{ user_agent }}</p>
                <p>Failed attempts from this IP: {{ failed_count }}</p>
                <a href="/">Try again</a>
            </body>                  
        </html>
        """, failed_count=log_entry['failed_count'], ip=ip, user_agent=user_agent)

    return render_template_string("""
    <html>
        <style>
            body { font-family: 'Roboto', Arial, sans-serif; }
        </style>
        <body>
                                  
            <p>
                <strong>Current IP</strong>: 
                <span id="current-ip">
                    {{ ip }}
                </span>
            </p>
            <p>
                <strong>Current User-Agent</strong>: 
                <span id="current-ua">
                    {{ user_agent }}
                </span>
            </p>
            <button onClick="changeSource()">Change source</button>
                                  

            <p>
                <strong>Available credentials</strong>:
            </p>
            {% for username, password in USERS.items() %}
                <p>{{ username }}: {{ password }}</p>
            {% endfor %}
                                  
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                                  
                <button type="submit">Login</button>            
            </form>
                                  
            <button onClick="startAttack()">Start Attack</button>
            <button onClick="clearLogs()">Clear Logs</button>
            
            <script>
                function changeSource() {
                    fetch('/api/change-source')
                        .then(response=>response.json())
                        .then(data => {
                            document.getElementById('current-ip').textContent = data.new_ip
                            document.getElementById('current-ua').textContent = data.new_ua
                                    
                            fetch('/api/set-source', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'          
                                },
                                body: JSON.stringify({
                                    ip: data.new_ip,
                                    user_agent: data.new_ua   
                                })                   
                            })
                        })
                        .catch(error => {
                            console.error('Error:', error)
                    })
                }
                                  
                function startAttack() {
                    fetch('/api/start-attack')
                        .then(response=>response.json())
                        .catch(error => {
                            console.error('Error:', error)              
                        })    
                }
                                  
                function clearLogs() {
                    fetch('/api/clear-logs', { method: 'POST' })
                        .then(() => alert('Logs cleared successfully'));
                }     
           
                }
            </script>
                                  
        </body>
    </html>
    """, USERS=USERS, ip=ip, user_agent=user_agent)

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    conn = get_db()
    conn.execute("DELETE FROM auth_logs")
    conn.commit()
    conn.close()

    return jsonify({'status': 'logs cleared'})

@app.route('/logs')
def show_logs():
    logs = get_logs()
    logs_html = '<h2>logs</h2>'
    for log in logs:
        logs_html += f"""
            <div style="border: 1px solid #222; margin-bottom: 10px; padding: 8px;">
                {log['timestamp']} | IP: {log['ip']} | User-Agent: {log['user_agent']}<br>
                {log['success']}<br>
                Failed attempts until now: {log['failed_count']}
            </div>
        """

    return f"""
        <html>
            <body style="font-family: 'Roboto', Arial, sans-serif;">
                {logs_html}
            </body>
        </html>
        """

@app.route('/api/change-source')
def change_source():
    new_ip = generate_public_ip()
    new_ua = generate_user_agent()
    return jsonify({
        'new_ip': new_ip,
        'new_ua': new_ua
    })

@app.route('/api/set-source', methods=['POST'])
def set_source():
    data = request.get_json()
    session['current_ip'] = data.get('ip')
    session['current_user_agent'] = data.get('user_agent')
    return jsonify({'status': 'success'})

@app.route('/api/start-attack')
def start_attack():
    ip = session.get('current_ip')
    user_agent = session.get('current_user_agent')

    target_user = 'admin'

    try:
        with open('passwords.txt') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return jsonify({'error': 'passwords.txt not found'}), 500
    
    attempts = 0
    success = 0

    for pwd in passwords:
        attempts += 1

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'user_agent': user_agent,
            'success': False
        }

        if USERS.get(target_user) == pwd:
            log_entry['success'] = True
            success += 1
        else:
            last_failed = get_failed_attempts_count(ip)
            log_entry['failed_count'] = last_failed + 1

        save_log(log_entry)
        time.sleep(0.15)

    return jsonify({
        'attempts': attempts,
        'success': success,
        'user': target_user
    })




if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
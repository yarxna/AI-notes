from flask import Flask, render_template_string, session, request, jsonify
from helpers import generate_public_ip, generate_user_agent
from datetime import datetime, timedelta
from pseudo_ai import ai_bruteforce
from threading import Thread
import requests
import sqlite3
# import random
import time

app = Flask(__name__)
app.secret_key = "this is a local test :)"

ai = ai_bruteforce()

USERS = {
    'admin': 'adminP@ssw0rd123',
    'user1': 'user1P@ssw0rd123',
    'user2': 'user2P@ssw0rd123',

    'root': 'root123',
    'guest': 'guest123',
    'test': 'test123',
    'demo': 'demo123',

    'alice': 'alice2024',
    'bob': 'bob2024',
    'charlie': 'charlie123',
    'david': 'david123',

    'support': 'support@123',
    'developer': 'dev123',
    'devops': 'devops123',
    'security': 'security123'
}

WEB_APP_URL = "http://localhost:5001"
POLL_INTERVAL = 5  # time between each poll for new logs

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
            hour INTEGER,
            ip TEXT,
            user_agent TEXT,
            username TEXT,
            success INTEGER,
            failed_count INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()

def fetch_logs():
    conn = get_db()
    rows = conn.execute("""
        SELECT * FROM auth_logs
        ORDER BY id DESC
    """).fetchall()
    conn.close()
    return rows

def fetch_logs_after_id(after_id): # so the monitor only fetches new logs, not the ones it already processed
    conn = get_db()
    rows = conn.execute("""
        SELECT *
        FROM auth_logs
        WHERE id > ?
        ORDER BY id ASC
    """, (after_id,)).fetchall()
    conn.close()
    return rows


def save_log(entry):
    conn = get_db()
    conn.execute(
        """INSERT INTO auth_logs
        (timestamp, hour, ip, user_agent, username, success, failed_count) 
        VALUES (?,?,?,?,?,?,?)
        """, 
        (
            entry['timestamp'],
            entry['hour'],
            entry['ip'],
            entry['user_agent'],
            entry['username'],
            int(entry['success']),
            entry.get('failed_count')
        )
    )
    conn.commit()
    conn.close()

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

def monitor_logs():
    last_id = 0

    while True:
        try:
            res = requests.get(f'{WEB_APP_URL}/api/logs?after_id={last_id}', timeout=10)
            if res.status_code == 200:
                data = res.json()
                logs = data.get('recent_logs', [])

                if logs:
                    results = ai.analyze_all_logs(logs)
                    last_id = logs[-1]['id']

                    for r in results:
                        if r['is_attack']:
                            print(
                                f"Brute force attack detected from IP {r['ip']} "
                                f"with probability {r['probability']:.2f}"
                            )

        except Exception as e:
            print(f"Error: {e}")

        time.sleep(POLL_INTERVAL)

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
            'hour': datetime.now().hour,
            'ip': ip,
            'user_agent': user_agent,
            'username': username,
            'success': False,
            'failed_count': get_failed_attempts_count(ip)
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
                <p>{{ login_timestamp }}</p>
                <p>IP: {{ ip }}</p>
                <p>User-Agent: {{ user_agent }}</p>
                <p>Username: {{ username }}</p>
                <p>Failed attempts from this IP: {{ failed_count }}</p>
                <a href="/">Try again</a>
            </body>                  
        </html>
        """, failed_count=log_entry['failed_count'], ip=ip, user_agent=user_agent, username=username, login_timestamp=log_entry['timestamp'])

    return render_template_string("""
    <html>
        <style>
            body { font-family: 'Roboto', Arial, sans-serif; }
        </style>
        <body>
            <h1>Test App</h1>                
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
                <p style="margin: 2px 0;">{{ username }}: {{ password }}</p>
            {% endfor %}
            <br>             
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required><br>
                <input type="password" name="password" placeholder="Password" required><br>
                                  
                <button type="submit">Login</button>            
            </form>
                                  
            <label for="target-user"><strong>Target user:</strong></label><br>
            <select id="target-user">
                {% for username in USERS.keys() %}
                    <option value="{{ username }}">{{ username }}</option>
                {% endfor %}
            </select>
            <br><br>
                                  
            <button id="atk-btn" onClick="startAttack()">Start Attack</button>
            <p id="attack-status" style="margin-top:10px; font-weight:bold;"></p>
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
                    const btn = document.getElementById('atk-btn');
                    const status = document.getElementById('attack-status');
                    const targetUser = document.getElementById('target-user').value;


                    btn.disabled = true;
                    btn.style.opacity = '0.6';
                    status.style.color = '#d39e00';
                    status.textContent = `Attack in progress against "${targetUser}"…`;

                        fetch('/api/start-attack', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                target_user: targetUser
                            })
                        })
                        .then(response=>response.json())
                        .then(data => {
                        status.style.color = '#28a745';
                        status.textContent = `Attack finished (${data.attempts} attempts)`;


                        btn.disabled = false;
                        btn.style.opacity = '1';
                        })
                        .catch(error => {
                            console.error('Error:', error)              
                        })    
                }
                                  
                function clearLogs() {
                    fetch('/api/clear-logs', { method: 'POST' })
                        .then(() => alert('Logs cleared successfully'));
                }     
            </script>
                                  
        </body>
    </html>
    """, USERS=USERS, ip=ip, user_agent=user_agent)

@app.route('/api/logs')
def get_logs():
    after_id = request.args.get('after_id', 0, type=int)
    rows = fetch_logs_after_id(after_id)
    logs = [dict(row) for row in rows]

    return jsonify({
        'recent_logs': logs
    })

@app.route('/api/clear-logs', methods=['POST'])
def clear_logs():
    conn = get_db()
    conn.execute("DELETE FROM auth_logs")
    conn.commit()
    conn.close()

    return jsonify({'status': 'logs cleared'})

@app.route('/logs')
def show_logs():
    logs = fetch_logs()
    logs_html = '<h2>Authentication Logs</h2>'
    for log in logs:
        color = 'green' if log['success'] else 'red'
        success = 'SUCCESS' if log['success'] else 'FAILURE'
        logs_html += f"""
            <div style="border: 1px solid #222; margin-bottom: 10px; padding: 12px;">
                <strong>{log['timestamp']}</strong> | <strong>Hour</strong>: {log['hour']} | <strong>IP</strong>: {log['ip']} | <strong>User-Agent</strong>: {log['user_agent']}<br>
                <strong>Username</strong>: {log['username']}<br>
                <span style="color: {color};"><strong>{success}</strong></span><br>
                <strong>Failed attempts from this IP so far</strong>: {log['failed_count']}
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

@app.route('/api/start-attack', methods=['POST'])
def start_attack():
    data = request.get_json()
    target_user = data.get('target_user')

    ip = session.get('current_ip')
    user_agent = session.get('current_user_agent')

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
            'hour': datetime.now().hour, # the AI could use hour of day as a feature as well, but I'm lazy
            'ip': ip,
            'user_agent': user_agent,
            'username': target_user,
            'success': False,
            'failed_count': get_failed_attempts_count(ip)
        }

        if USERS.get(target_user) == pwd:
            log_entry['success'] = True
            success += 1
        else:
            last_failed = get_failed_attempts_count(ip)
            log_entry['failed_count'] = last_failed + 1

        save_log(log_entry)
        time.sleep(0.15) # <-- change here to adjust speed of attack / I'm too lazy to put a proper UI for it :) (want to move on to next week lol)

    return jsonify({
        'attempts': attempts,
        'success': success,
        'user': target_user
    })

@app.route('/api/detections')
def get_detections():
    return jsonify({
        'total_detections': len(ai.detections),
        'recent_detections': ai.detections[-10:][::-1], 
        'ip_history': {ip: info for ip, info in list(ai.ip_history.items())[:20]},
        'monitoring': {
            'web_app_url': WEB_APP_URL,
            'poll_interval': POLL_INTERVAL
        }
    })

@app.route('/api/stats')
def get_stats():
 
    total_ips = len(ai.ip_history)
    suspicious_ips = len([
        ip for ip, logs in ai.ip_history.items()
        if len([l for l in logs if not l.get('success', True)]) > 5
    ])
    now = datetime.now()
    hourly_counts = {i: 0 for i in range(24)}
    
    for detection in ai.detections:
        try:
            dt = datetime.fromisoformat(detection['timestamp'])
            if (now - dt) < timedelta(hours=24):
                hour = dt.hour
                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
        except:
            pass
    
    return jsonify({
        'total_ips_monitored': total_ips,
        'suspicious_ips': suspicious_ips,
        'total_detections': len(ai.detections),
        'detections_last_24h': sum(hourly_counts.values()),
        'hourly_detections': hourly_counts,
        'top_offending_ips': sorted(
            [
                (
                    ip,
                    len([l for l in logs if not l.get('success', True)])
                )
                for ip, logs in ai.ip_history.items()
            ],
            key=lambda x: x[1],
            reverse=True
        )[:10]
    })

@app.route('/api/logs/probabilities')
def logs_probabilities():
    rows = fetch_logs()
    logs = [dict(row) for row in rows]

    logs_by_ip = {}
    for log in logs:
        ip = log.get('ip', 'unknown')
        logs_by_ip.setdefault(ip, []).append(log)

    result = []
    for ip, ip_logs in logs_by_ip.items():

        ip_logs = sorted(ip_logs, key=lambda l: l['timestamp'])

        history = []

        for log in ip_logs:
            history.append(log)
            prediction = ai.predict(history)
            result.append({
                'id': log['id'],
                'timestamp': log['timestamp'],
                'ip': log['ip'],
                'username': log['username'],
                'success': bool(log['success']),
                'failed_count': log['failed_count'],
                'attack_probability': prediction['probability']
            })

    return jsonify(result)

if __name__ == '__main__':
    monitor_thread = Thread(target=monitor_logs, daemon=True)
    monitor_thread.start()
    app.run(host='0.0.0.0', port=5001, debug=True)
from flask import Flask, request, jsonify, render_template_string
from helpers import generate_public_ip, generate_user_agent
from datetime import datetime

app = Flask(__name__)
app.secret_key = '123456'

USERS = {
    'admin': 'Adm1n_$3cur3p@$$',
    'user1': 'user1_$3cur3p@$$',
    'user2': 'user2_$3cur3p@$$'
}

auth_logs = []
failed_attempts = []

@app.route('/', methods=['GET', 'POST'])
def home():

    ip = generate_public_ip()
    user_agent = generate_user_agent()

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'username': username,
            'success': False,
            'user_agent': user_agent,
            'hour': datetime.now().hour
        }

        if username in USERS and USERS[username] == password:
            log_entry['success'] = True
            message = f'Login successful for {username}'

            if ip in failed_attempts:
                del failed_attempts[ip]
        else:
            if ip not in failed_attempts:
                failed_attempts[ip] = {'count': 0, 'first_attempt': datetime.now().isoformat()}
            
            failed_attempts[ip]['count'] += 1
            failed_attempts[ip]['last_attempt'] = datetime.now().isoformat()
            
            log_entry['failed_count'] = failed_attempts[ip]['count']
            message = f"Login failed for {username}"

        auth_logs.append(log_entry)

        if len(auth_logs) > 2000:
            auth_logs.pop(0)

        return render_template_string('''
        <html>
            <style>
                body { font-family: 'Roboto', sans-serif; }
            </style>
            <body>
                <h1>Test App</h1>
                <h2>{{ message }}</h2>
                <p>IP: {{ ip }}</p>
                <p>User-Agent: {{ user_agent }}</p>
                <p>Failed attempts from this IP: {{ failed_count }}</p>
                <a href="/">Try again</a> |
            </body>
        </html>
        ''', message=message, ip=ip, user_agent=user_agent, failed_count=failed_attempts.get(ip, {}).get("count", 0))
    return render_template_string('''
    <html>
        <style>
            body { font-family: Arial; padding: 40px; }
            .login-box { border: 1px solid #ccc; padding: 30px; max-width: 400px; margin: auto; }
            input { padding: 10px; margin: 10px 0; width: 100%; }
            button { background: #28a745; color: white; padding: 12px; width: 100%; border: none; cursor: pointer; }
        </style>
        <body>
            <div class="login-box">
                <h1>Test App</h1>
                <p>IP: <span id="current-ip">{{ ip }}</span></p>
                <p>User-Agent: <span id="current-ua">{{ user_agent }}</span></p>
                <button onClick="changeSource()">Change source</button>
                <h2>Login</h2>
                <p><i>Test this credentials:</i></p>
                <p><b>admin / Adm1n_$3cur3p@$$</b></p>
                <p><b>user1 / user1_$3cur3p@$$</b></p>
                <p><b>user2 / user2_$3cur3p@$$</b></p>
                <form method="POST">
                    <input type="text" name="username" placeholder="Username" required><br>
                    <input type="password" name="password" placeholder="Password" required><br>
                    <button type="submit">Login</button>
                </form>
                <p style="color: #666; font-size: 12px; margin-top: 20px;">
                    Each login attempt generates a log that will be analyzed by the AI.
                </p>
            </div>

            <script>                     
                function changeSource() {
                    fetch('/api/change-source')
                        .then(response => response.json())
                        .then(data => {
                            document.getElementById('current-ip').textContent = data.new_ip;
                            document.getElementById('current-ua').textContent = data.new_user_agent;
                        })
                        .catch(error => {
                            console.error('Error:', error);
                        });
                }
            </script>
        </body>
    </html>
    ''', ip=ip, user_agent=user_agent)

@app.route('/logs')
def show_logs():
    logs_html = "<h2>Authentication Logs</h2>"
    
    for log in reversed(auth_logs[-50:]):
        color = "green" if log.get('success') else "red"
        logs_html += f'''
        <div style="border: 1px solid #ccc; margin: 10px; padding: 10px; background: #f9f9f9;">
            <p><b>{log['timestamp']}</b> - IP: {log['ip']}</p>
            <p>Usuário: {log['username']} - 
               <span style="color: {color}; font-weight: bold;">
                 {"SUCCESS" if log.get('success') else "FAILURE"}
               </span>
            </p>
            <p>Tentativas falhas: {log.get('failed_count', 0)}</p>
        </div>
        '''
    
    return f'''
    <html>
        <body style="font-family: Arial; padding: 20px;">
            {logs_html}
            <a href="/">← Back</a>
        </body>
    </html>
    '''

@app.route('/api/logs')
def get_logs_api():
    return jsonify({
        'total_logs': len(auth_logs),
        'failed_attempts_by_ip': failed_attempts,
        'recent_logs': auth_logs[-20:],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/change-source')
def change_ip():
    new_ip = generate_public_ip()
    new_user_agent = generate_user_agent()
    return jsonify({
            'new_ip': new_ip,
            'new_user_agent': new_user_agent
        })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
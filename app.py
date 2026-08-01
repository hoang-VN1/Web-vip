from flask import Flask, request, jsonify, render_template, redirect, url_for, session, make_response
import requests
import json
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta
from functools import wraps
import time
import threading
import csv
import io

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# ============================================
# DATABASE INIT
# ============================================
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        api_key TEXT UNIQUE NOT NULL,
        name TEXT,
        webhook_url TEXT,
        max_boss INTEGER DEFAULT 100,
        total_jobs INTEGER DEFAULT 10,
        prefix TEXT,
        suffix TEXT,
        whitelist_ips TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_key TEXT,
        job_data TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS monitors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        url TEXT,
        interval INTEGER DEFAULT 60,
        webhook_url TEXT,
        status TEXT DEFAULT 'unknown',
        last_check TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS shields (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        webhook_url TEXT,
        link TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS quests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        discord_token TEXT,
        delay INTEGER DEFAULT 60,
        status TEXT DEFAULT 'stopped',
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS executors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT,
        script TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS key_systems (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        bot_token TEXT,
        bot_name TEXT,
        admin_id TEXT,
        keys TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event TEXT,
        details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    
    # Tạo admin mặc định
    admin_username = 'Hoang2026'
    admin_password = hashlib.sha256('hoang@2k13'.encode()).hexdigest()
    c.execute('SELECT id FROM users WHERE username = ?', (admin_username,))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
                  (admin_username, admin_password, 'admin'))
        log_event('SYSTEM', 'Admin account Hoang2026 created')
    
    conn.commit()
    conn.close()

def log_event(event, details):
    try:
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO logs (event, details) VALUES (?, ?)', (event, details))
        conn.commit()
        conn.close()
    except:
        pass

init_db()

# ============================================
# DECORATORS
# ============================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if not user or user[0] != 'admin':
            return jsonify({'error': 'Yêu cầu quyền Admin'}), 403
        return f(*args, **kwargs)
    return decorated

def vip_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT role FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()
        if not user or user[0] not in ['vip', 'admin']:
            return jsonify({'error': 'Yêu cầu quyền VIP'}), 403
        return f(*args, **kwargs)
    return decorated

# ============================================
# ROUTES - AUTH
# ============================================
@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Vui lòng điền đầy đủ'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ?', (username,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Tên đã tồn tại'}), 400
    hashed = hashlib.sha256(password.encode()).hexdigest()
    c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
    conn.commit()
    conn.close()
    log_event('REGISTER', f'User {username} registered')
    return jsonify({'success': True, 'message': 'Đăng ký thành công!'})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    data = request.get_json() or request.form
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Vui lòng điền đầy đủ'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    hashed = hashlib.sha256(password.encode()).hexdigest()
    c.execute('SELECT id, username, role FROM users WHERE username = ? AND password = ?', (username, hashed))
    user = c.fetchone()
    conn.close()
    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[2]
        log_event('LOGIN', f'User {username} logged in')
        return jsonify({'success': True, 'redirect': url_for('dashboard')})
    return jsonify({'error': 'Sai tên hoặc mật khẩu'}), 401

@app.route('/logout')
def logout():
    log_event('LOGOUT', f'User {session.get("username")} logged out')
    session.clear()
    return redirect(url_for('home'))

# ============================================
# DASHBOARD
# ============================================
@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    total_api = c.execute('SELECT COUNT(*) FROM api_keys WHERE user_id = ?', (session['user_id'],)).fetchone()[0]
    total_monitors = c.execute('SELECT COUNT(*) FROM monitors WHERE user_id = ?', (session['user_id'],)).fetchone()[0]
    total_shields = c.execute('SELECT COUNT(*) FROM shields WHERE user_id = ?', (session['user_id'],)).fetchone()[0]
    total_quests = c.execute('SELECT COUNT(*) FROM quests WHERE user_id = ?', (session['user_id'],)).fetchone()[0]
    total_exec = c.execute('SELECT COUNT(*) FROM executors WHERE user_id = ?', (session['user_id'],)).fetchone()[0]
    conn.close()
    return render_template('dashboard.html', 
                         username=session.get('username'),
                         role=session.get('role'),
                         total_api=total_api,
                         total_monitors=total_monitors,
                         total_shields=total_shields,
                         total_quests=total_quests,
                         total_exec=total_exec)

# ============================================
# TAB: API
# ============================================
@app.route('/api')
@login_required
def api_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT id, api_key, name, webhook_url, max_boss, total_jobs, 
                 prefix, suffix, whitelist_ips, created_at 
                 FROM api_keys WHERE user_id = ?''', (session['user_id'],))
    api_keys = c.fetchall()
    conn.close()
    return render_template('api.html', api_keys=api_keys, role=session.get('role'))

@app.route('/api/create', methods=['POST'])
@login_required
def create_api():
    data = request.get_json()
    name = data.get('name', 'API mới')
    webhook_url = data.get('webhook_url', '')
    max_boss = data.get('max_boss', 100)
    total_jobs = data.get('total_jobs', 10)
    prefix = data.get('prefix', '')
    suffix = data.get('suffix', '')
    whitelist_ips = data.get('whitelist_ips', '')
    api_key = 'api_' + secrets.token_hex(16)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''INSERT INTO api_keys 
                 (user_id, api_key, name, webhook_url, max_boss, total_jobs, prefix, suffix, whitelist_ips)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
              (session['user_id'], api_key, name, webhook_url, max_boss, total_jobs, prefix, suffix, whitelist_ips))
    conn.commit()
    conn.close()
    log_event('CREATE_API', f'User {session["username"]} created API {name}')
    return jsonify({'success': True, 'api_key': api_key, 'message': f'API {name} đã tạo!'})

@app.route('/api/delete/<int:api_id>', methods=['POST'])
@login_required
def delete_api(api_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?', (api_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/<api_key>', methods=['GET', 'POST'])
def webhook_endpoint(api_key):
    if request.method == 'GET':
        return jsonify({'status': 'active', 'message': 'API đang hoạt động'})
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT webhook_url FROM api_keys WHERE api_key = ?', (api_key,))
    result = c.fetchone()
    if not result:
        conn.close()
        return jsonify({'error': 'Invalid API key'}), 401
    webhook_url = result[0]
    c.execute('INSERT INTO jobs (api_key, job_data) VALUES (?, ?)', (api_key, json.dumps(data)))
    conn.commit()
    conn.close()
    if webhook_url:
        try:
            requests.post(webhook_url, json=data, timeout=10)
        except:
            pass
    return jsonify({'status': 'success', 'message': 'Data received!'})

# ============================================
# TAB: OWNER (Admin only)
# ============================================
@app.route('/owner')
@admin_required
def owner_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    users = c.execute('SELECT id, username, role, created_at FROM users').fetchall()
    stats = {
        'total_users': len(users),
        'total_api': c.execute('SELECT COUNT(*) FROM api_keys').fetchone()[0],
        'total_jobs': c.execute('SELECT COUNT(*) FROM jobs').fetchone()[0],
        'total_monitors': c.execute('SELECT COUNT(*) FROM monitors').fetchone()[0],
        'total_shields': c.execute('SELECT COUNT(*) FROM shields').fetchone()[0],
        'total_quests': c.execute('SELECT COUNT(*) FROM quests').fetchone()[0],
        'total_exec': c.execute('SELECT COUNT(*) FROM executors').fetchone()[0],
        'total_keysystems': c.execute('SELECT COUNT(*) FROM key_systems').fetchone()[0],
    }
    conn.close()
    return render_template('owner.html', users=users, stats=stats)

@app.route('/owner/update_role', methods=['POST'])
@admin_required
def update_role():
    data = request.get_json()
    user_id = data.get('user_id')
    role = data.get('role')
    if role not in ['user', 'vip', 'admin']:
        return jsonify({'error': 'Role không hợp lệ'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('UPDATE users SET role = ? WHERE id = ?', (role, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ============================================
# TAB: BOT (VIP+)
# ============================================
@app.route('/bot')
@vip_required
def bot_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    bots = c.execute('SELECT id, name, created_at FROM executors WHERE user_id = ?',
                     (session['user_id'],)).fetchall()
    conn.close()
    return render_template('bot.html', bots=bots, role=session.get('role'))

@app.route('/bot/host', methods=['POST'])
@vip_required
def host_bot():
    data = request.get_json()
    name = data.get('name')
    code = data.get('code')
    env = data.get('env', '{}')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO executors (user_id, name, script) VALUES (?, ?, ?)',
              (session['user_id'], name, code))
    conn.commit()
    conn.close()
    log_event('HOST_BOT', f'User {session["username"]} hosted bot {name}')
    return jsonify({'success': True, 'message': f'Bot {name} đã được lưu!'})

# ============================================
# TAB: UPTIME
# ============================================
@app.route('/uptime')
@login_required
def uptime_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    monitors = c.execute('SELECT id, name, url, interval, status, last_check FROM monitors WHERE user_id = ?',
                         (session['user_id'],)).fetchall()
    conn.close()
    return render_template('uptime.html', monitors=monitors)

@app.route('/uptime/add', methods=['POST'])
@login_required
def add_monitor():
    data = request.get_json()
    name = data.get('name')
    url = data.get('url')
    interval = data.get('interval', 60)
    webhook_url = data.get('webhook_url', '')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO monitors (user_id, name, url, interval, webhook_url) VALUES (?, ?, ?, ?, ?)',
              (session['user_id'], name, url, interval, webhook_url))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/uptime/check/<int:monitor_id>', methods=['POST'])
@login_required
def check_uptime(monitor_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT url, webhook_url FROM monitors WHERE id = ? AND user_id = ?', (monitor_id, session['user_id']))
    monitor = c.fetchone()
    if not monitor:
        conn.close()
        return jsonify({'error': 'Monitor not found'}), 404
    url, webhook_url = monitor
    try:
        start = time.time()
        r = requests.get(url, timeout=10)
        latency = int((time.time() - start) * 1000)
        status = 'up' if r.status_code == 200 else 'down'
        c.execute('UPDATE monitors SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?',
                  (status, monitor_id))
        conn.commit()
        conn.close()
        if webhook_url and status == 'down':
            requests.post(webhook_url, json={'alert': f'Monitor {monitor_id} is down!'})
        return jsonify({'status': status, 'latency': latency})
    except:
        c.execute('UPDATE monitors SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?',
                  ('down', monitor_id))
        conn.commit()
        conn.close()
        return jsonify({'status': 'down', 'latency': 0})

# ============================================
# TAB: SHIELD
# ============================================
@app.route('/shield')
@login_required
def shield_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    shields = c.execute('SELECT id, name, webhook_url, link, created_at FROM shields WHERE user_id = ?',
                        (session['user_id'],)).fetchall()
    conn.close()
    return render_template('shield.html', shields=shields)

@app.route('/shield/create', methods=['POST'])
@login_required
def create_shield():
    data = request.get_json()
    name = data.get('name')
    webhook_url = data.get('webhook_url')
    link = secrets.token_hex(8)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO shields (user_id, name, webhook_url, link) VALUES (?, ?, ?, ?)',
              (session['user_id'], name, webhook_url, link))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'link': link})

@app.route('/shield/<link>')
def shield_redirect(link):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT webhook_url FROM shields WHERE link = ?', (link,))
    shield = c.fetchone()
    conn.close()
    if shield:
        return redirect(shield[0])
    return 'Shield not found', 404

# ============================================
# TAB: QUEST
# ============================================
@app.route('/quest')
@login_required
def quest_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    quests = c.execute('SELECT id, discord_token, delay, status FROM quests WHERE user_id = ?',
                       (session['user_id'],)).fetchall()
    conn.close()
    return render_template('quest.html', quests=quests)

@app.route('/quest/add', methods=['POST'])
@login_required
def add_quest():
    data = request.get_json()
    token = data.get('discord_token')
    delay = data.get('delay', 60)
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO quests (user_id, discord_token, delay, status) VALUES (?, ?, ?, ?)',
              (session['user_id'], token, delay, 'running'))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ============================================
# TAB: EXEC
# ============================================
@app.route('/exec')
@login_required
def exec_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    execs = c.execute('SELECT id, name, created_at FROM executors WHERE user_id = ?',
                      (session['user_id'],)).fetchall()
    conn.close()
    return render_template('exec.html', execs=execs)

@app.route('/exec/create', methods=['POST'])
@login_required
def create_exec():
    data = request.get_json()
    name = data.get('name')
    script = data.get('script')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO executors (user_id, name, script) VALUES (?, ?, ?)',
              (session['user_id'], name, script))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ============================================
# TAB: CREAPI (VIP+)
# ============================================
@app.route('/creapi')
@vip_required
def creapi_tab():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    systems = c.execute('SELECT id, bot_token, bot_name, admin_id, created_at FROM key_systems WHERE user_id = ?',
                        (session['user_id'],)).fetchall()
    conn.close()
    return render_template('creapi.html', systems=systems)

@app.route('/creapi/create', methods=['POST'])
@vip_required
def create_keysystem():
    data = request.get_json()
    bot_token = data.get('bot_token')
    bot_name = data.get('bot_name')
    admin_id = data.get('admin_id')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('INSERT INTO key_systems (user_id, bot_token, bot_name, admin_id) VALUES (?, ?, ?, ?)',
              (session['user_id'], bot_token, bot_name, admin_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ============================================
# USER FEATURES
# ============================================
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    old = data.get('old_password')
    new = data.get('new_password')
    if not old or not new or len(new) < 6:
        return jsonify({'error': 'Mật khẩu mới phải có ít nhất 6 ký tự'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    hashed_old = hashlib.sha256(old.encode()).hexdigest()
    c.execute('SELECT id FROM users WHERE id = ? AND password = ?', (session['user_id'], hashed_old))
    if not c.fetchone():
        conn.close()
        return jsonify({'error': 'Mật khẩu cũ không đúng'}), 400
    hashed_new = hashlib.sha256(new.encode()).hexdigest()
    c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_new, session['user_id']))
    conn.commit()
    conn.close()
    log_event('CHANGE_PASSWORD', f'User {session["username"]} changed password')
    return jsonify({'success': True})

@app.route('/export_api_keys')
@login_required
def export_api_keys():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT api_key, name, webhook_url, created_at FROM api_keys WHERE user_id = ?', (session['user_id'],))
    keys = c.fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['API Key', 'Name', 'Webhook URL', 'Created At'])
    for row in keys:
        writer.writerow(row)
    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=api_keys.csv'
    response.headers['Content-type'] = 'text/csv'
    return response

@app.route('/test_webhook', methods=['POST'])
@login_required
def test_webhook():
    data = request.get_json()
    webhook_url = data.get('webhook_url')
    test_data = data.get('test_data', {'test': 'Hello from WebAPI!'})
    if not webhook_url:
        return jsonify({'error': 'Webhook URL required'}), 400
    try:
        r = requests.post(webhook_url, json=test_data, timeout=10)
        return jsonify({'success': True, 'status_code': r.status_code, 'response': r.text[:500]})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================
# ADMIN - BACKUP & RESTORE
# ============================================
@app.route('/admin/backup')
@admin_required
def admin_backup():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    tables = ['users', 'api_keys', 'jobs', 'monitors', 'shields', 'quests', 'executors', 'key_systems', 'logs', 'settings']
    data = {}
    for table in tables:
        c.execute(f'SELECT * FROM {table}')
        rows = c.fetchall()
        data[table] = rows
    conn.close()
    log_event('ADMIN_BACKUP', f'Admin {session["username"]} exported database backup')
    return jsonify(data)

@app.route('/admin/restore', methods=['POST'])
@admin_required
def admin_restore():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data'}), 400
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        for table, rows in data.items():
            c.execute(f'DELETE FROM {table}')
            if rows:
                placeholders = ','.join(['?' for _ in range(len(rows[0]))])
                c.executemany(f'INSERT INTO {table} VALUES ({placeholders})', rows)
        conn.commit()
        log_event('ADMIN_RESTORE', f'Admin {session["username"]} restored database from backup')
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': str(e)}), 500
    conn.close()
    return jsonify({'success': True})

# ============================================
# BACKGROUND TASKS
# ============================================
def scheduled_backup():
    while True:
        time.sleep(86400)
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            tables = ['users', 'api_keys', 'jobs', 'monitors', 'shields', 'quests', 'executors', 'key_systems', 'logs', 'settings']
            data = {}
            for table in tables:
                c.execute(f'SELECT * FROM {table}')
                rows = c.fetchall()
                data[table] = rows
            conn.close()
            with open(f'backup_{datetime.now().strftime("%Y%m%d")}.json', 'w') as f:
                json.dump(data, f)
            log_event('SCHEDULED_BACKUP', 'Auto backup completed')
        except Exception as e:
            log_event('BACKUP_ERROR', str(e))

def auto_clean_old_jobs():
    while True:
        time.sleep(3600)
        try:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            cutoff = (datetime.now() - timedelta(days=30)).isoformat()
            c.execute('DELETE FROM jobs WHERE created_at < ?', (cutoff,))
            conn.commit()
            conn.close()
            log_event('AUTO_CLEAN', 'Deleted jobs older than 30 days')
        except Exception as e:
            log_event('CLEAN_ERROR', str(e))

threading.Thread(target=scheduled_backup, daemon=True).start()
threading.Thread(target=auto_clean_old_jobs, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
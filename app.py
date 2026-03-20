from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timezone
import pg8000.native
import bcrypt
import os
import urllib.parse

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-key')

DB_URL = os.environ.get('DATABASE_URL')

def get_db():
    r = urllib.parse.urlparse(DB_URL)
    conn = pg8000.native.Connection(
        host=r.hostname,
        port=r.port or 5432,
        database=r.path.lstrip('/'),
        user=r.username,
        password=r.password,
        ssl_context=True
    )
    return conn

def query(conn, sql, params=()):
    """Run a SELECT and return list of dicts."""
    rows = conn.run(sql, *params)
    if not rows:
        return []
    cols = [c['name'] for c in conn.columns]
    return [dict(zip(cols, row)) for row in rows]

def execute(conn, sql, params=()):
    """Run INSERT / UPDATE / DELETE."""
    conn.run(sql, *params)

@app.before_request
def setup():
    if not getattr(app, '_db_initialized', False):
        conn = get_db()
        conn.run('''
            CREATE TABLE IF NOT EXISTS accounts (
                name TEXT UNIQUE NOT NULL,
                pwd_hash BYTEA,
                balance INTEGER DEFAULT 0
            )
        ''')
        conn.run('''
            CREATE TABLE IF NOT EXISTS history (
                time TEXT,
                name TEXT,
                amount INTEGER
            )
        ''')
        conn.run('''
            CREATE TABLE IF NOT EXISTS pwd_meta (
                name TEXT UNIQUE NOT NULL,
                pwd_rounds INTEGER
            )
        ''')
        conn.run('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                name TEXT UNIQUE NOT NULL,
                attempts INTEGER,
                last_attempt TEXT
            )
        ''')
        conn.close()
        app._db_initialized = True

def hash_pwd(password: str, rounds: int = 12) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds))

def check_pwd(password: str, hashed) -> bool:
    if isinstance(hashed, memoryview):
        hashed = bytes(hashed)
    if isinstance(hashed, str):
        hashed = hashed.encode()
    return bcrypt.checkpw(password.encode(), hashed)

MAX_ATTEMPTS = 3
LOCKOUT_MINS = 5
MIN_ROUNDS   = 14

def is_locked(conn, name: str) -> bool:
    rows = query(conn, 'SELECT attempts, last_attempt FROM login_attempts WHERE name=$1', (name,))
    if not rows or rows[0]['attempts'] < MAX_ATTEMPTS:
        return False
    elapsed = (datetime.now() - datetime.fromisoformat(rows[0]['last_attempt'])).total_seconds() / 60
    if elapsed < LOCKOUT_MINS:
        return True
    execute(conn, 'DELETE FROM login_attempts WHERE name=$1', (name,))
    return False

def track_attempt(conn, name: str):
    now = datetime.now().isoformat()
    rows = query(conn, 'SELECT attempts FROM login_attempts WHERE name=$1', (name,))
    if rows:
        execute(conn,
            'UPDATE login_attempts SET attempts=$1, last_attempt=$2 WHERE name=$3',
            (rows[0]['attempts'] + 1, now, name))
    else:
        execute(conn, 'INSERT INTO login_attempts VALUES ($1, 1, $2)', (name, now))

def remaining_attempts(conn, name: str) -> int:
    rows = query(conn, 'SELECT attempts FROM login_attempts WHERE name=$1', (name,))
    return MAX_ATTEMPTS - (rows[0]['attempts'] if rows else 0)

def upgrade_hash(conn, name: str, password: str):
    rows = query(conn, 'SELECT pwd_rounds FROM pwd_meta WHERE name=$1', (name,))
    current = rows[0]['pwd_rounds'] if rows else 12
    if current < MIN_ROUNDS:
        new_hash = hash_pwd(password, MIN_ROUNDS)
        try:
            execute(conn, 'UPDATE accounts SET pwd_hash=$1 WHERE name=$2', (new_hash, name))
            execute(conn, 'UPDATE pwd_meta SET pwd_rounds=$1 WHERE name=$2', (MIN_ROUNDS, name))
        except Exception:
            pass

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        password = request.form.get('password', '')
        conn = get_db()

        if is_locked(conn, name):
            flash(f'Account locked. Too many failed attempts. Try again in {LOCKOUT_MINS} minutes.', 'error')
            conn.close()
            return redirect(url_for('login'))

        rows = query(conn, 'SELECT pwd_hash FROM accounts WHERE name=$1', (name,))
        if not rows:
            flash('User not found. Please register first.', 'error')
            conn.close()
            return redirect(url_for('login'))

        if not check_pwd(password, rows[0]['pwd_hash']):
            track_attempt(conn, name)
            rem = remaining_attempts(conn, name)
            flash(
                f'Incorrect password. {rem} attempt(s) remaining.' if rem > 0
                else 'Account locked after too many failed attempts.',
                'error'
            )
            conn.close()
            return redirect(url_for('login'))

        execute(conn, 'DELETE FROM login_attempts WHERE name=$1', (name,))
        upgrade_hash(conn, name, password)
        conn.close()
        session['user'] = name
        return redirect(url_for('dashboard'))

    return render_template('login.html', mode='login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name     = request.form.get('name', '').strip()
        password = request.form.get('password', '')
        conn = get_db()

        if not name:
            flash('Username cannot be empty.', 'error')
            conn.close()
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            conn.close()
            return redirect(url_for('register'))

        rows = query(conn, 'SELECT name FROM accounts WHERE name=$1', (name,))
        if rows:
            flash('Username already taken. Please log in instead.', 'error')
            conn.close()
            return redirect(url_for('register'))

        pwd_hash = hash_pwd(password)
        try:
            execute(conn,
                'INSERT INTO accounts (name, pwd_hash, balance) VALUES ($1, $2, 0)',
                (name, pwd_hash))
            execute(conn,
                'INSERT INTO pwd_meta (name, pwd_rounds) VALUES ($1, 12)',
                (name,))
            flash('Registered successfully. Please log in.', 'success')
        except Exception as e:
            flash(f'Registration failed: {e}', 'error')
        finally:
            conn.close()

        return redirect(url_for('login'))

    return render_template('login.html', mode='register')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    name = session['user']
    conn = get_db()

    rows = query(conn, 'SELECT balance FROM accounts WHERE name=$1', (name,))
    balance = rows[0]['balance'] if rows else 0

    history = query(conn,
        'SELECT time, amount FROM history WHERE name=$1 ORDER BY time DESC LIMIT 5',
        (name,))
    conn.close()

    recent = []
    for h in history:
        utc_dt = datetime.fromisoformat(h['time'])
        recent.append({
            'time':   utc_dt.strftime('%d %b %Y, %H:%M'),
            'amount': h['amount'],
            'state':  'Deposited' if h['amount'] > 0 else 'Withdrawn'
        })

    return render_template('dashboard.html', name=name, balance=balance, recent=recent)

@app.route('/deposit', methods=['GET', 'POST'])
@login_required
def deposit():
    name = session['user']
    conn = get_db()

    if request.method == 'POST':
        try:
            amt = int(request.form.get('amount', 0))
        except ValueError:
            flash('Invalid amount.', 'error')
            conn.close()
            return redirect(url_for('deposit'))

        if amt <= 0:
            flash('Amount must be positive.', 'error')
            conn.close()
            return redirect(url_for('deposit'))

        rows = query(conn, 'SELECT balance FROM accounts WHERE name=$1', (name,))
        new_bal   = rows[0]['balance'] + amt
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            execute(conn, 'UPDATE accounts SET balance=$1 WHERE name=$2', (new_bal, name))
            execute(conn,
                'INSERT INTO history (time, name, amount) VALUES ($1, $2, $3)',
                (timestamp, name, amt))
            flash(f'Successfully deposited ₹{amt:,}.', 'success')
        except Exception as e:
            flash(f'Transaction failed: {e}', 'error')
        finally:
            conn.close()
        return redirect(url_for('dashboard'))

    rows = query(conn, 'SELECT balance FROM accounts WHERE name=$1', (name,))
    balance = rows[0]['balance'] if rows else 0
    conn.close()
    return render_template('deposit.html', name=name, balance=balance)

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    name = session['user']
    conn = get_db()

    if request.method == 'POST':
        try:
            amt = int(request.form.get('amount', 0))
        except ValueError:
            flash('Invalid amount.', 'error')
            conn.close()
            return redirect(url_for('withdraw'))

        rows = query(conn, 'SELECT balance FROM accounts WHERE name=$1', (name,))
        balance = rows[0]['balance'] if rows else 0

        if amt <= 0:
            flash('Amount must be positive.', 'error')
            conn.close()
            return redirect(url_for('withdraw'))
        if amt > balance:
            flash(f'Insufficient funds. Your balance is ₹{balance:,}.', 'error')
            conn.close()
            return redirect(url_for('withdraw'))

        new_bal   = balance - amt
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            execute(conn, 'UPDATE accounts SET balance=$1 WHERE name=$2', (new_bal, name))
            execute(conn,
                'INSERT INTO history (time, name, amount) VALUES ($1, $2, $3)',
                (timestamp, name, -amt))
            flash(f'Successfully withdrawn ₹{amt:,}.', 'success')
        except Exception as e:
            flash(f'Transaction failed: {e}', 'error')
        finally:
            conn.close()
        return redirect(url_for('dashboard'))

    rows = query(conn, 'SELECT balance FROM accounts WHERE name=$1', (name,))
    balance = rows[0]['balance'] if rows else 0
    conn.close()
    return render_template('withdraw.html', name=name, balance=balance)

@app.route('/history')
@login_required
def history():
    name = session['user']
    conn = get_db()
    rows = query(conn,
        'SELECT time, amount FROM history WHERE name=$1 ORDER BY time DESC',
        (name,))
    conn.close()

    txns = []
    for r in rows:
        utc_dt = datetime.fromisoformat(r['time'])
        txns.append({
            'time':   utc_dt.strftime('%d %b %Y, %H:%M UTC'),
            'amount': r['amount'],
            'state':  'Deposited' if r['amount'] > 0 else 'Withdrawn'
        })

    return render_template('history.html', name=name, transactions=txns)

if __name__ == '__main__':
    app.run(debug=True)
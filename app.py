from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timezone
import psycopg2
import psycopg2.extras
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-key')

DB_URL = os.environ.get('DATABASE_URL')

def get_db():
    conn = psycopg2.connect(DB_URL)
    conn.autocommit = True
    return conn

def query(conn, sql, params=()):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]

def execute(conn, sql, params=()):
    with conn.cursor() as cur:
        cur.execute(sql, params)

@app.before_request
def setup():
    if not getattr(app, '_db_initialized', False):
        try:
            conn = get_db()
            conn.cursor().execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    name TEXT UNIQUE NOT NULL,
                    pwd_hash BYTEA,
                    balance INTEGER DEFAULT 0
                )
            ''')
            conn.cursor().execute('''
                CREATE TABLE IF NOT EXISTS history (
                    time TEXT,
                    name TEXT,
                    amount INTEGER
                )
            ''')
            conn.cursor().execute('''
                CREATE TABLE IF NOT EXISTS pwd_meta (
                    name TEXT UNIQUE NOT NULL,
                    pwd_rounds INTEGER
                )
            ''')
            conn.cursor().execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    name TEXT UNIQUE NOT NULL,
                    attempts INTEGER,
                    last_attempt TEXT
                )
            ''')
            conn.close()
            app._db_initialized = True
        except Exception as e:
            app.logger.error(f"DB init error: {e}")

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
    rows = query(conn, 'SELECT attempts, last_attempt FROM login_attempts WHERE name=%s', (name,))
    if not rows or rows[0]['attempts'] < MAX_ATTEMPTS:
        return False
    elapsed = (datetime.now() - datetime.fromisoformat(rows[0]['last_attempt'])).total_seconds() / 60
    if elapsed < LOCKOUT_MINS:
        return True
    execute(conn, 'DELETE FROM login_attempts WHERE name=%s', (name,))
    return False

def track_attempt(conn, name: str):
    now = datetime.now().isoformat()
    rows = query(conn, 'SELECT attempts FROM login_attempts WHERE name=%s', (name,))
    if rows:
        execute(conn,
            'UPDATE login_attempts SET attempts=%s, last_attempt=%s WHERE name=%s',
            (rows[0]['attempts'] + 1, now, name))
    else:
        execute(conn, 'INSERT INTO login_attempts VALUES (%s, 1, %s)', (name, now))

def remaining_attempts(conn, name: str) -> int:
    rows = query(conn, 'SELECT attempts FROM login_attempts WHERE name=%s', (name,))
    return MAX_ATTEMPTS - (rows[0]['attempts'] if rows else 0)

def upgrade_hash(conn, name: str, password: str):
    rows = query(conn, 'SELECT pwd_rounds FROM pwd_meta WHERE name=%s', (name,))
    current = rows[0]['pwd_rounds'] if rows else 12
    if current < MIN_ROUNDS:
        new_hash = hash_pwd(password, MIN_ROUNDS)
        try:
            execute(conn, 'UPDATE accounts SET pwd_hash=%s WHERE name=%s', (new_hash, name))
            execute(conn, 'UPDATE pwd_meta SET pwd_rounds=%s WHERE name=%s', (MIN_ROUNDS, name))
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

        rows = query(conn, 'SELECT pwd_hash FROM accounts WHERE name=%s', (name,))
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

        execute(conn, 'DELETE FROM login_attempts WHERE name=%s', (name,))
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

        rows = query(conn, 'SELECT name FROM accounts WHERE name=%s', (name,))
        if rows:
            flash('Username already taken. Please log in instead.', 'error')
            conn.close()
            return redirect(url_for('register'))

        pwd_hash = hash_pwd(password)
        try:
            execute(conn,
                'INSERT INTO accounts (name, pwd_hash, balance) VALUES (%s, %s, 0)',
                (name, pwd_hash))
            execute(conn,
                'INSERT INTO pwd_meta (name, pwd_rounds) VALUES (%s, 12)',
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

    rows = query(conn, 'SELECT balance FROM accounts WHERE name=%s', (name,))
    balance = rows[0]['balance'] if rows else 0

    history = query(conn,
        'SELECT time, amount FROM history WHERE name=%s ORDER BY time DESC LIMIT 5',
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

        rows = query(conn, 'SELECT balance FROM accounts WHERE name=%s', (name,))
        new_bal   = rows[0]['balance'] + amt
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            execute(conn, 'UPDATE accounts SET balance=%s WHERE name=%s', (new_bal, name))
            execute(conn,
                'INSERT INTO history (time, name, amount) VALUES (%s, %s, %s)',
                (timestamp, name, amt))
            flash(f'Successfully deposited ₹{amt:,}.', 'success')
        except Exception as e:
            flash(f'Transaction failed: {e}', 'error')
        finally:
            conn.close()
        return redirect(url_for('dashboard'))

    rows = query(conn, 'SELECT balance FROM accounts WHERE name=%s', (name,))
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

        rows = query(conn, 'SELECT balance FROM accounts WHERE name=%s', (name,))
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
            execute(conn, 'UPDATE accounts SET balance=%s WHERE name=%s', (new_bal, name))
            execute(conn,
                'INSERT INTO history (time, name, amount) VALUES (%s, %s, %s)',
                (timestamp, name, -amt))
            flash(f'Successfully withdrawn ₹{amt:,}.', 'success')
        except Exception as e:
            flash(f'Transaction failed: {e}', 'error')
        finally:
            conn.close()
        return redirect(url_for('dashboard'))

    rows = query(conn, 'SELECT balance FROM accounts WHERE name=%s', (name,))
    balance = rows[0]['balance'] if rows else 0
    conn.close()
    return render_template('withdraw.html', name=name, balance=balance)

@app.route('/history')
@login_required
def history():
    name = session['user']
    conn = get_db()
    rows = query(conn,
        'SELECT time, amount FROM history WHERE name=%s ORDER BY time DESC',
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
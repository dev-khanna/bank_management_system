from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timezone
import psycopg2
import psycopg2.extras
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-fallback-key')

DB_URL = os.environ.get('DATABASE_URL')  # set this in Vercel env vars

# ── Database connection ───────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DB_URL, cursor_factory=psycopg2.extras.RealDictCursor)
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            name TEXT UNIQUE NOT NULL,
            pwd_hash BYTEA,
            balance INTEGER DEFAULT 0
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS history (
            time TEXT,
            name TEXT,
            amount INTEGER
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS pwd_meta (
            name TEXT UNIQUE NOT NULL,
            pwd_rounds INTEGER
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            name TEXT UNIQUE NOT NULL,
            attempts INTEGER,
            last_attempt TEXT
        )
    ''')
    conn.commit()
    cur.close()
    conn.close()

init_db()

# ── Password helpers ──────────────────────────────────────────────────────────
def hash_pwd(password: str, rounds: int = 12) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds))

def check_pwd(password: str, hashed: bytes) -> bool:
    if isinstance(hashed, memoryview):
        hashed = bytes(hashed)
    return bcrypt.checkpw(password.encode(), hashed)

# ── Auth helpers ──────────────────────────────────────────────────────────────
MAX_ATTEMPTS = 3
LOCKOUT_MINS = 5
MIN_ROUNDS   = 14

def is_locked(conn, name: str) -> bool:
    cur = conn.cursor()
    cur.execute('SELECT attempts, last_attempt FROM login_attempts WHERE name=%s', (name,))
    row = cur.fetchone()
    cur.close()
    if not row or row['attempts'] < MAX_ATTEMPTS:
        return False
    elapsed = (datetime.now() - datetime.fromisoformat(row['last_attempt'])).total_seconds() / 60
    if elapsed < LOCKOUT_MINS:
        return True
    cur = conn.cursor()
    cur.execute('DELETE FROM login_attempts WHERE name=%s', (name,))
    conn.commit()
    cur.close()
    return False

def track_attempt(conn, name: str):
    now = datetime.now().isoformat()
    cur = conn.cursor()
    cur.execute('SELECT attempts FROM login_attempts WHERE name=%s', (name,))
    existing = cur.fetchone()
    if existing:
        cur.execute(
            'UPDATE login_attempts SET attempts=%s, last_attempt=%s WHERE name=%s',
            (existing['attempts'] + 1, now, name)
        )
    else:
        cur.execute(
            'INSERT INTO login_attempts VALUES (%s, 1, %s)', (name, now)
        )
    conn.commit()
    cur.close()

def remaining_attempts(conn, name: str) -> int:
    cur = conn.cursor()
    cur.execute('SELECT attempts FROM login_attempts WHERE name=%s', (name,))
    row = cur.fetchone()
    cur.close()
    return MAX_ATTEMPTS - (row['attempts'] if row else 0)

def upgrade_hash(conn, name: str, password: str):
    cur = conn.cursor()
    cur.execute('SELECT pwd_rounds FROM pwd_meta WHERE name=%s', (name,))
    row = cur.fetchone()
    current = row['pwd_rounds'] if row else 12
    if current < MIN_ROUNDS:
        new_hash = hash_pwd(password, MIN_ROUNDS)
        try:
            cur.execute('UPDATE accounts SET pwd_hash=%s WHERE name=%s', (new_hash, name))
            cur.execute('UPDATE pwd_meta SET pwd_rounds=%s WHERE name=%s', (MIN_ROUNDS, name))
            conn.commit()
        except Exception:
            conn.rollback()
    cur.close()

# ── Auth guard ────────────────────────────────────────────────────────────────
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ── Routes ────────────────────────────────────────────────────────────────────
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

        cur = conn.cursor()
        cur.execute('SELECT pwd_hash FROM accounts WHERE name=%s', (name,))
        row = cur.fetchone()
        cur.close()

        if not row:
            flash('User not found. Please register first.', 'error')
            conn.close()
            return redirect(url_for('login'))

        stored = bytes(row['pwd_hash']) if isinstance(row['pwd_hash'], memoryview) else row['pwd_hash']
        if not check_pwd(password, stored):
            track_attempt(conn, name)
            rem = remaining_attempts(conn, name)
            if rem > 0:
                flash(f'Incorrect password. {rem} attempt(s) remaining.', 'error')
            else:
                flash('Account locked after too many failed attempts.', 'error')
            conn.close()
            return redirect(url_for('login'))

        cur = conn.cursor()
        cur.execute('DELETE FROM login_attempts WHERE name=%s', (name,))
        conn.commit()
        cur.close()
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

        cur = conn.cursor()
        cur.execute('SELECT name FROM accounts WHERE name=%s', (name,))
        existing = cur.fetchone()
        cur.close()

        if existing:
            flash('Username already taken. Please log in instead.', 'error')
            conn.close()
            return redirect(url_for('register'))

        pwd_hash = hash_pwd(password)
        try:
            cur = conn.cursor()
            cur.execute('INSERT INTO accounts (name, pwd_hash, balance) VALUES (%s, %s, 0)', (name, pwd_hash))
            cur.execute('INSERT INTO pwd_meta (name, pwd_rounds) VALUES (%s, 12)', (name,))
            conn.commit()
            cur.close()
            flash('Registered successfully. Please log in.', 'success')
        except Exception as e:
            conn.rollback()
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
    cur = conn.cursor()

    cur.execute('SELECT balance FROM accounts WHERE name=%s', (name,))
    row = cur.fetchone()
    balance = row['balance'] if row else 0

    cur.execute(
        'SELECT time, amount FROM history WHERE name=%s ORDER BY time DESC LIMIT 5',
        (name,)
    )
    history = cur.fetchall()
    cur.close()
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

        cur = conn.cursor()
        cur.execute('SELECT balance FROM accounts WHERE name=%s', (name,))
        row = cur.fetchone()
        new_bal = row['balance'] + amt
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            cur.execute('UPDATE accounts SET balance=%s WHERE name=%s', (new_bal, name))
            cur.execute('INSERT INTO history (time, name, amount) VALUES (%s, %s, %s)', (timestamp, name, amt))
            conn.commit()
            flash(f'Successfully deposited ₹{amt:,}.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Transaction failed: {e}', 'error')
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('dashboard'))

    cur = conn.cursor()
    cur.execute('SELECT balance FROM accounts WHERE name=%s', (name,))
    row = cur.fetchone()
    balance = row['balance'] if row else 0
    cur.close()
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

        cur = conn.cursor()
        cur.execute('SELECT balance FROM accounts WHERE name=%s', (name,))
        row = cur.fetchone()
        balance = row['balance'] if row else 0
        cur.close()

        if amt <= 0:
            flash('Amount must be positive.', 'error')
            conn.close()
            return redirect(url_for('withdraw'))
        if amt > balance:
            flash(f'Insufficient funds. Your balance is ₹{balance:,}.', 'error')
            conn.close()
            return redirect(url_for('withdraw'))

        new_bal = balance - amt
        timestamp = datetime.now(timezone.utc).isoformat()
        cur = conn.cursor()
        try:
            cur.execute('UPDATE accounts SET balance=%s WHERE name=%s', (new_bal, name))
            cur.execute('INSERT INTO history (time, name, amount) VALUES (%s, %s, %s)', (timestamp, name, -amt))
            conn.commit()
            flash(f'Successfully withdrawn ₹{amt:,}.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Transaction failed: {e}', 'error')
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('dashboard'))

    cur = conn.cursor()
    cur.execute('SELECT balance FROM accounts WHERE name=%s', (name,))
    row = cur.fetchone()
    balance = row['balance'] if row else 0
    cur.close()
    conn.close()
    return render_template('withdraw.html', name=name, balance=balance)

@app.route('/history')
@login_required
def history():
    name = session['user']
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        'SELECT time, amount FROM history WHERE name=%s ORDER BY time DESC',
        (name,)
    )
    rows = cur.fetchall()
    cur.close()
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
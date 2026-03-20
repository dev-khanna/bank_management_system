from flask import Flask, render_template, request, redirect, url_for, session, flash
from datetime import datetime, timezone
import sqlite3
import bcrypt
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback-dev-key')  

DB_PATH = '/data/BANKING_SESSION.db'

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.execute('CREATE TABLE IF NOT EXISTS accounts (name TEXT UNIQUE, pwd_hash, balance)')
    db.execute('CREATE TABLE IF NOT EXISTS history  (time, name, amount)')
    db.execute('CREATE TABLE IF NOT EXISTS pwd_meta (name TEXT UNIQUE, pwd_rounds)')
    db.execute('CREATE TABLE IF NOT EXISTS login_attempts (name TEXT UNIQUE, attempts INT, last_attempt TEXT)')
    db.commit()
    db.close()

init_db()

def hash_pwd(password: str, rounds: int = 12) -> bytes:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds))

def check_pwd(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

MAX_ATTEMPTS  = 3
LOCKOUT_MINS  = 5
MIN_ROUNDS    = 14

def is_locked(db, name: str) -> bool:
    row = db.execute('SELECT attempts, last_attempt FROM login_attempts WHERE name=?', (name,)).fetchone()
    if not row or row['attempts'] < MAX_ATTEMPTS:
        return False
    elapsed = (datetime.now() - datetime.fromisoformat(row['last_attempt'])).total_seconds() / 60
    if elapsed < LOCKOUT_MINS:
        return True
    db.execute('DELETE FROM login_attempts WHERE name=?', (name,))
    db.commit()
    return False

def track_attempt(db, name: str):
    now = datetime.now().isoformat()
    existing = db.execute('SELECT attempts FROM login_attempts WHERE name=?', (name,)).fetchone()
    if existing:
        db.execute('UPDATE login_attempts SET attempts=?, last_attempt=? WHERE name=?',
                   (existing['attempts'] + 1, now, name))
    else:
        db.execute('INSERT INTO login_attempts VALUES (?, 1, ?)', (name, now))
    db.commit()

def remaining_attempts(db, name: str) -> int:
    row = db.execute('SELECT attempts FROM login_attempts WHERE name=?', (name,)).fetchone()
    return MAX_ATTEMPTS - (row['attempts'] if row else 0)

def upgrade_hash(db, name: str, password: str):
    row = db.execute('SELECT pwd_rounds FROM pwd_meta WHERE name=?', (name,)).fetchone()
    current = row['pwd_rounds'] if row else 12
    if current < MIN_ROUNDS:
        new_hash = hash_pwd(password, MIN_ROUNDS)
        try:
            db.execute('UPDATE accounts SET pwd_hash=? WHERE name=?', (new_hash, name))
            db.execute('UPDATE pwd_meta  SET pwd_rounds=? WHERE name=?', (MIN_ROUNDS, name))
            db.commit()
        except Exception:
            db.rollback()

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
        db = get_db()

        if is_locked(db, name):
            flash(f'Account locked. Too many failed attempts. Try again in {LOCKOUT_MINS} minutes.', 'error')
            db.close()
            return redirect(url_for('login'))

        row = db.execute('SELECT pwd_hash FROM accounts WHERE name=?', (name,)).fetchone()
        if not row:
            flash('User not found. Please register first.', 'error')
            db.close()
            return redirect(url_for('login'))

        stored = bytes(row['pwd_hash']) if isinstance(row['pwd_hash'], memoryview) else row['pwd_hash']
        if not check_pwd(password, stored):
            track_attempt(db, name)
            rem = remaining_attempts(db, name)
            if rem > 0:
                flash(f'Incorrect password. {rem} attempt(s) remaining.', 'error')
            else:
                flash('Account locked after too many failed attempts.', 'error')
            db.close()
            return redirect(url_for('login'))

        db.execute('DELETE FROM login_attempts WHERE name=?', (name,))
        db.commit()
        upgrade_hash(db, name, password)
        db.close()
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
        db = get_db()

        if not name:
            flash('Username cannot be empty.', 'error')
            db.close()
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters.', 'error')
            db.close()
            return redirect(url_for('register'))

        existing = db.execute('SELECT name FROM accounts WHERE name=?', (name,)).fetchone()
        if existing:
            flash('Username already taken. Please log in instead.', 'error')
            db.close()
            return redirect(url_for('register'))

        pwd_hash = hash_pwd(password)
        try:
            db.execute('INSERT INTO accounts VALUES (?, ?, ?)', (name, pwd_hash, 0))
            db.execute('INSERT INTO pwd_meta   VALUES (?, ?)', (name, 12))
            db.commit()
            flash('Registered successfully. Please log in.', 'success')
        except Exception as e:
            db.rollback()
            flash(f'Registration failed: {e}', 'error')
        finally:
            db.close()

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
    db = get_db()
    row = db.execute('SELECT balance FROM accounts WHERE name=?', (name,)).fetchone()
    balance = row['balance'] if row else 0
    history = db.execute(
        'SELECT time, amount FROM history WHERE name=? ORDER BY time DESC LIMIT 5',
        (name,)
    ).fetchall()
    db.close()

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
    db = get_db()

    if request.method == 'POST':
        try:
            amt = int(request.form.get('amount', 0))
        except ValueError:
            flash('Invalid amount.', 'error')
            db.close()
            return redirect(url_for('deposit'))

        if amt <= 0:
            flash('Amount must be positive.', 'error')
            db.close()
            return redirect(url_for('deposit'))

        row = db.execute('SELECT balance FROM accounts WHERE name=?', (name,)).fetchone()
        new_bal = row['balance'] + amt
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            db.execute('UPDATE accounts SET balance=? WHERE name=?', (new_bal, name))
            db.execute('INSERT INTO history VALUES (?, ?, ?)', (timestamp, name, amt))
            db.commit()
            flash(f'Successfully deposited ₹{amt:,}.', 'success')
        except Exception as e:
            db.rollback()
            flash(f'Transaction failed: {e}', 'error')
        db.close()
        return redirect(url_for('dashboard'))

    row = db.execute('SELECT balance FROM accounts WHERE name=?', (name,)).fetchone()
    balance = row['balance'] if row else 0
    db.close()
    return render_template('deposit.html', name=name, balance=balance)

@app.route('/withdraw', methods=['GET', 'POST'])
@login_required
def withdraw():
    name = session['user']
    db = get_db()

    if request.method == 'POST':
        try:
            amt = int(request.form.get('amount', 0))
        except ValueError:
            flash('Invalid amount.', 'error')
            db.close()
            return redirect(url_for('withdraw'))

        row = db.execute('SELECT balance FROM accounts WHERE name=?', (name,)).fetchone()
        balance = row['balance'] if row else 0

        if amt <= 0:
            flash('Amount must be positive.', 'error')
            db.close()
            return redirect(url_for('withdraw'))
        if amt > balance:
            flash(f'Insufficient funds. Your balance is ₹{balance:,}.', 'error')
            db.close()
            return redirect(url_for('withdraw'))

        new_bal = balance - amt
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            db.execute('UPDATE accounts SET balance=? WHERE name=?', (new_bal, name))
            db.execute('INSERT INTO history VALUES (?, ?, ?)', (timestamp, name, -amt))
            db.commit()
            flash(f'Successfully withdrawn ₹{amt:,}.', 'success')
        except Exception as e:
            db.rollback()
            flash(f'Transaction failed: {e}', 'error')
        db.close()
        return redirect(url_for('dashboard'))

    row = db.execute('SELECT balance FROM accounts WHERE name=?', (name,)).fetchone()
    balance = row['balance'] if row else 0
    db.close()
    return render_template('withdraw.html', name=name, balance=balance)

@app.route('/history')
@login_required
def history():
    name = session['user']
    db = get_db()
    rows = db.execute(
        'SELECT time, amount FROM history WHERE name=? ORDER BY time DESC',
        (name,)
    ).fetchall()
    db.close()

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
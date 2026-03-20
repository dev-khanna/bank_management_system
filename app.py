from datetime import datetime, timezone
import sqlite3
import bcrypt
from typing import Tuple


db = sqlite3.connect('BANKING_SESSION.db')

db.execute('CREATE TABLE IF NOT EXISTS accounts (name UNIQUE, pwd_hash, balance)')
db.execute('CREATE TABLE IF NOT EXISTS history  (time, name, amount)')
db.execute('CREATE TABLE IF NOT EXISTS pwd_meta (name UNIQUE, pwd_rounds)')   
db.execute('CREATE TABLE IF NOT EXISTS login_attempts (name TEXT UNIQUE, attempts INT, last_attempt TEXT)')

db.commit()


def hash_pwd(password: str, rounds: int = 12) -> bytes:
    """Hash a plaintext password with bcrypt (salt included automatically)."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds))


def check_pwd(password: str, hashed: bytes) -> bool:
    """Return True if *password* matches the stored bcrypt hash."""
    return bcrypt.checkpw(password.encode(), hashed)


class AuthManager:
    """Handles password verification, lockout, and hash upgrades.

    Works directly against the SQLite database so state survives across
    sessions (unlike the in-memory dict in the standalone demo).
    """

    MAX_ATTEMPTS   = 3
    LOCKOUT_MINS   = 5
    MIN_ROUNDS     = 14   

    def __init__(self):
        self._attempts: dict[str, tuple[int, datetime]] = {}

    def register(self, name: str, password: str) -> bool:
        """Insert a new user with a hashed password. Returns False if name taken."""
        if not name.strip():
            print("Username cannot be empty.")
            return False
        cursor = db.cursor()
        cursor.execute('SELECT name FROM accounts WHERE name=?', (name,))
        if cursor.fetchone():
            cursor.close()
            return False

        pwd_hash = hash_pwd(password)
        try:
            cursor.execute('INSERT INTO accounts VALUES (?, ?, ?)', (name, pwd_hash, 0))
            cursor.execute('INSERT INTO pwd_meta   VALUES (?, ?)',  (name, 12))
            db.commit()
        except sqlite3.Error as e:
            db.rollback()
            print(f"Registration failed: {e}")
            return False
        cursor.close()
        return True

    def login(self, name: str, password: str) -> Tuple[bool, str]:
        """Verify credentials. Returns (success, message)."""
        if self._is_locked(name):
            mins = self.LOCKOUT_MINS
            return False, f"Account locked after {self.MAX_ATTEMPTS} failed attempts. Try again in {mins} minutes."

        cursor = db.cursor()
        cursor.execute('SELECT pwd_hash FROM accounts WHERE name=?', (name,))
        row = cursor.fetchone()
        cursor.close()

        if not row:
            return False, "User not found. Please register first."

        stored_hash = row[0]
        if isinstance(stored_hash, memoryview):
            stored_hash = bytes(stored_hash)

        if not check_pwd(password, stored_hash):
            self._track_attempt(name)
            remaining = self.MAX_ATTEMPTS - self._attempts[name][0]
            if remaining > 0:
                return False, f"Incorrect password. {remaining} attempt(s) remaining."
            return False, f"Account locked. Too many failed attempts."

        self._attempts.pop(name, None)

        self._upgrade_hash(name, password)

        return True, "Logged in successfully!"

    def _is_locked(self, name: str) -> bool:
        if name not in self._attempts:
            return False
        attempts, last = self._attempts[name]
        if attempts >= self.MAX_ATTEMPTS:
            elapsed = (datetime.now() - last).total_seconds() / 60
            if elapsed < self.LOCKOUT_MINS:
                return True
            del self._attempts[name]   
        return False

    def _track_attempt(self, name: str) -> None:
        now = datetime.now()
        if name in self._attempts:
            count, _ = self._attempts[name]
            self._attempts[name] = (count + 1, now)
        else:
            self._attempts[name] = (1, now)

    def _upgrade_hash(self, name: str, password: str) -> None:
        cursor = db.cursor()
        cursor.execute('SELECT pwd_rounds FROM pwd_meta WHERE name=?', (name,))
        row = cursor.fetchone()
        current_rounds = row[0] if row else 12

        if current_rounds < self.MIN_ROUNDS:
            new_hash = hash_pwd(password, self.MIN_ROUNDS)
            try:
                cursor.execute('UPDATE accounts SET pwd_hash   = ? WHERE name=?', (new_hash, name))
                cursor.execute('UPDATE pwd_meta  SET pwd_rounds = ? WHERE name=?', (self.MIN_ROUNDS, name))
                db.commit()
            except sqlite3.Error as e:
                db.rollback()
                print(f"Hash upgrade failed: {e}")
        cursor.close()


class Accounts:

    def __init__(self, name: str) -> None:
        self.name = name
        cursor = db.cursor()
        cursor.execute('SELECT balance FROM accounts WHERE name=?', (self.name,))
        data = cursor.fetchone()
        self._bal = data[0] if data else 0
        cursor.close()

    def save_update(self, amt: int) -> None:
        new_bal   = self._bal + amt
        timestamp = datetime.now(timezone.utc).isoformat()
        cursor    = db.cursor()
        try:
            cursor.execute('UPDATE accounts SET balance = ? WHERE name=?', (new_bal, self.name))
            cursor.execute('INSERT INTO history VALUES (?, ?, ?)', (timestamp, self.name, amt))
        except sqlite3.Error as e:
            db.rollback()
            print(f"Transaction failed. Error: {e}")
        else:
            db.commit()
            self._bal = new_bal
            if amt > 0:
                print(f"{amt} deposited successfully.")
            else:
                print(f"{-amt} withdrawn successfully.")
        finally:
            cursor.close()

    def deposit(self, amt: int) -> None:
        if amt < 0:
            print("Unsuccessful. Negative amounts cannot be deposited.")
            return
        self.save_update(amt)

    def withdraw(self, amt: int) -> None:
        if amt < 0:
            print("Unsuccessful. Negative amounts cannot be withdrawn.")
            return
        if amt > self._bal:
            print(f"Unsuccessful. You cannot withdraw more than your balance [{self._bal}].")
            return
        self.save_update(-amt)

    def show_bal(self) -> None:
        print(f"Name: {self.name} | Balance: {self._bal}")

    def view_history(self) -> None:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM history WHERE name=?', (self.name,))
        data = cursor.fetchall()
        cursor.close()

        if not data:
            print("No transaction history found.")
            return

        for time_str, name, amount in data:
            utc_dt = datetime.fromisoformat(time_str)
            state  = "Deposited" if amount > 0 else "Withdrawn"
            print(f"Name: {name}\t|\tTime: {utc_dt}\t|\tAmount: {amount}\t|\t{state}")


if __name__ == "__main__":
    auth = AuthManager()

    while True:
        print("\n1. Register\n2. Login\n0. Exit")
        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("Please enter a number.")
            continue

        if choice == 1:                         
            name     = input("Enter your name: ")
            password = input("Create a password: ")

            if auth.register(name, password):
                print("Registered successfully. Please log in.")
            else:
                print("Name already taken. Please log in instead.")

        elif choice == 2:                       
            name     = input("Enter your name: ")
            password = input("Enter your password: ")

            success, msg = auth.login(name, password)
            print(msg)

            if success:
                account = Accounts(name)
                while True:
                    print("\n1. Deposit\n2. Withdraw\n3. View Balance\n4. View Transaction History\n0. Logout")
                    try:
                        action = int(input("What would you like to do? "))
                    except ValueError:
                        print("Please enter a number.")
                        continue

                    if action == 1:
                        try:
                            amt = int(input("Amount to deposit: "))
                            account.deposit(amt)
                        except ValueError:
                            print("Invalid amount.")
                    elif action == 2:
                        try:
                            amt = int(input("Amount to withdraw: "))
                            account.withdraw(amt)
                        except ValueError:
                            print("Invalid amount.")
                    elif action == 3:
                        account.show_bal()
                    elif action == 4:
                        account.view_history()
                    elif action == 0:
                        print("Logged out.")
                        break
                    else:
                        print("Invalid choice. Try again.")

        elif choice == 0:
            print("Goodbye.")
            break
        else:
            print("Invalid choice. Please try again.")

    db.commit()
    db.close()
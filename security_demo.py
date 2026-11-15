"""Local-only teaching demo: role permissions and SQL injection prevention."""
import argparse
import hashlib
import hmac
import os
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).with_name('demo.db')
ROLES = {'viewer': {'read'}, 'editor': {'read', 'update'}, 'admin': {'read', 'update'}}


def connect(path=DB_PATH):
    return sqlite3.connect(path)


def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 300_000)
    return salt.hex() + ':' + digest.hex()


def verify_password(password, stored):
    salt_hex, digest_hex = stored.split(':')
    candidate = hash_password(password, bytes.fromhex(salt_hex)).split(':')[1]
    return hmac.compare_digest(candidate, digest_hex)


def setup(path=DB_PATH):
    with connect(path) as db:
        db.executescript('''
            DROP TABLE IF EXISTS accounts;
            DROP TABLE IF EXISTS users;
            CREATE TABLE users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                                role TEXT NOT NULL CHECK(role IN ('viewer','editor','admin')));
            CREATE TABLE accounts (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, balance INTEGER NOT NULL);
        ''')
        db.executemany('INSERT INTO users VALUES (?, ?, ?)', [
            ('alice', hash_password('alice-demo-password'), 'viewer'),
            ('bob', hash_password('bob-demo-password'), 'editor'),
            ('carol', hash_password('carol-demo-password'), 'admin')])
        db.executemany('INSERT INTO accounts VALUES (?, ?, ?)',
                       [(1, 'alice', 100), (2, 'bob', 250), (3, 'carol', 500)])


def authenticate(db, username, password):
    row = db.execute('SELECT password_hash, role FROM users WHERE username = ?', (username,)).fetchone()
    if not row or not verify_password(password, row[0]):
        raise PermissionError('Invalid credentials')
    return row[1]


def authorize(role, action):
    if action not in ROLES.get(role, set()):
        raise PermissionError(f'{role} cannot perform {action}')


def safe_lookup(db, role, owner):
    authorize(role, 'read')
    return db.execute('SELECT id, owner, balance FROM accounts WHERE owner = ?', (owner,)).fetchall()


def unsafe_lookup(db, role, owner):
    """Intentionally vulnerable; for the local before/after experiment ONLY."""
    authorize(role, 'read')
    return db.execute("SELECT id, owner, balance FROM accounts WHERE owner = '" + owner + "'").fetchall()


def update_balance(db, role, account_id, balance):
    authorize(role, 'update')
    if balance < 0:
        raise ValueError('Balance must not be negative')
    with db:
        cursor = db.execute('UPDATE accounts SET balance = ? WHERE id = ?', (balance, account_id))
    return cursor.rowcount


def run_demo(path=DB_PATH):
    setup(path)
    injection = "alice' OR '1'='1"
    with connect(path) as db:
        viewer = authenticate(db, 'alice', 'alice-demo-password')
        print('BEFORE - unsafe query returns', len(unsafe_lookup(db, viewer, injection)), 'rows')
        print('AFTER  - parameterized query returns', len(safe_lookup(db, viewer, injection)), 'rows')
        try:
            update_balance(db, viewer, 1, 999)
        except PermissionError:
            print('AFTER  - viewer unauthorized update: BLOCKED')
        editor = authenticate(db, 'bob', 'bob-demo-password')
        print('AFTER  - editor authorized update:', 'ALLOWED' if update_balance(db, editor, 1, 125) == 1 else 'FAILED')
        print('AFTER  - updated account:', safe_lookup(db, editor, 'alice'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--demo', action='store_true', help='reset local demo DB and run before/after experiment')
    args = parser.parse_args()
    if args.demo:
        run_demo()
    else:
        parser.print_help()

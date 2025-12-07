import sqlite3
import hashlib

DATABASE_NAME = 'pharma.db'

def create_connection():
    try:
        conn = sqlite3.connect(DATABASE_NAME)
        # CRITICAL FIX: This enables accessing columns by name (e.g., row['drug_a'])
        conn.row_factory = sqlite3.Row 
        return conn
    except sqlite3.Error as e:
        print(f"FATAL ERROR: {e}")
        return None

def setup_database(conn):
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Users (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)
    # Fix: Ensure timestamp column exists
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS Interaction_Log (
            log_id INTEGER PRIMARY KEY,
            user_id INTEGER,
            drug_a TEXT NOT NULL,
            drug_b TEXT NOT NULL,
            severity TEXT,
            summary TEXT,
            timestamp TEXT,
            FOREIGN KEY(user_id) REFERENCES Users(user_id)
        )
    """)
    conn.commit()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(conn, username, password):
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    try:
        cursor.execute("INSERT INTO Users (username, password_hash) VALUES (?, ?)", (username, pwd_hash))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def authenticate_user(conn, username, password):
    cursor = conn.cursor()
    pwd_hash = hash_password(password)
    cursor.execute("SELECT user_id FROM Users WHERE username = ? AND password_hash = ?", (username, pwd_hash))
    user = cursor.fetchone()
    if user:
        return user['user_id']
    return None

def log_interaction(conn, user_id, drug_a, drug_b, severity, summary, timestamp):
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO Interaction_Log (user_id, drug_a, drug_b, severity, summary, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user_id, drug_a, drug_b, severity, summary, timestamp))
    conn.commit()

def get_user_history(conn, user_id):
    cursor = conn.cursor()
    cursor.execute("""
        SELECT timestamp, drug_a, drug_b, severity, summary 
        FROM Interaction_Log 
        WHERE user_id = ? 
        ORDER BY log_id DESC
    """, (user_id,))
    # Returns a list of Row objects
    return cursor.fetchall()
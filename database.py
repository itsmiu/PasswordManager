# database.py

import sqlite3

DATABASE_NAME = "passwords.db"

def get_db_connection():
    return sqlite3.connect(DATABASE_NAME)

def create_table():
    connection = get_db_connection()
    cursor = connection.cursor()

    # Create users table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            master_password_hash TEXT NOT NULL
        )
        """
    )

    # Create passwords table
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )

    connection.commit()
    connection.close()

def register_user(username, master_password_hash):
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            "INSERT INTO users (username, master_password_hash) VALUES (?, ?)",
            (username, master_password_hash)
        )
        connection.commit()
    except sqlite3.IntegrityError:
        return False  # Username already exists
    finally:
        connection.close()

    return True

def authenticate_user(username, master_password_hash):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND master_password_hash = ?",
        (username, master_password_hash)
    )
    user = cursor.fetchone()
    connection.close()

    return user is not None

def get_user_id(username):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    connection.close()

    if user:
        return user[0]
    return None

def add_password(user_id, name, username, encrypted_password):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        "INSERT INTO passwords (user_id, name, username, encrypted_password) VALUES (?, ?, ?, ?)",
        (user_id, name, username, encrypted_password)
    )
    connection.commit()
    connection.close()

def get_passwords(user_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM passwords WHERE user_id = ?", (user_id,))
    passwords = cursor.fetchall()
    connection.close()

    return passwords

def delete_password(password_id):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
    connection.commit()
    connection.close()

if __name__ == "__main__":
    create_table()
    print("Database and tables created successfully.")

# This file is the backend database manager for the application. It is responsible for managing the database connection and providing an interface for the application to interact with the database.
# Donot edit this file unless you are sure of what you are doing. Any changes made to this file should be reported.
#The intial prototype will be using SQLite as the database. However, the code is designed to be easily adaptable to other databases in the future.
# Gateway to 2 dbs : users, schedule 
import hashlib
import hmac
import os
import sqlite3


_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16


def hash_password(password):
    """Hash a password with a unique salt using memory-hard scrypt."""
    if not isinstance(password, str):
        raise TypeError("password must be a string")

    salt = os.urandom(_SALT_BYTES)
    derived_key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return "scrypt$%d$%d$%d$%s$%s" % (
        _SCRYPT_N,
        _SCRYPT_R,
        _SCRYPT_P,
        salt.hex(),
        derived_key.hex(),
    )


def verify_password(password, encoded_hash):
    """Verify a password against a scrypt hash using constant-time comparison."""
    if not isinstance(password, str) or not isinstance(encoded_hash, str):
        return False

    try:
        algorithm, n, r, p, salt_hex, expected_hex = encoded_hash.split("$")
        if algorithm != "scrypt":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
        return hmac.compare_digest(actual, expected)
    except (TypeError, ValueError, OverflowError):
        return False


def get_db_connection():
    """Establishes a connection to the SQLite database and returns the connection object."""
    try:
        # Connect to the SQLite database (or create it if it doesn't exist)
        conn = sqlite3.connect('database.db')
        conn.row_factory = sqlite3.Row  # Enable accessing columns by name
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None

def close_db_connection(conn):
    """Closes the database connection."""
    if conn:
        conn.close()

def initialize_database():
    """Initializes the database by creating necessary tables if they don't exist."""
    conn = get_db_connection()
    if conn is not None:
        try:
            cursor = conn.cursor()
            # Create a sample table (you can modify this to create your own tables)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    email TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            ''')
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
        finally:
            close_db_connection(conn)

def execute_query(query, params=None):
    """Executes a SQL query with optional parameters and returns the result."""
    conn = get_db_connection()
    if conn is not None:
        try:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return cursor.fetchall()  # Return all results
        except sqlite3.Error as e:
            print(f"Database query error: {e}")
            return None
        finally:
            close_db_connection(conn)



import sqlite3

def get_user(user_id):
    """Vulnerable: SQL injection via string formatting."""
    conn = sqlite3.connect('db.sqlite')
    # VULNERABLE: SQL Injection
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor = conn.execute(query)
    return cursor.fetchone()


def search_users(name):
    """Vulnerable: SQL injection via string concatenation."""
    conn = sqlite3.connect('db.sqlite')
    # VULNERABLE: SQL Injection
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor = conn.execute(query)
    return cursor.fetchall()

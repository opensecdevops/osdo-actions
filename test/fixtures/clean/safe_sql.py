import sqlite3

def get_user_safe(user_id):
    """Safe: SQL query using parameterized query."""
    conn = sqlite3.connect('db.sqlite')
    # SAFE: Parameterized query
    cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()


def search_users_safe(name):
    """Safe: SQL query using parameterized query."""
    conn = sqlite3.connect('db.sqlite')
    # SAFE: Parameterized query
    cursor = conn.execute("SELECT * FROM users WHERE name = ?", (name,))
    return cursor.fetchall()

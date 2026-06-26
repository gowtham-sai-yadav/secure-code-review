import sqlite3

from utils import hash_password

DB_PATH = "supportdesk.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            escalation_credits INTEGER NOT NULL DEFAULT 5
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            subject TEXT NOT NULL,
            body TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            priority TEXT NOT NULL DEFAULT 'normal'
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            author TEXT NOT NULL,
            body TEXT NOT NULL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            fingerprint TEXT
        )
        """
    )
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        users = [
            ("alice", hash_password("alice123"), "user", 5),
            ("bob", hash_password("bob123"), "user", 5),
            ("carol", hash_password("carol123"), "admin", 10),
        ]
        cur.executemany(
            "INSERT INTO users (username, password_hash, role, escalation_credits) VALUES (?, ?, ?, ?)",
            users,
        )
        cur.execute(
            "INSERT INTO tickets (owner_id, subject, body, status, priority) VALUES (?, ?, ?, ?, ?)",
            (1, "VPN drops every afternoon", "Connection resets around 3pm daily.", "open", "normal"),
        )
        cur.execute(
            "INSERT INTO tickets (owner_id, subject, body, status, priority) VALUES (?, ?, ?, ?, ?)",
            (2, "Laptop won't boot", "Black screen after the login chime.", "open", "high"),
        )
        cur.execute(
            "INSERT INTO attachments (ticket_id, filename, fingerprint) VALUES (?, ?, ?)",
            (2, "boot_log.txt", "seed-fingerprint-not-real"),
        )
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def get_ticket(ticket_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    conn.close()
    return row


def list_tickets_for_user(user_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM tickets WHERE owner_id = ?", (user_id,)).fetchall()
    conn.close()
    return rows


def search_tickets(term):
    conn = get_connection()
    sql = "SELECT * FROM tickets WHERE subject LIKE '%" + term + "%'"
    rows = conn.execute(sql).fetchall()
    conn.close()
    return rows


STATUS_COLUMNS = {
    "open": "open",
    "closed": "closed",
    "pending": "pending",
}


def tickets_by_status(status):
    column = STATUS_COLUMNS.get(status)
    if column is None:
        return None
    conn = get_connection()
    sql = "SELECT * FROM tickets WHERE status = '{}'".format(column)
    rows = conn.execute(sql).fetchall()
    conn.close()
    return rows


def add_comment(ticket_id, author, body):
    conn = get_connection()
    conn.execute("INSERT INTO comments (ticket_id, author, body) VALUES (?, ?, ?)", (ticket_id, author, body))
    conn.commit()
    conn.close()


def get_comments(ticket_id):
    conn = get_connection()
    rows = conn.execute("SELECT * FROM comments WHERE ticket_id = ?", (ticket_id,)).fetchall()
    conn.close()
    return rows


def get_attachment(ticket_id, filename):
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM attachments WHERE ticket_id = ? AND filename = ?", (ticket_id, filename)
    ).fetchone()
    conn.close()
    return row


def add_attachment(ticket_id, filename, fingerprint):
    conn = get_connection()
    conn.execute(
        "INSERT INTO attachments (ticket_id, filename, fingerprint) VALUES (?, ?, ?)",
        (ticket_id, filename, fingerprint),
    )
    conn.commit()
    conn.close()


def find_attachment_by_fingerprint(fingerprint):
    conn = get_connection()
    row = conn.execute("SELECT * FROM attachments WHERE fingerprint = ?", (fingerprint,)).fetchone()
    conn.close()
    return row


def get_credits(user_id):
    conn = get_connection()
    row = conn.execute("SELECT escalation_credits FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row["escalation_credits"] if row else None


def set_credits(user_id, value):
    conn = get_connection()
    conn.execute("UPDATE users SET escalation_credits = ? WHERE id = ?", (value, user_id))
    conn.commit()
    conn.close()


def set_priority(ticket_id, priority):
    conn = get_connection()
    conn.execute("UPDATE tickets SET priority = ? WHERE id = ?", (priority, ticket_id))
    conn.commit()
    conn.close()


def all_tickets():
    conn = get_connection()
    rows = conn.execute(
        "SELECT tickets.*, users.username FROM tickets JOIN users ON tickets.owner_id = users.id"
    ).fetchall()
    conn.close()
    return rows

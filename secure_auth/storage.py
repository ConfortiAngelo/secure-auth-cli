"""SQLite persistence for user accounts.

Every query uses ``?`` placeholders, so user input is always sent to SQLite
as data and never concatenated into the SQL text.
"""

import sqlite3
from contextlib import closing
from pathlib import Path

DEFAULT_DB_PATH = Path("users.db")


class UserStore:
    """Stores usernames and their Argon2 password hashes."""

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = str(db_path)
        self._init_schema()

    def _connect(self):
        return closing(sqlite3.connect(self.db_path))

    def _init_schema(self) -> None:
        with self._connect() as conn, conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS users ("
                " name TEXT PRIMARY KEY,"
                " password_hash TEXT NOT NULL)"
            )

    def add_user(self, name: str, password_hash: str) -> bool:
        """Insert a user. Return False if the name is already taken."""
        try:
            with self._connect() as conn, conn:
                conn.execute(
                    "INSERT INTO users (name, password_hash) VALUES (?, ?)",
                    (name, password_hash),
                )
        except sqlite3.IntegrityError:
            return False
        return True

    def get_password_hash(self, name: str) -> str | None:
        """Return the stored hash for ``name``, or None if the user does not exist."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT password_hash FROM users WHERE name = ?", (name,)
            ).fetchone()
        return row[0] if row else None

    def update_password_hash(self, name: str, password_hash: str) -> None:
        with self._connect() as conn, conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE name = ?",
                (password_hash, name),
            )

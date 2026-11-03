"""User storage and password/token helpers for the authentication API."""

import base64
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from typing import Dict, Optional

PASSWORD_ITERATIONS = 260000
TOKEN_TTL_SECONDS = 3600
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_DEVELOPMENT_SECRET = "development-only-change-me"


class AuthError(Exception):
    """Expected authentication or input error with an HTTP status."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class UserStore:
    """SQLite-backed user store. Connections are short-lived per operation."""

    def __init__(self, database_path: str) -> None:
        self.database_path = database_path
        with self._connection() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self):
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _hash_password(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
        )

    def register(self, username: str, email: str, password: str) -> Dict[str, object]:
        username = username.strip()
        email = email.strip().lower()
        if not USERNAME_RE.fullmatch(username):
            raise AuthError("Username must be 3-32 letters, digits, dots, dashes, or underscores.")
        if len(email) > 254 or not EMAIL_RE.fullmatch(email):
            raise AuthError("A valid email address is required.")
        if len(password) < 8 or len(password) > 1024:
            raise AuthError("Password must be between 8 and 1024 characters.")

        salt = secrets.token_bytes(16)
        password_hash = self._hash_password(password, salt)
        try:
            with self._connection() as connection:
                cursor = connection.execute(
                    "INSERT INTO users (username, email, password_salt, password_hash, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (username, email, salt.hex(), password_hash.hex(), int(time.time())),
                )
                user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise AuthError("Username or email is already registered.", 409)
        return {"id": user_id, "username": username, "email": email}

    def authenticate(self, email: str, password: str) -> Dict[str, object]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT id, username, email, password_salt, password_hash "
                "FROM users WHERE email = ? COLLATE NOCASE",
                (email.strip().lower(),),
            ).fetchone()
        if row is None:
            raise AuthError("Invalid email or password.", 401)
        salt = bytes.fromhex(row["password_salt"])
        candidate = self._hash_password(password, salt)
        if not hmac.compare_digest(candidate.hex(), row["password_hash"]):
            raise AuthError("Invalid email or password.", 401)
        return {"id": row["id"], "username": row["username"], "email": row["email"]}

    def get_user(self, user_id: int) -> Optional[Dict[str, object]]:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT id, username, email FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if row is None:
            return None
        return {"id": row["id"], "username": row["username"], "email": row["email"]}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def issue_token(user_id: int, secret: str, now: Optional[int] = None) -> str:
    issued_at = int(time.time()) if now is None else now
    payload = _b64url(json.dumps(
        {"sub": user_id, "iat": issued_at, "exp": issued_at + TOKEN_TTL_SECONDS},
        separators=(",", ":"),
    ).encode("utf-8"))
    signature = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).digest()
    return payload + "." + _b64url(signature)


def verify_token(token: str, secret: str, now: Optional[int] = None) -> int:
    try:
        payload_part, signature_part = token.split(".", 1)
        expected = hmac.new(
            secret.encode("utf-8"), payload_part.encode("ascii"), hashlib.sha256
        ).digest()
        padding = "=" * (-len(signature_part) % 4)
        actual = base64.urlsafe_b64decode(signature_part + padding)
        if not hmac.compare_digest(expected, actual):
            raise ValueError("signature")
        padding = "=" * (-len(payload_part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_part + padding).decode("utf-8"))
        current_time = int(time.time()) if now is None else now
        if not isinstance(payload.get("sub"), int) or payload["sub"] <= 0:
            raise ValueError("subject")
        if not isinstance(payload.get("exp"), int) or payload["exp"] <= current_time:
            raise ValueError("expiration")
        return payload["sub"]
    except (ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeError):
        raise AuthError("Invalid or expired access token.", 401)

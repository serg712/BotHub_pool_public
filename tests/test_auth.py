import io
import json
import os
import tempfile
import unittest

from app.auth import AuthError, TOKEN_TTL_SECONDS, UserStore, issue_token, verify_token
from app.main import create_app


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_dir.name, "users.sqlite3")
        self.store = UserStore(self.database_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_registration_normalizes_email_and_never_returns_password(self):
        user = self.store.register("alice", " Alice@Example.COM ", "correct-horse")
        self.assertEqual(user["email"], "alice@example.com")
        self.assertNotIn("password", user)
        with self.store._connection() as connection:
            row = connection.execute("SELECT password_salt, password_hash FROM users").fetchone()
        self.assertNotEqual(row["password_hash"], "correct-horse")
        self.assertNotEqual(row["password_salt"], "")

    def test_registration_rejects_invalid_fields_and_duplicates(self):
        for username, email, password in (
            ("ab", "alice@example.com", "correct-horse"),
            ("alice", "invalid", "correct-horse"),
            ("alice", "alice@example.com", "short"),
        ):
            with self.subTest(username=username, email=email):
                with self.assertRaises(AuthError):
                    self.store.register(username, email, password)
        self.store.register("alice", "alice@example.com", "correct-horse")
        with self.assertRaisesRegex(AuthError, "already registered"):
            self.store.register("other", "ALICE@example.com", "different-pass")

    def test_authentication_checks_password(self):
        self.store.register("alice", "alice@example.com", "correct-horse")
        self.assertEqual(self.store.authenticate("ALICE@example.com", "correct-horse")["username"], "alice")
        with self.assertRaises(AuthError) as error:
            self.store.authenticate("alice@example.com", "wrong-password")
        self.assertEqual(error.exception.status, 401)

    def test_tokens_are_signed_and_expire(self):
        token = issue_token(7, "secret", now=100)
        self.assertEqual(verify_token(token, "secret", now=101), 7)
        self.assertEqual(TOKEN_TTL_SECONDS, 3600)
        for bad_token, secret, now in ((token, "wrong", 101), (token, "secret", 3700)):
            with self.subTest(now=now):
                with self.assertRaises(AuthError):
                    verify_token(bad_token, secret, now=now)

    def test_api_registration_login_and_authenticated_identity(self):
        app = create_app(self.database_path, "test-secret")
        status, registration = self.request(app, "POST", "/api/auth/register", {
            "username": "alice", "email": "alice@example.com", "password": "correct-horse",
        })
        self.assertEqual(status, 201)
        self.assertEqual(registration["user"]["username"], "alice")
        self.assertNotIn("password", registration["user"])

        status, login = self.request(app, "POST", "/api/auth/login", {
            "email": "alice@example.com", "password": "correct-horse",
        })
        self.assertEqual(status, 200)
        self.assertEqual(login["token_type"], "Bearer")
        status, identity = self.request(app, "GET", "/api/auth/me", headers={
            "HTTP_AUTHORIZATION": "Bearer " + login["access_token"],
        })
        self.assertEqual(status, 200)
        self.assertEqual(identity["user"]["email"], "alice@example.com")

    def test_api_rejects_missing_or_invalid_authentication(self):
        app = create_app(self.database_path, "test-secret")
        status, _ = self.request(app, "GET", "/api/auth/me")
        self.assertEqual(status, 401)
        status, body = self.request(app, "POST", "/api/auth/login", {
            "email": "unknown@example.com", "password": "correct-horse",
        })
        self.assertEqual(status, 401)
        self.assertIn("error", body)
        status, _ = self.request(app, "POST", "/api/auth/register", raw_body=b"{")
        self.assertEqual(status, 400)

    @staticmethod
    def request(app, method, path, data=None, headers=None, raw_body=None):
        body = raw_body if raw_body is not None else (
            json.dumps(data).encode("utf-8") if data is not None else b""
        )
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "CONTENT_LENGTH": str(len(body)) if method == "POST" else "0",
            "wsgi.input": io.BytesIO(body),
        }
        environ.update(headers or {})
        result = {}

        def start_response(status, response_headers):
            result["status"] = int(status.split()[0])
            result["headers"] = dict(response_headers)

        response = b"".join(app(environ, start_response))
        return result["status"], json.loads(response.decode("utf-8"))


if __name__ == "__main__":
    unittest.main()

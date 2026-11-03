"""Minimal JSON WSGI API for user registration and authentication."""

import json
import os
from http import HTTPStatus
from typing import Callable, Iterable, Tuple
from wsgiref.simple_server import make_server

from .auth import AuthError, TOKEN_TTL_SECONDS, UserStore, _DEVELOPMENT_SECRET, issue_token, verify_token

MAX_BODY_BYTES = 1024 * 1024


def create_app(database_path: str = None, token_secret: str = None) -> Callable:
    database_path = database_path or os.environ.get("BOTHUB_DB_PATH", "bothub.sqlite3")
    token_secret = token_secret or os.environ.get("BOTHUB_TOKEN_SECRET", _DEVELOPMENT_SECRET)
    if os.environ.get("BOTHUB_ENV", "development").lower() == "production" and token_secret == _DEVELOPMENT_SECRET:
        raise RuntimeError("BOTHUB_TOKEN_SECRET must be configured in production.")
    users = UserStore(database_path)

    def respond(start_response, status: int, body: dict) -> Iterable[bytes]:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        start_response(
            "%d %s" % (status, HTTPStatus(status).phrase),
            [("Content-Type", "application/json; charset=utf-8"),
             ("Content-Length", str(len(payload))), ("Cache-Control", "no-store")],
        )
        return [payload]

    def app(environ, start_response):
        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "/")
        if method not in ("GET", "POST"):
            return respond(start_response, 405, {"error": "Method not allowed."})
        try:
            if method == "POST":
                try:
                    content_length = int(environ.get("CONTENT_LENGTH") or "0")
                except ValueError:
                    raise AuthError("Invalid content length.")
                if content_length <= 0 or content_length > MAX_BODY_BYTES:
                    raise AuthError("Request body must be between 1 byte and 1 MiB.", 413 if content_length > MAX_BODY_BYTES else 400)
                raw_body = environ["wsgi.input"].read(content_length)
                try:
                    data = json.loads(raw_body.decode("utf-8"))
                except (UnicodeError, json.JSONDecodeError):
                    raise AuthError("Request body must be valid JSON.")
                if not isinstance(data, dict):
                    raise AuthError("Request body must be a JSON object.")

                if path == "/api/auth/register":
                    required = ("username", "email", "password")
                    if any(not isinstance(data.get(key), str) for key in required):
                        raise AuthError("Username, email, and password are required.")
                    user = users.register(data["username"], data["email"], data["password"])
                    return respond(start_response, 201, {"user": user})
                if path == "/api/auth/login":
                    if not isinstance(data.get("email"), str) or not isinstance(data.get("password"), str):
                        raise AuthError("Email and password are required.")
                    user = users.authenticate(data["email"], data["password"])
                    token = issue_token(user["id"], token_secret)
                    return respond(start_response, 200, {
                        "access_token": token, "token_type": "Bearer",
                        "expires_in": TOKEN_TTL_SECONDS, "user": user,
                    })
                return respond(start_response, 404, {"error": "Not found."})

            if path == "/api/auth/me":
                authorization = environ.get("HTTP_AUTHORIZATION", "")
                parts = authorization.split()
                if len(parts) != 2 or parts[0].lower() != "bearer":
                    raise AuthError("Bearer access token required.", 401)
                user_id = verify_token(parts[1], token_secret)
                user = users.get_user(user_id)
                if user is None:
                    raise AuthError("User no longer exists.", 401)
                return respond(start_response, 200, {"user": user})
            if path == "/health":
                return respond(start_response, 200, {"status": "ok"})
            return respond(start_response, 404, {"error": "Not found."})
        except AuthError as error:
            return respond(start_response, error.status, {"error": str(error)})

    return app


def main() -> None:
    host = os.environ.get("BOTHUB_HOST", "127.0.0.1")
    port = int(os.environ.get("BOTHUB_PORT", "8000"))
    app = create_app()
    with make_server(host, port, app) as server:
        print("BotHub Pool auth API listening on %s:%d" % (host, port))
        server.serve_forever()


if __name__ == "__main__":
    main()

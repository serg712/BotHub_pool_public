# BotHub Pool

A small service for managing users and bot pool access.

## Authentication service

This repository currently provides a standard-library WSGI service with JSON endpoints for account registration, login, and bearer-token identity lookup.

### Run

```sh
python3 -m app
```

Set `BOTHUB_DB_PATH` to choose the SQLite database file and `BOTHUB_TOKEN_SECRET` to set the signing secret. The service refuses to start with the development secret when `BOTHUB_ENV=production`.

### Endpoints

- `POST /api/auth/register` with `{"username":"alice","email":"alice@example.com","password":"correct-horse"}`
- `POST /api/auth/login` with `{"email":"alice@example.com","password":"correct-horse"}`
- `GET /api/auth/me` with `Authorization: Bearer <access_token>`

Passwords are stored as PBKDF2-HMAC-SHA256 hashes with a per-user random salt. Access tokens are signed and expire after one hour. Set a long, random `BOTHUB_TOKEN_SECRET` in deployed environments.

### Tests

```sh
python3 -m unittest discover -s tests -v
```

# secure-auth-cli

A small Python CLI that registers and authenticates users, rebuilt after a security review of my own first version (2024), which had SQL injection, fast password hashing and a predictable password generator.

> Originally published as `Password-Manager`. It never stored third-party passwords; it is a user registration and login system, so it was renamed.

## Demo

```text
$ python -m secure_auth
1. Register
2. Log in
3. Generate a password
4. Exit
Choice: 2
Username: ' OR '1'='1
Password:
Invalid username or password (1/3).
```

## Security fixes

Each issue below was confirmed by running the original code, then fixed and covered by tests.

| # | Vulnerability in v1 | Evidence | Fix in v2 | Test |
|---|---|---|---|---|
| 1 | **SQL injection (CWE-89):** `f"SELECT * FROM Users WHERE name = '{name}'"` | `query_name("' OR '1'='1")` returned **2 of 2** users | `?` placeholders in every query | `tests/test_storage.py`, `tests/test_auth.py` |
| 2 | **Fast hash (CWE-916):** one round of salted SHA-256 | **~775,000** guesses/s on one CPU core of my laptop | Argon2id (`argon2-cffi`, RFC 9106 low-memory profile: 64 MiB, t=3, p=4): **~6.5** guesses/s on the same laptop | `tests/test_security.py` |
| 3 | **Predictable generator (CWE-338):** `random.choice` (Mersenne Twister) | Output can be predicted after enough samples | `secrets.choice` (OS CSPRNG) | `tests/test_password_generator.py` |
| 4 | **Non-constant-time compare (CWE-208):** `hash == hash` | — | `PasswordHasher.verify` (constant time) | `tests/test_security.py` |
| 5 | **User enumeration (CWE-204):** different messages for unknown user and wrong password | "Usuario no registrado" vs "Contraseña incorrecta" | One generic message; unknown users still pay one Argon2 verification | `tests/test_auth.py` |
| 6 | **Password echoed** on screen with `input()` | — | `getpass.getpass()` | `tests/test_cli.py` |

Functional bugs fixed on the way: the menu compared `input()` (a `str`) with `1` (an `int`), so **no option ever worked**; a wrong password crashed with `TypeError`; `requirements.txt` listed standard-library modules, so `pip install` failed; the "test" file was an interactive script.

## Architecture

```
secure_auth/
├── cli.py                 # menu, getpass, 3-attempt login loop
├── auth.py                # register / authenticate (no I/O, fully testable)
├── security.py            # Argon2id hash / verify / rehash
├── storage.py             # SQLite UserStore, parameterized queries only
└── password_generator.py  # secrets-based generator
tests/                     # 33 pytest tests
```

`auth.py` contains the rules and knows nothing about the terminal, so the security properties are tested directly, without simulating keyboard input.

## How to run

```bash
pip install -r requirements-dev.txt
python -m pytest            # 33 passed
python -m secure_auth       # optional: --db path/to/users.db
```

Requires Python 3.10+.

## Design decisions and limitations

- **Argon2id over bcrypt:** memory-hard, current OWASP recommendation, and the salt and parameters live inside the hash string, so stronger parameters can be applied later with `needs_rehash` on the next successful login.
- **Input validation is defense in depth, not the SQLi fix.** Usernames are restricted to `[A-Za-z0-9_.-]{3,32}`, but the storage layer is safe even for hostile strings (a test stores `' OR '1'='1` literally).
- **Limitations:** the 3-attempt limit resets every time the program starts, so it is not a real account lockout. The SQLite file is not encrypted. v1 hashes (SHA-256) are not migrated; those users must register again.

## With more time

- Persistent lockout with exponential backoff per account and per source.
- Check new passwords against known breaches (k-anonymity range API).
- Static analysis in CI (`bandit`, `ruff`) next to the tests.

## License

[MIT](LICENSE)

"""Interactive command-line interface."""

import argparse
import getpass

from .auth import RegistrationError, authenticate, register
from .password_generator import generate_password
from .storage import DEFAULT_DB_PATH, UserStore

MAX_LOGIN_ATTEMPTS = 3
MENU = "\n1. Register\n2. Log in\n3. Generate a password\n4. Exit\nChoice: "


def _register(store: UserStore) -> None:
    username = input("Username: ").strip()
    password = getpass.getpass("Password (min 16 chars): ")
    if password != getpass.getpass("Repeat password: "):
        print("Passwords do not match.")
        return
    try:
        register(store, username, password)
    except RegistrationError as exc:
        print(f"Registration failed: {exc}")
        return
    print("User registered.")


def _login(store: UserStore) -> None:
    username = input("Username: ").strip()
    for attempt in range(1, MAX_LOGIN_ATTEMPTS + 1):
        if authenticate(store, username, getpass.getpass("Password: ")):
            print("Login successful.")
            return
        # Same message for unknown user and wrong password (no user enumeration).
        print(f"Invalid username or password ({attempt}/{MAX_LOGIN_ATTEMPTS}).")
    print("Too many failed attempts.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="secure_auth", description=__doc__)
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help="SQLite database path (default: users.db)")
    args = parser.parse_args(argv)
    store = UserStore(args.db)

    while True:
        choice = input(MENU).strip()  # input() returns str: compare with "1", not 1
        if choice == "1":
            _register(store)
        elif choice == "2":
            _login(store)
        elif choice == "3":
            print(generate_password())
        elif choice == "4":
            print("Bye.")
            return
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()

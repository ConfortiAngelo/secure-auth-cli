"""Registration and authentication logic, independent of the CLI."""

import re
from functools import cache

from .security import hash_password, needs_rehash, verify_password
from .storage import UserStore

MIN_PASSWORD_LENGTH = 16
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class RegistrationError(ValueError):
    """Raised when a new account cannot be created."""


@cache
def _dummy_hash() -> str:
    return hash_password("dummy-password-for-timing")


def register(store: UserStore, username: str, password: str) -> None:
    if not USERNAME_PATTERN.fullmatch(username):
        raise RegistrationError("Username must be 3-32 characters: letters, digits, _ . -")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise RegistrationError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")
    if not store.add_user(username, hash_password(password)):
        raise RegistrationError("Username already exists")


def authenticate(store: UserStore, username: str, password: str) -> bool:
    """Return True only if the user exists and the password matches.

    Unknown users still pay the cost of one Argon2 verification, so response
    time does not reveal which usernames exist (user enumeration).
    """
    stored_hash = store.get_password_hash(username)
    if stored_hash is None:
        verify_password(_dummy_hash(), password)
        return False
    if not verify_password(stored_hash, password):
        return False
    if needs_rehash(stored_hash):
        store.update_password_hash(username, hash_password(password))
    return True

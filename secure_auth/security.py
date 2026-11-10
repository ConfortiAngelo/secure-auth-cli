"""Password hashing with Argon2id (argon2-cffi).

Argon2id is memory-hard: every guess costs tens of megabytes of RAM, which
makes GPU/ASIC brute force far more expensive than with a fast hash such as
SHA-256. The salt is generated per hash and embedded in the encoded string,
so it does not need its own column.
"""

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

# argon2-cffi defaults follow the RFC 9106 low-memory profile.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time check of ``password`` against ``stored_hash``."""
    try:
        return _hasher.verify(stored_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when the hash was made with weaker parameters than the current ones."""
    return _hasher.check_needs_rehash(stored_hash)

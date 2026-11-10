"""Random password generation using a cryptographically secure source."""

import secrets
import string

MIN_LENGTH = 16


def generate_password(length: int = MIN_LENGTH, special_characters: bool = True) -> str:
    """Return a random password of ``length`` characters.

    Uses :mod:`secrets` (OS CSPRNG). The :mod:`random` module is a Mersenne
    Twister: fast and fine for simulations, but its output can be predicted
    after observing enough values, so it must never be used for secrets.
    """
    if length < MIN_LENGTH:
        raise ValueError(f"Password length must be at least {MIN_LENGTH}")
    alphabet = string.ascii_letters + string.digits
    if special_characters:
        alphabet += string.punctuation
    return "".join(secrets.choice(alphabet) for _ in range(length))

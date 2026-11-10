import string

import pytest

from secure_auth import password_generator
from secure_auth.password_generator import MIN_LENGTH, generate_password


def test_default_length():
    assert len(generate_password()) == MIN_LENGTH


def test_custom_length():
    assert len(generate_password(32)) == 32


def test_short_length_is_rejected():
    with pytest.raises(ValueError):
        generate_password(MIN_LENGTH - 1)


def test_without_special_characters():
    allowed = set(string.ascii_letters + string.digits)
    assert set(generate_password(64, special_characters=False)) <= allowed


def test_uses_secrets_csprng(monkeypatch):
    calls = []

    def fake_choice(seq):
        calls.append(seq)
        return seq[0]

    monkeypatch.setattr(password_generator.secrets, "choice", fake_choice)
    generate_password(20)
    assert len(calls) == 20


def test_does_not_use_random_module():
    assert not hasattr(password_generator, "random")

import pytest

from secure_auth.auth import RegistrationError, authenticate, register

GOOD_PASSWORD = "a-long-enough-password!"


def test_register_and_authenticate(store):
    register(store, "alice", GOOD_PASSWORD)
    assert authenticate(store, "alice", GOOD_PASSWORD)


def test_wrong_password_is_rejected(store):
    register(store, "alice", GOOD_PASSWORD)
    assert not authenticate(store, "alice", "a-wrong-but-long-password")


def test_unknown_user_is_rejected(store):
    assert not authenticate(store, "ghost", GOOD_PASSWORD)


@pytest.mark.parametrize("payload", ["' OR '1'='1", "' OR 1=1 --", "alice' --"])
def test_sql_injection_username_cannot_log_in(store, payload):
    register(store, "alice", GOOD_PASSWORD)
    assert not authenticate(store, payload, GOOD_PASSWORD)
    assert not authenticate(store, payload, "anything")


def test_password_is_stored_as_argon2_hash(store):
    register(store, "alice", GOOD_PASSWORD)
    stored = store.get_password_hash("alice")
    assert stored.startswith("$argon2id$")
    assert GOOD_PASSWORD not in stored


def test_short_password_is_rejected(store):
    with pytest.raises(RegistrationError):
        register(store, "alice", "short")


@pytest.mark.parametrize("bad_name", ["", "ab", "' OR '1'='1", "a" * 33, "with space"])
def test_invalid_username_is_rejected(store, bad_name):
    with pytest.raises(RegistrationError):
        register(store, bad_name, GOOD_PASSWORD)


def test_duplicate_username_is_rejected(store):
    register(store, "alice", GOOD_PASSWORD)
    with pytest.raises(RegistrationError):
        register(store, "alice", GOOD_PASSWORD)

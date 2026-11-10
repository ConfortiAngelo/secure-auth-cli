from secure_auth.storage import UserStore

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "alice' --",
    "x'; DROP TABLE users; --",
]


def test_sql_injection_payloads_return_no_user(store):
    store.add_user("alice", "hash-a")
    store.add_user("bob", "hash-b")
    for payload in SQLI_PAYLOADS:
        assert store.get_password_hash(payload) is None, payload


def test_drop_table_payload_does_not_drop_table(store):
    store.add_user("alice", "hash-a")
    store.get_password_hash("x'; DROP TABLE users; --")
    assert store.get_password_hash("alice") == "hash-a"


def test_payload_is_stored_literally_when_used_as_data(store):
    payload = "' OR '1'='1"
    assert store.add_user(payload, "hash-x")
    assert store.get_password_hash(payload) == "hash-x"


def test_duplicate_user_is_rejected(store):
    assert store.add_user("alice", "h1")
    assert not store.add_user("alice", "h2")
    assert store.get_password_hash("alice") == "h1"


def test_schema_creation_is_idempotent(tmp_path):
    path = tmp_path / "users.db"
    UserStore(path).add_user("alice", "h")
    assert UserStore(path).get_password_hash("alice") == "h"

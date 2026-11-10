from secure_auth.security import hash_password, needs_rehash, verify_password


def test_hash_uses_argon2id_and_is_not_plaintext():
    hashed = hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert "correct horse" not in hashed


def test_same_password_gets_different_salts():
    assert hash_password("same-password-123456") != hash_password("same-password-123456")


def test_verify_accepts_right_and_rejects_wrong_password():
    hashed = hash_password("right-password-123456")
    assert verify_password(hashed, "right-password-123456")
    assert not verify_password(hashed, "wrong-password-123456")


def test_verify_returns_false_on_garbage_hash():
    # Old SHA-256 hex digests from v1 must not crash or validate.
    assert not verify_password("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", "password")


def test_fresh_hash_does_not_need_rehash():
    assert not needs_rehash(hash_password("some-password-123456"))

import pytest

from secure_auth.storage import UserStore


@pytest.fixture
def store(tmp_path):
    return UserStore(tmp_path / "users.db")

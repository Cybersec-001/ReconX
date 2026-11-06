import os
import stat
import string

from generate_secret_key import generate_secret_key, update_env_file


def test_keys_are_unique_urlsafe_and_scaled_with_length():
    first, second = generate_secret_key(), generate_secret_key()
    assert first != second
    assert set(first) <= set(string.ascii_letters + string.digits + "-_")
    # token_urlsafe(50) encodes 50 random bytes, so the key is longer than 50 chars.
    assert len(first) > 50
    assert len(generate_secret_key(8)) < len(generate_secret_key(64))


def test_update_env_file_replaces_an_existing_key(tmp_path):
    env = tmp_path / ".env"
    env.write_text("SECRET_KEY=old\nOTHER=1\n")
    update_env_file("newsecret", env)
    assert env.read_text() == "SECRET_KEY=newsecret\nOTHER=1\n"


def test_update_env_file_appends_when_no_key_line_exists(tmp_path):
    env = tmp_path / ".env"
    env.write_text("OTHER=1\n")
    update_env_file("k", env)
    assert env.read_text() == "OTHER=1\nSECRET_KEY=k\n"


def test_update_env_file_creates_a_missing_file(tmp_path):
    env = tmp_path / ".env"
    update_env_file("k", env)
    assert env.read_text() == "SECRET_KEY=k\n"


def test_env_file_permissions_are_owner_only(tmp_path):
    env = tmp_path / ".env"
    update_env_file("k", env)
    assert stat.S_IMODE(os.stat(env).st_mode) == 0o600

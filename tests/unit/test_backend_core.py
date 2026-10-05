"""Backend security primitives: password policy, tokens, credential encryption, config guards."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.core import security
from app.core.config import INSECURE_DEV_SECRET, Settings


def test_password_hash_roundtrip():
    h = security.hash_password("Correct-Horse-Battery-9")
    assert h.startswith("$argon2id$")
    assert security.verify_password("Correct-Horse-Battery-9", h)
    assert not security.verify_password("wrong", h)
    assert not security.verify_password("anything", None)


@pytest.mark.parametrize(
    "password,ok",
    [
        ("short1A!", False),
        ("alllowercaseletters", False),
        ("Lowercase-and-Upper", True),
        ("lowercase-and-digits-123", True),
        ("x" * 129 + "A1", False),
    ],
)
def test_password_policy(password, ok):
    assert (security.password_policy_violations(password) == []) is ok


def test_password_may_not_contain_email_name():
    assert security.password_policy_violations("Jane.Doe-Secure-9", "jane.doe@example.com")


def test_session_token_roundtrip_and_tamper_detection():
    token, jti = security.create_session_token(7, "VIEWER", datetime.now(timezone.utc) + timedelta(minutes=5))
    claims = security.decode_session_token(token)
    assert claims["sub"] == "7" and claims["jti"] == jti
    head, body, sig = token.split(".")
    assert security.decode_session_token(f"{head}.{body}.{sig[:-2]}xx") is None


def test_expired_token_rejected():
    token, _ = security.create_session_token(7, "VIEWER", datetime.now(timezone.utc) - timedelta(seconds=1))
    assert security.decode_session_token(token) is None


def test_credentials_encrypted_at_rest():
    secret = {"secret_access_key": "wJalrXUtnFEMI/K7MDENG", "session_token": "IQoJb3JpZ2lu"}
    blob = security.encrypt_secret_payload(secret)
    assert "wJalr" not in blob and "IQoJ" not in blob
    assert security.decrypt_secret_payload(blob) == secret
    assert security.decrypt_secret_payload("not-a-token") == {}
    assert security.decrypt_secret_payload(None) == {}


def test_constant_time_compare():
    assert security.constant_time_equals("abc", "abc")
    assert not security.constant_time_equals("abc", "abd")
    assert not security.constant_time_equals(None, "abc")


def test_production_refuses_insecure_configuration():
    with pytest.raises(ValidationError):
        Settings(environment="production", secret_key=INSECURE_DEV_SECRET, credential_encryption_key="k")
    with pytest.raises(ValidationError):
        Settings(environment="production", secret_key="s" * 40, credential_encryption_key=None)
    with pytest.raises(ValidationError):
        Settings(environment="production", secret_key="s" * 40, credential_encryption_key="k", cookie_secure=False)
    ok = Settings(environment="production", secret_key="s" * 40, credential_encryption_key="k", cookie_secure=True)
    assert ok.is_production


def test_cors_origins_accept_comma_separated_env():
    assert Settings(cors_origins="https://a.example, https://b.example").cors_origins == ["https://a.example", "https://b.example"]

"""Helpers shared by AWS collectors."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Callable, TypeVar
from urllib.parse import unquote

from botocore.exceptions import BotoCoreError, ClientError

log = logging.getLogger("cloudaegis.engine.aws")

T = TypeVar("T")

ACCESS_DENIED_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "AuthorizationError"}


def iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def error_code(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "ClientError")
    return type(exc).__name__


def call(fn: Callable[..., T], *args: Any, missing: tuple[str, ...] = (), default: Any = None, **kwargs: Any) -> T | Any:
    """Call an AWS API; return ``default`` for expected 'not configured' errors.

    Other errors are logged (without request details that could carry
    credentials) and also yield ``default`` so one resource cannot abort
    discovery of the rest.
    """
    try:
        return fn(*args, **kwargs)
    except ClientError as exc:
        code = error_code(exc)
        if code not in missing:
            log.warning("aws_call_failed", extra={"operation": getattr(fn, "__name__", "?"), "code": code})
        return default
    except BotoCoreError as exc:
        log.warning("aws_call_failed", extra={"operation": getattr(fn, "__name__", "?"), "code": type(exc).__name__})
        return default


def policy_doc(value: Any) -> dict[str, Any] | None:
    """Normalise a policy document (dict, JSON string or URL-encoded JSON)."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    text = str(value)
    for candidate in (text, unquote(text)):
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


def tags_to_dict(tags: Any) -> dict[str, str]:
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    return {str(t.get("Key")): str(t.get("Value")) for t in tags if isinstance(t, dict)}


def name_from_tags(tags: dict[str, str], fallback: str) -> str:
    return tags.get("Name") or fallback


def mask_key_id(key_id: str | None) -> str | None:
    """Access key IDs are identifiers, not secrets, but we still only keep
    a recognisable fragment to limit what the platform stores."""
    if not key_id:
        return key_id
    return f"{key_id[:4]}…{key_id[-4:]}"

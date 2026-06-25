from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import settings


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode()).digest())
    return Fernet(key)


def encrypt_secret_fields(fields: dict[str, Any] | None) -> str | None:
    if not fields:
        return None
    payload = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()
    return _fernet().encrypt(payload).decode()


def decrypt_secret_fields(token: str | None) -> dict[str, Any]:
    if not token:
        return {}
    try:
        return json.loads(_fernet().decrypt(token.encode()).decode())
    except (InvalidToken, json.JSONDecodeError):
        return {}


def mask_credential(doc: dict[str, Any]) -> dict[str, Any]:
    result = dict(doc)
    secrets = decrypt_secret_fields(result.pop("encrypted_secret_fields", None))
    result["secret_fields"] = {key: "********" for key in secrets.keys()}
    result["has_secret_fields"] = sorted(secrets.keys())
    return result

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import timedelta
from typing import Any

from fastapi import Depends, Header, HTTPException, Request

from .db import mongo, now, oid, to_jsonable

ROLE_SCOPES = {
    "owner": ["admin"],
    "admin": ["auth.manage", "config.manage", "scan.read", "scan.write", "assets.read", "assets.write", "findings.read", "findings.write", "audit.read"],
    "operator": ["scan.read", "scan.write", "assets.read", "assets.write", "findings.read", "findings.write"],
    "viewer": ["scan.read", "assets.read", "findings.read"],
    "api_client": [],
}


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return "pbkdf2_sha256$260000$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(rounds))
        return hmac.compare_digest(expected, actual)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_user(email: str, name: str, password_hash: str, role: str, scopes: list[str]) -> str:
    result = mongo().users.insert_one({
        "email": email.lower(),
        "name": name,
        "password_hash": password_hash,
        "role": role,
        "scopes": scopes,
        "is_active": True,
        "created_at": now(),
        "updated_at": now(),
    })
    return str(result.inserted_id)


def create_session(user_id: Any) -> str:
    raw = secrets.token_urlsafe(48)
    mongo().sessions.insert_one({
        "user_id": str(user_id),
        "token_hash": token_hash(raw),
        "expires_at": now() + timedelta(hours=12),
        "created_at": now(),
        "last_seen_at": None,
    })
    return raw


def create_api_client(name: str, scopes: list[str]) -> tuple[str, str]:
    raw = "nsi_" + secrets.token_urlsafe(40)
    result = mongo().api_clients.insert_one({
        "name": name,
        "token_hash": token_hash(raw),
        "scopes": scopes,
        "is_active": True,
        "created_at": now(),
        "updated_at": now(),
        "last_used_at": None,
    })
    return str(result.inserted_id), raw


def scopes_for_principal(principal: dict[str, Any]) -> set[str]:
    if "admin" in principal.get("scopes", []):
        return {"admin"}
    scopes = set(ROLE_SCOPES.get(principal.get("role", ""), []))
    scopes.update(principal.get("scopes") or [])
    return scopes


def has_scope(principal: dict[str, Any], scope: str) -> bool:
    scopes = scopes_for_principal(principal)
    return "admin" in scopes or scope in scopes


def audit(action: str, principal: dict[str, Any] | None = None, request: Request | None = None, resource_type: str | None = None, resource_id: Any = None, details: Any = None) -> None:
    actor_type = "system"
    actor_id = None
    if principal:
        actor_type = principal.get("type", "user")
        actor_id = str(principal.get("id")) if principal.get("id") is not None else None
    ip = request.client.host if request and request.client else None
    mongo().audit_events.insert_one({
        "actor_type": actor_type,
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "ip_address": ip,
        "details": details,
        "created_at": now(),
    })


async def current_principal(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    raw = authorization.removeprefix("Bearer ").strip()
    digest = token_hash(raw)
    db = mongo()
    session = db.sessions.find_one({"token_hash": digest, "expires_at": {"$gt": now()}})
    if session:
        user = db.users.find_one({"_id": oid(session["user_id"]), "is_active": True})
        if user:
            db.sessions.update_one({"_id": session["_id"]}, {"$set": {"last_seen_at": now()}})
            return {
                "type": "user",
                "id": str(user["_id"]),
                "email": user.get("email"),
                "name": user.get("name"),
                "role": user.get("role"),
                "scopes": user.get("scopes") or [],
            }
    client = db.api_clients.find_one({"token_hash": digest, "is_active": True})
    if client:
        db.api_clients.update_one({"_id": client["_id"]}, {"$set": {"last_used_at": now()}})
        return {"type": "api_client", "id": str(client["_id"]), "name": client.get("name"), "role": "api_client", "scopes": client.get("scopes") or []}
    raise HTTPException(status_code=401, detail="Invalid token")


def require_scope(scope: str):
    async def dependency(principal: dict[str, Any] = Depends(current_principal)) -> dict[str, Any]:
        if not has_scope(principal, scope):
            raise HTTPException(status_code=403, detail=f"Missing scope: {scope}")
        return principal

    return dependency

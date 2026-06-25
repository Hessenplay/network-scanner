from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from bson import ObjectId
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from pymongo import DESCENDING

from .auth import audit, create_api_client, create_session, current_principal, hash_password, require_scope, verify_password
from .config import settings
from .db import bootstrap, ensure_scan_jobs_for_network, list_docs, mongo, now, oid, to_jsonable
from .scanner import (
    create_scan_run, run_scan, sync_identity_source, run_snmpwalk,
    reset_failed_scan_jobs, reset_single_scan_job,
    DEFAULT_DISCOVERY_TIMEOUT_S, DEFAULT_TCP_PROBE_TIMEOUT_MS, DEFAULT_RETRY_COUNT, DEFAULT_RATE_LIMIT,
)
from .secrets import encrypt_secret_fields, decrypt_secret_fields, mask_credential

app = FastAPI(title="Network Inventory Scanner", version="4.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
scheduler = None


class LoginRequest(BaseModel):
    email: str
    password: str


class NetworkPayload(BaseModel):
    name: str
    cidr: str
    is_active: bool = True
    excludes: list[str] = Field(default_factory=list)
    discovery_interval_seconds: int = 120
    deep_scan_interval_minutes: int = 360
    rate_limit_per_minute: int = 600
    scan_window: str | None = None


class PortProfilePayload(BaseModel):
    name: str
    description: str | None = None
    ports: list[int]
    is_default: bool = False


class ScanProfilePayload(BaseModel):
    name: str
    kind: str
    is_enabled: bool = False
    requires_manual_approval: bool = True
    config: dict[str, Any] = Field(default_factory=dict)


class ScanRequest(BaseModel):
    mode: str = "discovery"
    network_id: str | None = None
    profile_id: str | None = None
    cidr: str | None = None
    # Scan tuning — all optional, fall back to server defaults
    discovery_timeout_s: int | None = None   # nmap per-host timeout in seconds
    tcp_timeout_ms: int | None = None        # fallback TCP connect timeout in ms
    retry_count: int | None = None           # how many times to retry a failed subnet
    rate_limit: int | None = None            # target packets/min (informational, stored in options)


class ApiClientPayload(BaseModel):
    name: str
    scopes: list[str]


class UserPayload(BaseModel):
    email: str
    name: str
    password: str | None = None
    role: str = "viewer"
    scopes: list[str] = Field(default_factory=list)
    is_active: bool = True


class FindingUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    title: str | None = None


class DeviceUpdate(BaseModel):
    category: str | None = None
    override_vendor: str | None = None
    override_model: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


class IdentitySourcePayload(BaseModel):
    name: str
    type: str
    config: dict[str, Any] = Field(default_factory=dict)
    credential_id: str | None = None
    is_active: bool = True


class CredentialPayload(BaseModel):
    name: str
    type: str
    username: str | None = None
    secret_fields: dict[str, Any] = Field(default_factory=dict)
    config: dict[str, Any] = Field(default_factory=dict)
    target_patterns: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    is_active: bool = True


class CredentialUpdate(BaseModel):
    name: str | None = None
    type: str | None = None
    username: str | None = None
    secret_fields: dict[str, Any] | None = None
    config: dict[str, Any] | None = None
    target_patterns: list[str] | None = None
    tags: list[str] | None = None
    is_active: bool | None = None


class SystemSettingsPayload(BaseModel):
    app_name: str | None = None
    timezone: str | None = None
    setup_completed: bool | None = None
    default_scan_mode: str | None = None
    retention_days: int | None = None
    ui_defaults: dict[str, Any] = Field(default_factory=dict)


class SetupBootstrapPayload(BaseModel):
    token: str | None = None
    email: str | None = None
    name: str = "Owner"
    password: str | None = None
    default_network: str | None = None


def regex_query(q: str | None) -> dict[str, Any]:
    if not q:
        return {}
    safe = re.escape(q.strip())
    return {"$or": [
        {"search_text": {"$regex": safe, "$options": "i"}},
        {"device_id": {"$regex": safe, "$options": "i"}},
        {"current_ips": q.strip()},
        {"identifiers.mac": {"$regex": safe, "$options": "i"}},
        {"identifiers.hostnames": {"$regex": safe, "$options": "i"}},
    ]}


def normalize_device(doc: dict[str, Any]) -> dict[str, Any]:
    item = to_jsonable(doc)
    ips = item.get("current_ips") or []
    detected = item.get("detected") or {}
    overrides = item.get("overrides") or {}
    identifiers = item.get("identifiers") or {}
    item["primary_ip"] = ips[0] if ips else None
    item["hostname"] = (identifiers.get("hostnames") or [None])[0]
    item["mac_address"] = identifiers.get("mac")
    item["detected_vendor"] = detected.get("vendor")
    item["detected_model"] = detected.get("model")
    item["override_vendor"] = overrides.get("vendor")
    item["override_model"] = overrides.get("model")
    return item


def scan_target_label(row: dict[str, Any]) -> str:
    if row.get("cidr"):
        return str(row["cidr"])
    if row.get("target_label"):
        return str(row["target_label"])
    network_id = row.get("network_id")
    if network_id:
        try:
            network = mongo().networks.find_one({"_id": oid(network_id)})
            if network and network.get("cidr"):
                return str(network["cidr"])
        except Exception:
            pass
    return "Alle aktiven Zielnetze"


def normalize_scan(row: dict[str, Any]) -> dict[str, Any]:
    item = to_jsonable(row)
    item["target_label"] = scan_target_label(row)
    if row.get("network_id"):
        try:
            network = mongo().networks.find_one({"_id": oid(row["network_id"])})
            if network:
                item["network_name"] = network.get("name")
                item["network_cidr"] = network.get("cidr")
        except Exception:
            pass
    item["short_id"] = str(item.get("id") or item.get("_id") or "")[-8:]
    return item


def scan_doc(scan_id: str) -> dict[str, Any]:
    row = mongo().scan_runs.find_one({"_id": oid(scan_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    return normalize_scan(row)


def global_settings() -> dict[str, Any]:
    row = mongo().system_settings.find_one({"key": "global"})
    if not row:
        row = {"key": "global", "app_name": settings.app_name, "timezone": settings.timezone_name,
               "setup_completed": False, "created_at": now(), "updated_at": now()}
        mongo().system_settings.insert_one(row)
    return row


def setup_allowed(token: str | None = None) -> bool:
    if mongo().users.count_documents({}) == 0:
        return True
    return bool(settings.setup_token and token and token == settings.setup_token)


def clean_user(row: dict[str, Any]) -> dict[str, Any]:
    item = to_jsonable(row)
    item.pop("password_hash", None)
    return item


@app.on_event("startup")
async def startup() -> None:
    bootstrap()
    from .scanner import ScannerScheduler
    import asyncio
    global scheduler
    scheduler = ScannerScheduler()
    asyncio.create_task(scheduler.start())


@app.get("/health")
async def health() -> dict[str, Any]:
    db = mongo()
    return {
        "status": "ok", "storage": "mongodb", "database": db.name,
        "timezone": settings.timezone_name, "server_time": now().isoformat(),
        "devices": db.devices.count_documents({}),
        "scan_jobs": db.scan_jobs.count_documents({}),
        "defaults": {
            "discovery_timeout_s": DEFAULT_DISCOVERY_TIMEOUT_S,
            "tcp_timeout_ms": DEFAULT_TCP_PROBE_TIMEOUT_MS,
            "retry_count": DEFAULT_RETRY_COUNT,
            "rate_limit": DEFAULT_RATE_LIMIT,
        },
    }


@app.get("/api/v1/setup/status")
async def setup_status() -> dict[str, Any]:
    row = global_settings()
    return {
        "has_admin": mongo().users.count_documents({}) > 0,
        "setup_completed": bool(row.get("setup_completed")),
        "app_name": row.get("app_name") or settings.app_name,
        "timezone": row.get("timezone") or settings.timezone_name,
        "requires_token": mongo().users.count_documents({}) > 0,
    }


@app.post("/api/v1/setup/bootstrap")
async def setup_bootstrap(payload: SetupBootstrapPayload, request: Request) -> dict[str, Any]:
    if not setup_allowed(payload.token):
        raise HTTPException(status_code=403, detail="Setup token required")
    created_user = None
    if payload.email and payload.password and not mongo().users.find_one({"email": payload.email.lower()}):
        from .auth import create_user
        created_id = create_user(payload.email, payload.name, hash_password(payload.password), "owner", ["admin"])
        created_user = created_id
    if payload.default_network:
        existing = mongo().networks.find_one({"cidr": payload.default_network})
        if not existing:
            result = mongo().networks.insert_one({
                "name": payload.default_network, "cidr": payload.default_network,
                "is_active": True, "excludes": [], "discovery_interval_seconds": 120,
                "deep_scan_interval_minutes": 360, "rate_limit_per_minute": 600,
                "scan_window": None, "created_at": now(), "updated_at": now(),
            })
            ensure_scan_jobs_for_network(mongo().networks.find_one({"_id": result.inserted_id}))
    mongo().system_settings.update_one({"key": "global"}, {"$set": {"setup_completed": True, "updated_at": now()}}, upsert=True)
    audit("setup.bootstrap", request=request, details={"created_user": created_user, "default_network": payload.default_network})
    return {"status": "ok", "created_user": created_user}


@app.post("/api/v1/auth/login")
async def login(payload: LoginRequest, request: Request) -> dict[str, Any]:
    user = mongo().users.find_one({"email": payload.email.lower(), "is_active": True})
    if not user or not verify_password(payload.password, user["password_hash"]):
        audit("auth.login_failed", request=request, details={"email": payload.email})
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session(str(user["_id"]))
    principal = {"type": "user", "id": str(user["_id"]), "role": user.get("role"), "scopes": user.get("scopes") or []}
    audit("auth.login", principal, request)
    return {"token": token, "user": {"id": str(user["_id"]), "email": user["email"], "name": user.get("name"), "role": user.get("role")}}


@app.get("/api/v1/auth/me")
async def me(principal: dict[str, Any] = Depends(current_principal)) -> dict[str, Any]:
    return principal


@app.get("/api/v1/dashboard")
async def dashboard(_: dict[str, Any] = Depends(require_scope("assets.read"))) -> dict[str, Any]:
    db = mongo()
    counts = {
        "devices": db.devices.count_documents({}),
        "present_devices": db.devices.count_documents({"is_present": True}),
        "findings_open": db.findings.count_documents({"status": "open"}),
        "running_scans": db.scan_runs.count_documents({"status": "running"}),
        "scan_jobs": db.scan_jobs.count_documents({}),
    }
    # Category breakdown for dashboard chart
    pipeline = [{"$group": {"_id": "$category", "count": {"$sum": 1}}}]
    category_counts = {doc["_id"] or "unknown": doc["count"] for doc in db.devices.aggregate(pipeline)}

    recent_devices = [normalize_device(doc) for doc in db.devices.find({}).sort("last_seen_at", DESCENDING).limit(10)]
    recent_scans = [normalize_scan(doc) for doc in db.scan_runs.find({}).sort("created_at", DESCENDING).limit(10)]
    return {
        "counts": counts,
        "category_counts": category_counts,
        "recent_assets": recent_devices,
        "recent_devices": recent_devices,
        "recent_scans": recent_scans,
    }


@app.get("/api/v1/networks")
async def list_networks(_: dict[str, Any] = Depends(require_scope("config.manage"))) -> list[dict[str, Any]]:
    return list_docs("networks", sort=[("created_at", 1)])


@app.post("/api/v1/networks")
async def create_network(payload: NetworkPayload, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    db = mongo()
    doc = payload.model_dump() | {"created_at": now(), "updated_at": now()}
    result = db.networks.insert_one(doc)
    network = db.networks.find_one({"_id": result.inserted_id})
    ensure_scan_jobs_for_network(network)
    audit("network.create", principal, request, "network", result.inserted_id, payload.model_dump())
    return to_jsonable(network)


@app.patch("/api/v1/networks/{network_id}")
async def update_network(network_id: str, payload: NetworkPayload, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    db = mongo()
    db.networks.update_one({"_id": oid(network_id)}, {"$set": payload.model_dump() | {"updated_at": now()}})
    network = db.networks.find_one({"_id": oid(network_id)})
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")
    ensure_scan_jobs_for_network(network)
    audit("network.update", principal, request, "network", network_id, payload.model_dump())
    return to_jsonable(network)


@app.delete("/api/v1/networks/{network_id}")
async def delete_network(network_id: str, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    db = mongo()
    network = db.networks.find_one({"_id": oid(network_id)})
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")
    db.networks.delete_one({"_id": oid(network_id)})
    db.scan_jobs.delete_many({"network_id": network_id})
    audit("network.delete", principal, request, "network", network_id, {"cidr": network.get("cidr")})
    return {"status": "deleted"}


@app.get("/api/v1/port-profiles")
async def list_port_profiles(_: dict[str, Any] = Depends(require_scope("config.manage"))) -> list[dict[str, Any]]:
    return list_docs("port_profiles", sort=[("created_at", 1)])


@app.post("/api/v1/port-profiles")
async def create_port_profile(payload: PortProfilePayload, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    db = mongo()
    if payload.is_default:
        db.port_profiles.update_many({}, {"$set": {"is_default": False}})
    doc = payload.model_dump() | {"created_at": now(), "updated_at": now()}
    result = db.port_profiles.insert_one(doc)
    audit("port_profile.create", principal, request, "port_profile", result.inserted_id, payload.model_dump())
    return to_jsonable(db.port_profiles.find_one({"_id": result.inserted_id}))


@app.patch("/api/v1/port-profiles/{profile_id}")
async def update_port_profile(profile_id: str, payload: PortProfilePayload, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    db = mongo()
    if payload.is_default:
        db.port_profiles.update_many({"_id": {"$ne": oid(profile_id)}}, {"$set": {"is_default": False}})
    db.port_profiles.update_one({"_id": oid(profile_id)}, {"$set": payload.model_dump() | {"updated_at": now()}})
    row = db.port_profiles.find_one({"_id": oid(profile_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Port profile not found")
    audit("port_profile.update", principal, request, "port_profile", profile_id, payload.model_dump())
    return to_jsonable(row)


@app.delete("/api/v1/port-profiles/{profile_id}")
async def delete_port_profile(profile_id: str, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    row = mongo().port_profiles.find_one({"_id": oid(profile_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Port profile not found")
    if row.get("is_default") and mongo().port_profiles.count_documents({}) > 1:
        raise HTTPException(status_code=409, detail="Default profile cannot be deleted before another profile is default")
    mongo().port_profiles.delete_one({"_id": oid(profile_id)})
    audit("port_profile.delete", principal, request, "port_profile", profile_id, {"name": row.get("name")})
    return {"status": "deleted"}


@app.get("/api/v1/scan-profiles")
async def list_scan_profiles(_: dict[str, Any] = Depends(require_scope("config.manage"))) -> list[dict[str, Any]]:
    return list_docs("scan_profiles", sort=[("created_at", 1)])


@app.patch("/api/v1/scan-profiles/{profile_id}")
async def update_scan_profile(profile_id: str, payload: ScanProfilePayload, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    mongo().scan_profiles.update_one({"_id": oid(profile_id)}, {"$set": payload.model_dump() | {"updated_at": now()}})
    audit("scan_profile.update", principal, request, "scan_profile", profile_id, payload.model_dump())
    row = mongo().scan_profiles.find_one({"_id": oid(profile_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")
    return to_jsonable(row)


@app.delete("/api/v1/scan-profiles/{profile_id}")
async def delete_scan_profile(profile_id: str, request: Request, principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    row = mongo().scan_profiles.find_one({"_id": oid(profile_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Profile not found")
    mongo().scan_profiles.delete_one({"_id": oid(profile_id)})
    audit("scan_profile.delete", principal, request, "scan_profile", profile_id, {"name": row.get("name")})
    return {"status": "deleted"}


@app.get("/api/v1/scans")
async def list_scans(_: dict[str, Any] = Depends(require_scope("scan.read"))) -> list[dict[str, Any]]:
    return [normalize_scan(row) for row in mongo().scan_runs.find({}).sort("created_at", DESCENDING).limit(150)]


@app.get("/api/v1/scan-jobs")
async def list_scan_jobs(_: dict[str, Any] = Depends(require_scope("scan.read"))) -> list[dict[str, Any]]:
    rows = []
    for job in mongo().scan_jobs.find({}).sort([("order", 1), ("cidr", 1)]):
        item = to_jsonable(job)
        if job.get("network_id"):
            try:
                network = mongo().networks.find_one({"_id": oid(job["network_id"])})
                if network:
                    item["network_name"] = network.get("name")
                    item["network_cidr"] = network.get("cidr")
            except Exception:
                pass
        if job.get("current_scan_id"):
            run = mongo().scan_runs.find_one({"_id": oid(job["current_scan_id"])})
            if run:
                item["current_scan"] = normalize_scan(run)
        rows.append(item)
    return rows


@app.post("/api/v1/scan-jobs/reset-failed")
async def reset_failed_jobs(request: Request, principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    """Reset all failed scan jobs so they will be picked up on the next scheduler tick."""
    count = reset_failed_scan_jobs()
    audit("scan_job.reset_failed", principal, request, details={"count": count})
    return {"reset": count, "message": f"{count} jobs zurückgesetzt"}


@app.post("/api/v1/scan-jobs/{job_id}/reset")
async def reset_scan_job(job_id: str, request: Request, principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    """Reset a single scan job to queued state."""
    job = mongo().scan_jobs.find_one({"_id": oid(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    updated = reset_single_scan_job(job_id)
    audit("scan_job.reset", principal, request, "scan_job", job_id, {"cidr": job.get("cidr")})
    return to_jsonable(updated)


@app.post("/api/v1/scan-jobs/{job_id}/trigger-now")
async def trigger_job_now(job_id: str, background: BackgroundTasks, request: Request,
                           principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    """Immediately trigger a specific /24 scan job without waiting for its schedule."""
    from pymongo import ReturnDocument as RD
    job = mongo().scan_jobs.find_one({"_id": oid(job_id)})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.get("status") == "running":
        raise HTTPException(status_code=409, detail="Job is already running")
    reserved = mongo().scan_jobs.find_one_and_update(
        {"_id": oid(job_id), "status": {"$ne": "running"}},
        {"$set": {"status": "running", "next_due_at": now(), "message": "Triggered manually", "updated_at": now()}},
        return_document=RD.AFTER,
    )
    if not reserved:
        raise HTTPException(status_code=409, detail="Job could not be reserved")
    network = mongo().networks.find_one({"_id": oid(reserved["network_id"]), "is_active": True})
    if not network:
        mongo().scan_jobs.update_one({"_id": oid(job_id)}, {"$set": {"status": "skipped", "message": "Network inactive"}})
        raise HTTPException(status_code=400, detail="Network is inactive")
    scan_id = create_scan_run("discovery", str(network["_id"]), cidr=reserved["cidr"], job_id=str(reserved["_id"]))
    background.add_task(run_scan, scan_id, str(network["_id"]), "discovery",
                        cidr=reserved["cidr"], job_id=str(reserved["_id"]))
    audit("scan_job.trigger", principal, request, "scan_job", job_id, {"cidr": reserved.get("cidr")})
    return to_jsonable(mongo().scan_jobs.find_one({"_id": oid(job_id)}))


@app.post("/api/v1/scans")
async def start_scan(payload: ScanRequest, background: BackgroundTasks, request: Request,
                     principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    if payload.mode in {"exploit", "bruteforce", "vulnerability", "auth_audit"}:
        profile = mongo().scan_profiles.find_one({"_id": oid(payload.profile_id), "is_enabled": True}) if payload.profile_id else None
        if not profile:
            raise HTTPException(status_code=403, detail="Security profile must be explicitly enabled and selected")

    # Build options dict from payload
    options: dict[str, Any] = {}
    if payload.discovery_timeout_s is not None:
        options["discovery_timeout_s"] = payload.discovery_timeout_s
    if payload.tcp_timeout_ms is not None:
        options["tcp_timeout_ms"] = payload.tcp_timeout_ms
    if payload.retry_count is not None:
        options["retry_count"] = payload.retry_count
    if payload.rate_limit is not None:
        options["rate_limit"] = payload.rate_limit

    scan_id = create_scan_run(payload.mode, payload.network_id, payload.profile_id,
                               principal["type"], principal["id"], payload.cidr, options=options)
    audit("scan.start", principal, request, "scan_run", scan_id, payload.model_dump())
    background.add_task(run_scan, scan_id, payload.network_id, payload.mode,
                        cidr=payload.cidr, options=options)
    return scan_doc(scan_id)


@app.post("/api/v1/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request, principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    mongo().scan_runs.update_one(
        {"_id": oid(scan_id), "status": {"$in": ["queued", "running", "paused"]}},
        {"$set": {"status": "cancelled", "finished_at": now(), "message": "Cancelled by API"}},
    )
    audit("scan.cancel", principal, request, "scan_run", scan_id)
    return scan_doc(scan_id)


@app.post("/api/v1/scans/{scan_id}/pause")
async def pause_scan(scan_id: str, request: Request, principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    mongo().scan_runs.update_one({"_id": oid(scan_id), "status": "running"},
                                  {"$set": {"status": "paused", "message": "Paused by API"}})
    audit("scan.pause", principal, request, "scan_run", scan_id)
    return scan_doc(scan_id)


@app.post("/api/v1/scans/{scan_id}/resume")
async def resume_scan(scan_id: str, request: Request, principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    mongo().scan_runs.update_one({"_id": oid(scan_id), "status": "paused"},
                                  {"$set": {"status": "running", "message": "Resumed by API"}})
    audit("scan.resume", principal, request, "scan_run", scan_id)
    return scan_doc(scan_id)


@app.post("/api/v1/scans/{scan_id}/rerun")
async def rerun_scan(scan_id: str, background: BackgroundTasks, request: Request,
                     principal: dict[str, Any] = Depends(require_scope("scan.write"))) -> dict[str, Any]:
    old = mongo().scan_runs.find_one({"_id": oid(scan_id)})
    if not old:
        raise HTTPException(status_code=404, detail="Scan not found")
    options = old.get("options") or {}
    new_id = create_scan_run(old.get("mode"), old.get("network_id"), old.get("profile_id"),
                              principal["type"], principal["id"], old.get("cidr"), options=options)
    audit("scan.rerun", principal, request, "scan_run", new_id, {"source_scan_id": scan_id})
    background.add_task(run_scan, new_id, old.get("network_id"), old.get("mode"),
                        cidr=old.get("cidr"), options=options)
    return scan_doc(new_id)


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, _: dict[str, Any] = Depends(require_scope("scan.read"))) -> dict[str, Any]:
    return scan_doc(scan_id)


@app.get("/api/v1/scans/{scan_id}/logs")
async def get_scan_logs(scan_id: str, _: dict[str, Any] = Depends(require_scope("scan.read"))) -> dict[str, Any]:
    row = scan_doc(scan_id)
    return {"logs": row.get("logs") or [], "status": row.get("status"), "progress": row.get("progress")}


@app.get("/api/v1/devices/search")
async def search_devices(q: str = "", _: dict[str, Any] = Depends(require_scope("assets.read"))) -> list[dict[str, Any]]:
    return await list_devices(q=q, _=_)


@app.get("/api/v1/devices")
async def list_devices(q: str = "", category: str | None = None, status: str | None = None,
                        _: dict[str, Any] = Depends(require_scope("assets.read"))) -> list[dict[str, Any]]:
    query = regex_query(q)
    if category:
        query["category"] = category
    if status == "present":
        query["is_present"] = True
    cursor = mongo().devices.find(query).sort("last_seen_at", DESCENDING).limit(500)
    return [normalize_device(doc) for doc in cursor]


@app.get("/api/v1/devices/{device_id}")
async def get_device(device_id: str, _: dict[str, Any] = Depends(require_scope("assets.read"))) -> dict[str, Any]:
    doc = mongo().devices.find_one({"device_id": device_id})
    if not doc:
        doc = mongo().devices.find_one({"_id": oid(device_id)}) if ObjectId.is_valid(device_id) else None
    if not doc:
        raise HTTPException(status_code=404, detail="Device not found")
    item = normalize_device(doc)
    observations = [to_jsonable(row) for row in mongo().observations.find({"device_id": doc["device_id"]}).sort("observed_at", DESCENDING).limit(500)]
    item["recent_observations"] = observations
    item["timeline"] = observations
    item["ip_history"] = [to_jsonable(row) for row in mongo().observations.find(
        {"device_id": doc["device_id"], "ip": {"$ne": None}}, {"ip": 1, "observed_at": 1, "source": 1, "events": 1}
    ).sort("observed_at", DESCENDING).limit(500)]
    item["findings"] = list_docs("findings", {"device_id": doc["device_id"]}, sort=[("last_seen_at", DESCENDING)], limit=200)
    return item


@app.get("/api/v1/devices/{device_id}/timeline")
async def device_timeline(device_id: str, _: dict[str, Any] = Depends(require_scope("assets.read"))) -> list[dict[str, Any]]:
    return list_docs("observations", {"device_id": device_id}, sort=[("observed_at", DESCENDING)], limit=250)


@app.get("/api/v1/devices/{device_id}/observations")
async def device_observations(device_id: str, _: dict[str, Any] = Depends(require_scope("assets.read"))) -> list[dict[str, Any]]:
    return list_docs("observations", {"device_id": device_id}, sort=[("observed_at", DESCENDING)], limit=500)


@app.patch("/api/v1/devices/{device_id}")
async def update_device(device_id: str, payload: DeviceUpdate, request: Request,
                         principal: dict[str, Any] = Depends(require_scope("assets.write"))) -> dict[str, Any]:
    updates: dict[str, Any] = {"updated_at": now()}
    if payload.category is not None:
        updates["category"] = payload.category
    if payload.override_vendor is not None:
        updates["overrides.vendor"] = payload.override_vendor
    if payload.override_model is not None:
        updates["overrides.model"] = payload.override_model
    if payload.tags is not None:
        updates["tags"] = payload.tags
    if payload.notes is not None:
        updates["notes"] = payload.notes
    mongo().devices.update_one({"device_id": device_id}, {"$set": updates})
    audit("device.update", principal, request, "device", device_id, payload.model_dump(exclude_none=True))
    return await get_device(device_id, principal)


@app.get("/api/v1/assets")
async def list_assets(q: str = "", principal: dict[str, Any] = Depends(require_scope("assets.read"))) -> list[dict[str, Any]]:
    return await list_devices(q=q, _=principal)


@app.get("/api/v1/assets/{device_id}")
async def get_asset(device_id: str, principal: dict[str, Any] = Depends(require_scope("assets.read"))) -> dict[str, Any]:
    return await get_device(device_id, principal)


@app.patch("/api/v1/assets/{device_id}")
async def update_asset(device_id: str, payload: DeviceUpdate, request: Request,
                        principal: dict[str, Any] = Depends(require_scope("assets.write"))) -> dict[str, Any]:
    return await update_device(device_id, payload, request, principal)


@app.get("/api/v1/services")
async def services(_: dict[str, Any] = Depends(require_scope("assets.read"))) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for device in mongo().devices.find({"services": {"$exists": True, "$ne": []}}).limit(1000):
        for service in device.get("services") or []:
            rows.append(to_jsonable(service | {
                "device_id": device["device_id"],
                "primary_ip": (device.get("current_ips") or [None])[0],
                "hostname": ((device.get("identifiers") or {}).get("hostnames") or [None])[0],
            }))
    return rows


@app.get("/api/v1/enrichment/summary")
async def enrichment_summary(_: dict[str, Any] = Depends(require_scope("assets.read"))) -> dict[str, Any]:
    db = mongo()
    return {
        "devices": db.devices.count_documents({}),
        "with_mac": db.devices.count_documents({"identifiers.mac": {"$exists": True, "$ne": None}}),
        "with_hostname": db.devices.count_documents({"identifiers.hostnames.0": {"$exists": True}}),
        "with_http": db.devices.count_documents({"services.http": {"$exists": True}}),
        "with_tls": db.devices.count_documents({"services.tls": {"$exists": True}}),
        "with_ssh": db.devices.count_documents({"services.ssh": {"$exists": True}}),
        "with_fingerprints": db.devices.count_documents({"fingerprints": {"$exists": True, "$ne": {}}}),
    }


@app.get("/api/v1/findings")
async def list_findings(q: str = "", _: dict[str, Any] = Depends(require_scope("findings.read"))) -> list[dict[str, Any]]:
    query = {"$or": [{"title": {"$regex": re.escape(q), "$options": "i"}},
                     {"device_id": {"$regex": re.escape(q), "$options": "i"}}]} if q else {}
    return list_docs("findings", query, sort=[("last_seen_at", DESCENDING)], limit=250)


@app.patch("/api/v1/findings/{finding_id}")
async def update_finding(finding_id: str, payload: FindingUpdate, request: Request,
                          principal: dict[str, Any] = Depends(require_scope("findings.write"))) -> dict[str, Any]:
    updates = payload.model_dump(exclude_none=True) | {"updated_at": now()}
    mongo().findings.update_one({"_id": oid(finding_id)}, {"$set": updates})
    audit("finding.update", principal, request, "finding", finding_id, updates)
    row = mongo().findings.find_one({"_id": oid(finding_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Finding not found")
    return to_jsonable(row)


@app.get("/api/v1/identity-sources")
async def list_identity_sources(_: dict[str, Any] = Depends(require_scope("config.manage"))) -> list[dict[str, Any]]:
    return list_docs("identity_sources", sort=[("created_at", 1)])


@app.post("/api/v1/identity-sources")
async def create_identity_source(payload: IdentitySourcePayload, request: Request,
                                   principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    doc = payload.model_dump() | {"created_at": now(), "updated_at": now(), "last_sync_at": None}
    result = mongo().identity_sources.insert_one(doc)
    audit("identity_source.create", principal, request, "identity_source", result.inserted_id, payload.model_dump())
    return to_jsonable(mongo().identity_sources.find_one({"_id": result.inserted_id}))


@app.patch("/api/v1/identity-sources/{source_id}")
async def update_identity_source(source_id: str, payload: IdentitySourcePayload, request: Request,
                                   principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    mongo().identity_sources.update_one({"_id": oid(source_id)}, {"$set": payload.model_dump() | {"updated_at": now()}})
    audit("identity_source.update", principal, request, "identity_source", source_id, payload.model_dump())
    row = mongo().identity_sources.find_one({"_id": oid(source_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Identity source not found")
    return to_jsonable(row)


@app.delete("/api/v1/identity-sources/{source_id}")
async def delete_identity_source(source_id: str, request: Request,
                                   principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    row = mongo().identity_sources.find_one({"_id": oid(source_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Identity source not found")
    mongo().identity_sources.delete_one({"_id": oid(source_id)})
    audit("identity_source.delete", principal, request, "identity_source", source_id, {"name": row.get("name")})
    return {"status": "deleted"}


@app.post("/api/v1/identity-sources/{source_id}/test")
async def test_identity_source(source_id: str, request: Request,
                                principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    row = mongo().identity_sources.find_one({"_id": oid(source_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Identity source not found")
    ok = row.get("type") in {"dhcp", "arp", "snmp", "dns", "file", "ssdp", "mdns"}
    audit("identity_source.test", principal, request, "identity_source", source_id, {"ok": ok})
    return {"ok": ok, "message": "Source configuration accepted" if ok else "Unsupported source type"}


@app.post("/api/v1/identity-sources/{source_id}/sync")
async def sync_identity_source_endpoint(source_id: str, request: Request,
                                         principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    row = mongo().identity_sources.find_one({"_id": oid(source_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Identity source not found")
    result = sync_identity_source(row)
    audit("identity_source.sync", principal, request, "identity_source", source_id, result)
    return {"status": "completed", "result": result}


@app.get("/api/v1/credentials")
async def list_credentials(_: dict[str, Any] = Depends(require_scope("config.manage"))) -> list[dict[str, Any]]:
    return [to_jsonable(mask_credential(row)) for row in mongo().credentials.find({}).sort("created_at", DESCENDING)]


@app.post("/api/v1/credentials")
async def create_credential(payload: CredentialPayload, request: Request,
                              principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    doc = payload.model_dump(exclude={"secret_fields"}) | {
        "encrypted_secret_fields": encrypt_secret_fields(payload.secret_fields),
        "created_at": now(), "updated_at": now(),
    }
    result = mongo().credentials.insert_one(doc)
    audit("credential.create", principal, request, "credential", result.inserted_id, {"name": payload.name, "type": payload.type})
    return to_jsonable(mask_credential(mongo().credentials.find_one({"_id": result.inserted_id})))


@app.patch("/api/v1/credentials/{credential_id}")
async def update_credential(credential_id: str, payload: CredentialUpdate, request: Request,
                              principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    updates = payload.model_dump(exclude_unset=True, exclude={"secret_fields"})
    if payload.secret_fields is not None:
        updates["encrypted_secret_fields"] = encrypt_secret_fields(payload.secret_fields)
    updates["updated_at"] = now()
    mongo().credentials.update_one({"_id": oid(credential_id)}, {"$set": updates})
    row = mongo().credentials.find_one({"_id": oid(credential_id)})
    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")
    audit("credential.update", principal, request, "credential", credential_id, {"fields": sorted(updates.keys())})
    return to_jsonable(mask_credential(row))


@app.delete("/api/v1/credentials/{credential_id}")
async def delete_credential(credential_id: str, request: Request,
                              principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    mongo().credentials.update_one({"_id": oid(credential_id)}, {"$set": {"is_active": False, "updated_at": now()}})
    audit("credential.disable", principal, request, "credential", credential_id)
    return {"status": "disabled"}


@app.post("/api/v1/credentials/{credential_id}/test")
async def test_credential(credential_id: str, request: Request,
                           principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    row = mongo().credentials.find_one({"_id": oid(credential_id), "is_active": True})
    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")
    secrets = decrypt_secret_fields(row.get("encrypted_secret_fields"))
    ok = True
    message = "Credential format accepted"
    if row.get("type") == "snmp":
        host = (row.get("config") or {}).get("host") or secrets.get("host")
        community = secrets.get("community") or (row.get("config") or {}).get("community")
        output = run_snmpwalk(host, community, "1.3.6.1.2.1.1.1.0", timeout=3) if host and community else None
        ok = bool(output)
        message = "SNMP read succeeded" if ok else "SNMP read failed or missing host/community"
    audit("credential.test", principal, request, "credential", credential_id, {"ok": ok, "type": row.get("type")})
    return {"ok": ok, "message": message}


@app.get("/api/v1/system/settings")
async def get_system_settings(_: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    return to_jsonable(global_settings())


@app.patch("/api/v1/system/settings")
async def update_system_settings(payload: SystemSettingsPayload, request: Request,
                                   principal: dict[str, Any] = Depends(require_scope("config.manage"))) -> dict[str, Any]:
    updates = payload.model_dump(exclude_unset=True) | {"updated_at": now()}
    mongo().system_settings.update_one({"key": "global"}, {"$set": updates}, upsert=True)
    audit("system.update", principal, request, "system_settings", "global", updates)
    return to_jsonable(global_settings())


@app.patch("/api/v1/users/{user_id}")
async def update_user(user_id: str, payload: UserPayload, request: Request,
                       principal: dict[str, Any] = Depends(require_scope("auth.manage"))) -> dict[str, Any]:
    updates = {"email": payload.email.lower(), "name": payload.name, "role": payload.role,
               "scopes": payload.scopes, "is_active": payload.is_active, "updated_at": now()}
    if payload.password:
        updates["password_hash"] = hash_password(payload.password)
    mongo().users.update_one({"_id": oid(user_id)}, {"$set": updates})
    row = mongo().users.find_one({"_id": oid(user_id)})
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    audit("user.update", principal, request, "user", user_id, {"email": payload.email, "role": payload.role})
    return clean_user(row)


@app.delete("/api/v1/users/{user_id}")
async def disable_user(user_id: str, request: Request,
                        principal: dict[str, Any] = Depends(require_scope("auth.manage"))) -> dict[str, Any]:
    mongo().users.update_one({"_id": oid(user_id)}, {"$set": {"is_active": False, "updated_at": now()}})
    audit("user.disable", principal, request, "user", user_id)
    return {"status": "disabled"}


@app.get("/api/v1/api-clients")
async def list_api_clients(_: dict[str, Any] = Depends(require_scope("auth.manage"))) -> list[dict[str, Any]]:
    rows = list_docs("api_clients", sort=[("created_at", DESCENDING)])
    for row in rows:
        row.pop("token_hash", None)
    return rows


@app.post("/api/v1/api-clients")
async def create_client(payload: ApiClientPayload, request: Request,
                         principal: dict[str, Any] = Depends(require_scope("auth.manage"))) -> dict[str, Any]:
    client_id, token = create_api_client(payload.name, payload.scopes)
    audit("api_client.create", principal, request, "api_client", client_id, {"name": payload.name, "scopes": payload.scopes})
    return {"id": client_id, "name": payload.name, "token": token, "scopes": payload.scopes}


@app.get("/api/v1/users")
async def list_users(_: dict[str, Any] = Depends(require_scope("auth.manage"))) -> list[dict[str, Any]]:
    return [clean_user(row) for row in mongo().users.find({}).sort("created_at", DESCENDING)]


@app.post("/api/v1/users")
async def create_or_update_user(payload: UserPayload, request: Request,
                                  principal: dict[str, Any] = Depends(require_scope("auth.manage"))) -> dict[str, Any]:
    update = {"email": payload.email.lower(), "name": payload.name, "role": payload.role,
              "scopes": payload.scopes, "is_active": payload.is_active, "updated_at": now()}
    if payload.password:
        update["password_hash"] = hash_password(payload.password)
    mongo().users.update_one({"email": payload.email.lower()},
                              {"$set": update, "$setOnInsert": {"created_at": now()}}, upsert=True)
    user = mongo().users.find_one({"email": payload.email.lower()})
    audit("user.upsert", principal, request, "user", user["_id"], {"email": payload.email, "role": payload.role})
    item = to_jsonable(user)
    item.pop("password_hash", None)
    return item


@app.get("/api/v1/audit-events")
async def audit_events(_: dict[str, Any] = Depends(require_scope("audit.read"))) -> list[dict[str, Any]]:
    return list_docs("audit_events", sort=[("created_at", DESCENDING)], limit=250)


if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/{page_name}")
async def app_page(page_name: str) -> FileResponse:
    allowed = {"dashboard", "devices", "scans", "networks", "profiles", "identity",
                "credentials", "users", "system", "setup", "findings", "audit"}
    if page_name not in allowed:
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(WEB_DIR / "index.html")


@app.get("/robots.txt")
async def robots() -> PlainTextResponse:
    return PlainTextResponse("User-agent: *\nDisallow: /\n")

from __future__ import annotations

import ipaddress
import json
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from typing import Any

import pymysql
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument
from pymongo.database import Database
from pymysql.cursors import DictCursor

from .config import settings

APP_TZ = ZoneInfo(settings.timezone_name)
client: MongoClient[Any] = MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=3000, tz_aware=True, tzinfo=timezone.utc)


def now() -> datetime:
    return datetime.now(APP_TZ)


def as_app_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(APP_TZ)


def mongo() -> Database[Any]:
    return client[settings.mongo_db]


def oid(value: Any) -> ObjectId:
    if isinstance(value, ObjectId):
        return value
    return ObjectId(str(value))


def to_jsonable(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if isinstance(value, datetime):
        return as_app_time(value).isoformat()
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        result = {key: to_jsonable(item) for key, item in value.items()}
        if "_id" in result and "id" not in result:
            result["id"] = result["_id"]
        return result
    return value


def list_docs(collection: str, query: dict[str, Any] | None = None, *, sort: list[tuple[str, int]] | None = None, limit: int = 250) -> list[dict[str, Any]]:
    cursor = mongo()[collection].find(query or {})
    if sort:
        cursor = cursor.sort(sort)
    if limit:
        cursor = cursor.limit(limit)
    return [to_jsonable(doc) for doc in cursor]


def one_doc(collection: str, query: dict[str, Any]) -> dict[str, Any] | None:
    doc = mongo()[collection].find_one(query)
    return to_jsonable(doc) if doc else None


def wait_for_database() -> None:
    last_error: Exception | None = None
    for _ in range(60):
        try:
            client.admin.command("ping")
            return
        except Exception as exc:  # pragma: no cover - startup resilience
            last_error = exc
            time.sleep(2)
    raise RuntimeError(f"MongoDB not reachable: {last_error}")


def subnet_chunks(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version != 4:
        return [str(network)]
    if network.prefixlen <= 24:
        return [str(subnet) for subnet in network.subnets(new_prefix=24)]
    return [str(network)]


def ensure_indexes() -> None:
    db = mongo()
    db.users.create_index("email", unique=True)
    db.sessions.create_index("token_hash", unique=True)
    db.sessions.create_index("expires_at", expireAfterSeconds=0)
    db.api_clients.create_index("token_hash", unique=True)
    db.networks.create_index("cidr", unique=True)
    db.port_profiles.create_index("name", unique=True)
    db.scan_profiles.create_index("name", unique=True)
    db.scan_runs.create_index([("created_at", DESCENDING)])
    db.scan_runs.create_index("status")
    db.scan_jobs.create_index([("network_id", ASCENDING), ("cidr", ASCENDING)], unique=True)
    db.scan_jobs.create_index([("priority", DESCENDING), ("next_due_at", ASCENDING)])
    db.devices.create_index("device_id", unique=True)
    db.devices.create_index("identifiers.mac")
    db.devices.create_index("identifiers.hostnames")
    db.devices.create_index("current_ips")
    db.devices.create_index("search_text")
    db.observations.create_index([("device_id", ASCENDING), ("observed_at", DESCENDING)])
    db.observations.create_index("ip")
    db.findings.create_index([("device_id", ASCENDING), ("status", ASCENDING)])
    db.audit_events.create_index([("created_at", DESCENDING)])
    db.identity_sources.create_index("name", unique=True)
    db.credentials.create_index("name", unique=True)
    db.credentials.create_index("type")
    db.system_settings.create_index("key", unique=True)


def seed_defaults() -> None:
    from .auth import create_user, hash_password

    db = mongo()
    if db.users.count_documents({}) == 0:
        create_user(
            email=settings.admin_email,
            name="Initial Owner",
            password_hash=hash_password(settings.admin_password),
            role="owner",
            scopes=["admin"],
        )

    db.system_settings.update_one(
        {"key": "global"},
        {"$setOnInsert": {"key": "global", "app_name": settings.app_name, "timezone": settings.timezone_name, "setup_completed": False, "created_at": now()}, "$set": {"updated_at": now()}},
        upsert=True,
    )

    default_ports = [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162,
        389, 443, 445, 465, 500, 515, 548, 587, 631, 636, 873, 993, 995, 1433, 1521, 1723, 1883,
        2049, 2375, 2376, 3000, 3306, 3389, 5000, 5001, 5432, 5900, 5985, 5986, 6379, 8000, 8080,
        8443, 8888, 9000, 9001, 9090, 9100, 9200, 9300, 10000,
    ]
    if db.port_profiles.count_documents({"name": "Known infrastructure ports"}) == 0:
        db.port_profiles.insert_one({
            "name": "Known infrastructure ports",
            "description": "Broad defensive inventory profile.",
            "ports": default_ports,
            "is_default": True,
            "created_at": now(),
            "updated_at": now(),
        })

    profiles = [
        ("Fast discovery", "discovery", True, False, {"description": "ARP/Ping/TCP discovery only"}),
        ("Service detection", "service", True, False, {"nmap": "-sT -sV --version-light"}),
        ("Vulnerability checks", "vulnerability", False, True, {"requires": "explicit approval"}),
        ("Auth audit", "auth_audit", False, True, {"requires": "read-only credentials and approval"}),
        ("Exploit validation", "exploit", False, True, {"requires": "narrow target, approval, and audit"}),
        ("Bruteforce audit", "bruteforce", False, True, {"requires": "narrow target, limits, approval, and audit"}),
    ]
    for name, kind, enabled, approval, config in profiles:
        db.scan_profiles.update_one(
            {"name": name},
            {"$setOnInsert": {"name": name, "kind": kind, "is_enabled": enabled, "requires_manual_approval": approval, "config": config, "created_at": now()}, "$set": {"updated_at": now()}},
            upsert=True,
        )


    default_sources = [("Local ARP table", "arp", {}), ("SSDP multicast", "ssdp", {"timeout": 2}), ("mDNS multicast", "mdns", {"timeout": 2})]
    for name, source_type, config in default_sources:
        db.identity_sources.update_one(
            {"name": name},
            {"$setOnInsert": {"name": name, "type": source_type, "config": config, "is_active": True, "created_at": now(), "last_sync_at": None}, "$set": {"updated_at": now()}},
            upsert=True,
        )

    for cidr in settings.default_networks:
        network = db.networks.find_one_and_update(
            {"cidr": cidr},
            {"$setOnInsert": {"name": cidr, "cidr": cidr, "is_active": True, "excludes": [], "discovery_interval_seconds": settings.discovery_interval_seconds, "deep_scan_interval_minutes": 360, "rate_limit_per_minute": 600, "scan_window": None, "created_at": now()}, "$set": {"updated_at": now()}},
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        ensure_scan_jobs_for_network(network)


def ensure_scan_jobs_for_network(network: dict[str, Any]) -> None:
    db = mongo()
    network_id = str(network["_id"])
    for index, subnet in enumerate(subnet_chunks(network["cidr"])):
        db.scan_jobs.update_one(
            {"network_id": network_id, "cidr": subnet, "kind": "discovery"},
            {"$setOnInsert": {"network_id": network_id, "cidr": subnet, "kind": "discovery", "priority": 0, "next_due_at": now(), "last_started_at": None, "last_finished_at": None, "last_result_count": 0, "created_at": now(), "order": index}},
            upsert=True,
        )


def _legacy_connect():
    return pymysql.connect(
        host=settings.legacy_db_host,
        port=settings.legacy_db_port,
        user=settings.legacy_db_user,
        password=settings.legacy_db_password,
        database=settings.legacy_db_name,
        charset="utf8mb4",
        autocommit=True,
        cursorclass=DictCursor,
        connect_timeout=2,
    )


def migrate_legacy_mysql_once() -> None:
    db = mongo()
    marker = db.schema_migrations.find_one({"name": "legacy_mysql_import_v1"})
    if marker:
        return
    try:
        conn = _legacy_connect()
    except Exception:
        db.schema_migrations.insert_one({"name": "legacy_mysql_import_v1", "applied_at": now(), "skipped": True, "reason": "legacy mysql not reachable"})
        return
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM target_networks")
            for row in cur.fetchall():
                network = db.networks.find_one_and_update(
                    {"cidr": row["cidr"]},
                    {"$set": {"name": row.get("name") or row["cidr"], "cidr": row["cidr"], "is_active": bool(row.get("is_active")), "excludes": json.loads(row.get("excludes") or "[]"), "discovery_interval_seconds": row.get("discovery_interval_seconds") or settings.discovery_interval_seconds, "deep_scan_interval_minutes": row.get("deep_scan_interval_minutes") or 360, "rate_limit_per_minute": row.get("rate_limit_per_minute") or 600, "scan_window": row.get("scan_window"), "updated_at": now()}, "$setOnInsert": {"created_at": now()}},
                    upsert=True,
                    return_document=ReturnDocument.AFTER,
                )
                ensure_scan_jobs_for_network(network)

            cur.execute("SELECT * FROM scan_runs ORDER BY id")
            mysql_scan_to_mongo: dict[int, str] = {}
            for row in cur.fetchall():
                doc = {"legacy_id": row["id"], "mode": row.get("mode"), "status": row.get("status"), "progress": row.get("progress") or 0, "message": row.get("message"), "logs": json.loads(row.get("logs") or "[]"), "created_at": row.get("created_at") or now(), "started_at": row.get("started_at"), "finished_at": row.get("finished_at"), "requested_by_type": row.get("requested_by_type") or "system"}
                existing = db.scan_runs.find_one({"legacy_id": row["id"]})
                if existing:
                    mysql_scan_to_mongo[row["id"]] = str(existing["_id"])
                else:
                    result = db.scan_runs.insert_one(doc)
                    mysql_scan_to_mongo[row["id"]] = str(result.inserted_id)

            cur.execute("SELECT * FROM assets ORDER BY id")
            assets = cur.fetchall()
            for row in assets:
                device_id = f"legacy-ip:{row['primary_ip']}"
                current_ips = [row["primary_ip"]] if row.get("primary_ip") else []
                device = {
                    "device_id": device_id,
                    "display_name": row.get("hostname") or row.get("primary_ip"),
                    "current_ips": current_ips,
                    "identifiers": {"mac": row.get("mac_address"), "hostnames": [row.get("hostname")] if row.get("hostname") else [], "fingerprints": []},
                    "category": row.get("category") or "unknown",
                    "detected": {"vendor": row.get("detected_vendor"), "model": row.get("detected_model"), "os": row.get("detected_os"), "confidence": row.get("vendor_confidence") or 0},
                    "overrides": {"vendor": row.get("override_vendor"), "model": row.get("override_model")},
                    "tags": json.loads(row.get("tags") or "[]") if isinstance(row.get("tags"), str) else (row.get("tags") or []),
                    "notes": row.get("notes"),
                    "services": [],
                    "first_seen_at": row.get("first_seen_at") or now(),
                    "last_seen_at": row.get("last_seen_at") or now(),
                    "is_present": bool(row.get("is_present")),
                    "search_text": row.get("search_text") or row.get("primary_ip") or "",
                    "created_at": now(),
                    "updated_at": now(),
                    "legacy_asset_id": row["id"],
                }
                db.devices.update_one({"device_id": device_id}, {"$set": device}, upsert=True)
                db.observations.insert_one({"device_id": device_id, "type": "legacy_import", "ip": row.get("primary_ip"), "raw": dict(row), "observed_at": row.get("last_seen_at") or now(), "created_at": now()})

            cur.execute("SELECT s.*, a.primary_ip FROM services s JOIN assets a ON a.id=s.asset_id")
            for row in cur.fetchall():
                device_id = f"legacy-ip:{row['primary_ip']}"
                service = {"port": row.get("port"), "protocol": row.get("protocol"), "state": row.get("state"), "service_name": row.get("service_name"), "product": row.get("product"), "version": row.get("version"), "banner": row.get("banner"), "last_seen_at": row.get("last_seen_at") or now()}
                db.devices.update_one({"device_id": device_id}, {"$addToSet": {"services": service}, "$set": {"updated_at": now()}})

        db.schema_migrations.insert_one({"name": "legacy_mysql_import_v1", "applied_at": now(), "skipped": False})
    finally:
        conn.close()



def cleanup_stale_scan_runs() -> None:
    mongo().scan_runs.update_many(
        {"status": {"$in": ["queued", "running", "paused"]}},
        {"$set": {"status": "failed", "message": "Scanner restarted before this run completed", "finished_at": now(), "updated_at": now()}},
    )

def bootstrap() -> None:
    wait_for_database()
    ensure_indexes()
    cleanup_stale_scan_runs()
    seed_defaults()
    migrate_legacy_mysql_once()

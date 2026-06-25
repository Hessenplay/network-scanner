from __future__ import annotations

import os
from dataclasses import dataclass


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("NETWORK_SCANNER_APP_NAME", "Network Inventory Scanner")
    secret_key: str = os.getenv("NETWORK_SCANNER_SECRET_KEY", "change-me-network-scanner-secret")
    mongo_uri: str = os.getenv("NETWORK_SCANNER_MONGO_URI", "mongodb://network-scanner-mongo:27017")
    mongo_db: str = os.getenv("NETWORK_SCANNER_MONGO_DB", "network_inventory")
    timezone_name: str = os.getenv("NETWORK_SCANNER_TIMEZONE", os.getenv("TZ", "Europe/Berlin"))
    admin_email: str = os.getenv("NETWORK_SCANNER_ADMIN_EMAIL", "admin@example.local")
    admin_password: str = os.getenv("NETWORK_SCANNER_ADMIN_PASSWORD", "change-me-now")
    setup_token: str = os.getenv("NETWORK_SCANNER_SETUP_TOKEN", "")
    discovery_interval_seconds: int = int(os.getenv("NETWORK_SCANNER_DISCOVERY_INTERVAL_SECONDS", "120"))
    scan_timeout_seconds: int = int(os.getenv("NETWORK_SCANNER_SCAN_TIMEOUT_SECONDS", "90"))
    discovery_parallel_jobs: int = int(os.getenv("NETWORK_SCANNER_DISCOVERY_PARALLEL_JOBS", "6"))
    discovery_job_lease_seconds: int = int(os.getenv("NETWORK_SCANNER_DISCOVERY_JOB_LEASE_SECONDS", "180"))
    legacy_db_host: str = os.getenv("NETWORK_SCANNER_LEGACY_DB_HOST", "network-scanner-db")
    legacy_db_port: int = int(os.getenv("NETWORK_SCANNER_LEGACY_DB_PORT", "3306"))
    legacy_db_name: str = os.getenv("NETWORK_SCANNER_LEGACY_DB_NAME", "network_inventory")
    legacy_db_user: str = os.getenv("NETWORK_SCANNER_LEGACY_DB_USER", os.getenv("NETWORK_SCANNER_DB_USER", "network_scanner"))
    legacy_db_password: str = os.getenv("NETWORK_SCANNER_LEGACY_DB_PASSWORD", os.getenv("NETWORK_SCANNER_DB_PASSWORD", ""))
    default_networks: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "default_networks",
            _csv(os.getenv("NETWORK_SCANNER_DEFAULT_NETWORKS", "192.168.0.0/16")),
        )


settings = Settings()

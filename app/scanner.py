from __future__ import annotations

import asyncio
import concurrent.futures
import csv
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import struct
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import timedelta
from pathlib import Path
from typing import Any

from bson import ObjectId
from pymongo import ReturnDocument

from .auth import audit
from .config import settings
from .db import ensure_scan_jobs_for_network, mongo, now, oid, subnet_chunks, to_jsonable
from .secrets import decrypt_secret_fields

COMMON_VENDOR_PREFIXES = {
    "00:1A:11": "Google", "00:1B:63": "Apple", "00:50:56": "VMware",
    "08:00:27": "Oracle VirtualBox", "3C:5A:B4": "Google", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "F4:92:BF": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "78:8A:20": "Ubiquiti", "E0:63:DA": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    "A8:5E:45": "Ubiquiti", "00:11:32": "Synology", "00:08:9B": "ICP Electronics",
    "00:0C:29": "VMware", "00:05:69": "VMware", "00:1C:42": "Parallels",
    "F0:9F:C2": "Ubiquiti", "D8:3A:DD": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "10:9A:DD": "Apple", "28:CF:E9": "Apple", "3C:07:54": "Apple",
    "70:56:81": "Apple", "A4:83:E7": "Apple", "F0:18:98": "Apple",
    "18:E8:29": "TP-Link", "50:C7:BF": "TP-Link", "B0:4E:26": "TP-Link",
    "C0:25:E9": "TP-Link", "48:A9:8A": "QNAP", "00:80:77": "Brother",
    "30:05:5C": "Brother", "00:1B:A9": "Brother", "00:17:C8": "Kyocera",
    "00:21:B7": "Lexmark", "00:26:73": "Ricoh", "00:1E:8F": "Canon",
    "00:25:36": "Hikvision", "C4:2F:90": "Hikvision", "BC:AD:28": "Hikvision",
    "3C:E3:6B": "Hikvision", "90:02:A9": "Dahua", "BC:32:5F": "Dahua",
    "04:CF:8C": "Dahua",
}

DISCOVERY_PORTS = [22, 80, 443, 445, 3389, 5000, 8080, 8443, 9100]
HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 9000, 9090, 10000}
HTTPS_PORTS = {443, 5001, 8443, 9443}
SSH_PORTS = {22}

# --- Defaults (overridable per scan) ---
DEFAULT_DISCOVERY_TIMEOUT_S = 12    # was 4 – many hosts need more time
DEFAULT_TCP_PROBE_TIMEOUT_MS = 750  # was 350 – misses slow/overloaded hosts
DEFAULT_RETRY_COUNT = 1             # was 0 – single retry catches transient drops
DEFAULT_RATE_LIMIT = 600            # packets/min


def is_usable_host_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        if not isinstance(addr, ipaddress.IPv4Address):
            return True
        last_octet = int(str(addr).split(".")[-1])
        return last_octet not in {0, 255}
    except ValueError:
        return not ip.startswith("source-only:")


def is_web_port(port: int) -> bool:
    return port in HTTP_PORTS or port in HTTPS_PORTS


def is_generic_http_title(title: str | None) -> bool:
    value = (title or "").strip().lower()
    if not value:
        return True
    generic_prefixes = ("redirect to ", "moved temporarily", "moved permanently",
                        "document moved", "302 found", "301 moved", "index of /")
    return any(value.startswith(p) for p in generic_prefixes)


def has_strong_http_evidence(service: dict[str, Any]) -> bool:
    http = service.get("http") or {}
    if not http.get("status"):
        return False
    if http.get("error") and not (http.get("server") or http.get("title") or http.get("favicon_sha256")):
        return False
    server = (http.get("server") or "").strip()
    title = (http.get("title") or "").strip()
    if server:
        return True
    if title and not is_generic_http_title(title):
        return True
    if http.get("favicon_sha256") and (server or (title and not is_generic_http_title(title))):
        return True
    return False


def has_positive_service_evidence(service: dict[str, Any], *, allow_weak_web: bool = False) -> bool:
    port = int(service.get("port") or 0)
    if service.get("banner") or service.get("product") or service.get("version"):
        if not is_web_port(port):
            return True
    if service.get("ssh", {}).get("banner"):
        return True
    if not is_web_port(port):
        return True
    if has_strong_http_evidence(service):
        return True
    tls = service.get("tls") or {}
    if allow_weak_web and (tls.get("subject") or tls.get("sans")):
        return True
    return False


def has_positive_device_evidence(item: dict[str, Any]) -> bool:
    if not is_usable_host_ip(str(item.get("ip") or "")):
        return False
    if item.get("mac") or item.get("hostname"):
        return True
    fingerprints = item.get("fingerprints") or {}
    if fingerprints.get("ssdp") or fingerprints.get("mdns") or fingerprints.get("netbios") or fingerprints.get("snmp"):
        return True
    services = item.get("services") or []
    return any(has_positive_service_evidence(service) for service in services)


def safe_socket_connect(ip: str, port: int, timeout: float = 2.0) -> socket.socket | None:
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        return sock
    except OSError:
        return None


def extract_http_title(body: bytes) -> str | None:
    text = body[:120_000].decode("utf-8", errors="ignore")
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:240]


def fetch_http_fingerprint(ip: str, port: int, tls: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"scheme": "https" if tls else "http", "port": port}
    conn_cls = http.client.HTTPSConnection if tls else http.client.HTTPConnection
    try:
        conn = conn_cls(ip, port, timeout=3, context=ssl._create_unverified_context()) if tls else conn_cls(ip, port, timeout=3)
        conn.request("GET", "/", headers={"User-Agent": "NetworkInventory/1.0", "Accept": "text/html,*/*"})
        response = conn.getresponse()
        body = response.read(180_000)
        headers = {key.lower(): value for key, value in response.getheaders()}
        result.update({"status": response.status, "server": headers.get("server"),
                       "content_type": headers.get("content-type"),
                       "title": extract_http_title(body), "headers": headers})
        conn.close()
    except Exception as exc:
        result["error"] = str(exc)[:180]
    try:
        conn = conn_cls(ip, port, timeout=3, context=ssl._create_unverified_context()) if tls else conn_cls(ip, port, timeout=3)
        conn.request("GET", "/favicon.ico", headers={"User-Agent": "NetworkInventory/1.0"})
        response = conn.getresponse()
        icon = response.read(256_000)
        if response.status < 400 and icon:
            result["favicon_sha256"] = hashlib.sha256(icon).hexdigest()
            result["favicon_bytes"] = len(icon)
        conn.close()
    except Exception:
        pass
    return result


def fetch_tls_certificate(ip: str, port: int) -> dict[str, Any] | None:
    sock = safe_socket_connect(ip, port, timeout=3)
    if not sock:
        return None
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(sock, server_hostname=ip) as tls_sock:
            der = tls_sock.getpeercert(binary_form=True)
            cert = tls_sock.getpeercert() or {}
            return {"port": port, "sha256": hashlib.sha256(der).hexdigest() if der else None,
                    "subject": cert.get("subject"), "issuer": cert.get("issuer"),
                    "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                    "sans": cert.get("subjectAltName"), "cipher": tls_sock.cipher(),
                    "version": tls_sock.version()}
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def fetch_ssh_banner(ip: str, port: int = 22) -> dict[str, Any] | None:
    sock = safe_socket_connect(ip, port, timeout=3)
    if not sock:
        return None
    try:
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        if banner:
            return {"port": port, "banner": banner, "sha256": hashlib.sha256(banner.encode()).hexdigest()}
    except Exception:
        return None
    finally:
        sock.close()
    return None


def netbios_name_query(ip: str) -> dict[str, Any] | None:
    transaction_id = 0x4E49
    encoded = b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    packet = struct.pack("!HHHHHH", transaction_id, 0, 1, 0, 0, 0) + bytes([32]) + encoded + b"\x00\x00!\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        names = []
        if len(data) > 57:
            count = data[56]
            offset = 57
            for _ in range(min(count, 20)):
                raw = data[offset:offset + 15].decode("ascii", errors="ignore").strip()
                suffix = data[offset + 15] if offset + 15 < len(data) else None
                if raw:
                    names.append({"name": raw, "suffix": suffix})
                offset += 18
        if names:
            return {"names": names}
    except Exception:
        return None
    finally:
        sock.close()
    return None


def ssdp_discover(timeout: float = 2.0) -> dict[str, dict[str, Any]]:
    message = "\r\n".join([
        "M-SEARCH * HTTP/1.1", "HOST: 239.255.255.250:1900",
        'MAN: "ssdp:discover"', "MX: 1", "ST: ssdp:all", "", "",
    ]).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    found: dict[str, dict[str, Any]] = {}
    try:
        sock.sendto(message, ("239.255.255.250", 1900))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode("utf-8", errors="ignore")
            headers = {}
            for line in text.split("\r\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.lower()] = value.strip()
            found[addr[0]] = {"headers": headers, "raw": text[:2000]}
    except Exception:
        pass
    finally:
        sock.close()
    return found


def mdns_discover(timeout: float = 2.0) -> dict[str, dict[str, Any]]:
    query = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + \
            b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    found: dict[str, dict[str, Any]] = {}
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(query, ("224.0.0.251", 5353))
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                break
            strings = re.findall(rb"[A-Za-z0-9_. -]{4,}", data)
            found[addr[0]] = {
                "strings": sorted({item.decode("utf-8", errors="ignore")[:120] for item in strings})[:40],
                "bytes": len(data),
            }
    except Exception:
        pass
    finally:
        sock.close()
    return found


def enrich_device_item(item: dict[str, Any]) -> dict[str, Any]:
    ip = item["ip"]
    services = item.get("services") or []
    fingerprints: dict[str, Any] = {}
    http_results, tls_results, ssh_results = [], [], []
    for service in services:
        port = int(service.get("port") or 0)
        service_name = str(service.get("service_name") or "").lower()
        if port in HTTP_PORTS or service_name in {"http", "http-proxy"}:
            http_info = fetch_http_fingerprint(ip, port, tls=False)
            service["http"] = http_info
            http_results.append(http_info)
            if http_info.get("title") and not service.get("product"):
                service["product"] = http_info.get("server") or http_info.get("title")
        if port in HTTPS_PORTS or service_name in {"https", "ssl/http"}:
            tls_info = fetch_tls_certificate(ip, port)
            if tls_info:
                service["tls"] = tls_info
                tls_results.append(tls_info)
            http_info = fetch_http_fingerprint(ip, port, tls=True)
            service["http"] = http_info
            http_results.append(http_info)
        if port in SSH_PORTS or service_name == "ssh":
            ssh_info = fetch_ssh_banner(ip, port)
            if ssh_info:
                service["ssh"] = ssh_info
                ssh_results.append(ssh_info)
                service["banner"] = service.get("banner") or ssh_info.get("banner")
    nb = netbios_name_query(ip)
    if nb:
        fingerprints["netbios"] = nb
        if not item.get("hostname") and nb.get("names"):
            item["hostname"] = nb["names"][0].get("name")
    if http_results:
        fingerprints["http"] = http_results
    if tls_results:
        fingerprints["tls"] = tls_results
    if ssh_results:
        fingerprints["ssh"] = ssh_results
    if fingerprints:
        item["fingerprints"] = fingerprints
    text = service_text(services, item.get("hostname"))
    if "sma" in text or "sunny webbox" in text or "power reducer" in text:
        item.setdefault("detected_vendor", "SMA")
        item.setdefault("vendor_confidence", 70)
        if "sunny webbox" in text:
            item.setdefault("detected_model", "Sunny WebBox")
        elif "power reducer" in text:
            item.setdefault("detected_model", "Power Reducer Box")
    if "mocana" in text or "ehttp" in text:
        item.setdefault("detected_model", "Embedded network management interface")
    item["services"] = services
    item["category"] = classify_device(services, item.get("hostname"))
    return item


def service_text(services: list[dict[str, Any]], hostname: str | None = None) -> str:
    parts = [hostname or ""]
    for service in services:
        parts.extend([str(service.get("service_name") or ""), str(service.get("product") or ""),
                      str(service.get("version") or ""), str(service.get("banner") or "")])
        http_info = service.get("http") or {}
        tls_info = service.get("tls") or {}
        ssh_info = service.get("ssh") or {}
        parts.extend([str(http_info.get("title") or ""), str(http_info.get("server") or ""),
                      str(ssh_info.get("banner") or ""),
                      json.dumps(tls_info.get("subject") or "", default=str)])
    return " ".join(parts).lower()


def classify_device(services: list[dict[str, Any]], hostname: str | None) -> str:
    ports = {int(s.get("port", 0)) for s in services}
    text = service_text(services, hostname)
    host = (hostname or "").lower()
    if {9100, 515, 631} & ports or any(w in text for w in ["printer", "ipp", "jetdirect", "brother", "kyocera", "ricoh", "lexmark", "canon"]):
        return "printer"
    if {554, 8554} & ports or any(w in text for w in ["rtsp", "hikvision", "dahua", "axis", "camera", "ip cam"]):
        return "camera"
    if any(w in text for w in ["sma ", "sunny webbox", "power reducer", "webbox-20", "solar", "inverter"]):
        return "energy-device"
    if {161, 162} & ports:
        return "network-device"
    if any(w in text for w in ["unifi", "ubiquiti", "mikrotik", "routeros", "openwrt", "dd-wrt", "pfsense", "opnsense", "fortinet", "sophos", "fritz!box", "fritzbox"]):
        if "unifi ap" in text or "access point" in text or "airmax" in text:
            return "access-point"
        if "switch" in text:
            return "switch"
        return "router-firewall"
    if any(w in text for w in ["mocana", "nanoss", "ehhttp", "ehttp", "embedded", "web managed", "managed switch", "smart switch"]):
        if 23 in ports or {22, 80, 443}.issubset(ports):
            return "switch"
        return "network-device"
    if 23 in ports and ({80, 443, 22} & ports):
        return "network-device"
    if any(w in text for w in ["synology", "qnap", "truenas", "freenas", "nas "]):
        return "nas"
    if any(w in text for w in ["proxmox", "vmware esxi", "esxi", "xenserver", "hyper-v"]):
        return "hypervisor"
    if {445, 3389, 5985, 5986} & ports or "microsoft-ds" in text:
        return "windows-host"
    if {3306, 5432, 6379, 9200, 9300, 27017, 1433, 1521} & ports:
        return "database"
    if any(w in text for w in ["home assistant", "grafana", "prometheus", "kubernetes", "docker", "portainer", "nginx", "apache", "openssh", "debian", "ubuntu", "centos", "rocky linux"]):
        if {22, 80, 443, 3000, 5000, 8000, 8080, 8443, 9000, 9090} & ports:
            return "server"
    if (ports <= {80, 443, 8080, 8443, 8000, 8081, 8888, 9000, 9090, 10000}) and ports:
        return "web-device"
    if {22, 80, 443, 8080, 8443, 5000} & ports:
        return "appliance"
    if "cam" in host:
        return "camera"
    return "unknown"


def normalize_mac(mac: str | None) -> str | None:
    if not mac:
        return None
    cleaned = mac.upper().replace("-", ":")
    parts = [part.zfill(2) for part in cleaned.split(":") if part]
    return ":".join(parts[:6]) if len(parts) >= 6 else cleaned


def vendor_from_mac(mac: str | None) -> tuple[str | None, int]:
    normalized = normalize_mac(mac)
    if not normalized:
        return None, 0
    prefix = normalized[:8]
    return COMMON_VENDOR_PREFIXES.get(prefix), 40 if prefix in COMMON_VENDOR_PREFIXES else 0


def hosts_for_cidr(cidr: str) -> list[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    return [str(host) for host in network.hosts()]


def ports_for_default_profile() -> list[int]:
    row = mongo().port_profiles.find_one({"is_default": True}, sort=[("created_at", 1)])
    if not row:
        return DISCOVERY_PORTS
    return [int(port) for port in row.get("ports") or []]


def _run_nmap_args(args: list[str], timeout: int) -> str:
    completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    return completed.stdout if completed.stdout.strip() else ""


def tcp_probe_host(ip: str, ports: list[int], timeout: float | None = None) -> dict[str, Any] | None:
    """Connect-based host probe. timeout_s defaults to DEFAULT_TCP_PROBE_TIMEOUT_MS/1000."""
    t = timeout if timeout is not None else DEFAULT_TCP_PROBE_TIMEOUT_MS / 1000
    open_services = []
    for port in ports:
        sock = safe_socket_connect(ip, port, timeout=t)
        if sock:
            try:
                sock.close()
            except Exception:
                pass
            open_services.append({"port": port, "protocol": "tcp", "state": "open",
                                   "service_name": None, "product": None, "version": None, "banner": None})
    if open_services:
        return {"ip": ip, "services": open_services, "category": classify_device(open_services, None), "raw_source": "tcp-probe"}
    return None


def run_fast_tcp_discovery(cidr: str, timeout_ms: int | None = None) -> list[dict[str, Any]]:
    t = (timeout_ms if timeout_ms is not None else DEFAULT_TCP_PROBE_TIMEOUT_MS) / 1000
    hosts = hosts_for_cidr(cidr)
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=128) as executor:
        futures = [executor.submit(tcp_probe_host, ip, DISCOVERY_PORTS, t) for ip in hosts]
        for future in concurrent.futures.as_completed(futures, timeout=60):
            try:
                item = future.result()
            except Exception:
                item = None
            if item:
                results.append(item)
    return results


def run_ping_discovery(
    cidr: str,
    host_timeout_s: int | None = None,
    rtt_timeout_ms: int | None = None,
    nmap_retries: int | None = None,
    tcp_timeout_ms: int | None = None,
) -> list[dict[str, Any]]:
    """
    Two-phase discovery:
      1. nmap ping sweep (ARP + ICMP + TCP SYN on common ports)
      2. fallback to parallel TCP connect probe if nmap finds nothing or fails
    """
    host_t = host_timeout_s if host_timeout_s is not None else DEFAULT_DISCOVERY_TIMEOUT_S
    rtt_t = rtt_timeout_ms if rtt_timeout_ms is not None else 800
    retries = nmap_retries if nmap_retries is not None else DEFAULT_RETRY_COUNT
    probe_ports = ",".join(str(p) for p in DISCOVERY_PORTS)
    args = [
        "nmap", "-sn", "-n",
        "--max-retries", str(retries),
        "--host-timeout", f"{host_t}s",
        "--initial-rtt-timeout", "200ms",
        "--max-rtt-timeout", f"{rtt_t}ms",
        "--min-parallelism", "32",
        "--max-parallelism", "256",
        "-PE", f"-PS{probe_ports}", f"-PA{probe_ports}",
        "-oX", "-",
        cidr,
    ]
    try:
        xml = _run_nmap_args(args, host_t * 4 + 30)
        results = parse_nmap_xml(xml) if xml else []
    except Exception:
        results = []

    if results:
        return results
    # nmap found nothing or failed – fall back to raw TCP probe
    return run_fast_tcp_discovery(cidr, tcp_timeout_ms)


def run_port_scan(hosts: list[str], ports: list[int], service_detection: bool,
                  host_timeout_s: int | None = None) -> list[dict[str, Any]]:
    if not hosts:
        return []
    t = host_timeout_s if host_timeout_s is not None else settings.scan_timeout_seconds
    args = [
        "nmap", "-oX", "-", "-n",
        "--max-retries", "1",
        "--host-timeout", f"{t}s",
        "-p", ",".join(str(p) for p in ports),
    ]
    if service_detection:
        args.extend(["-sT", "-sV", "--version-light"])
    else:
        args.extend(["-sT"])
    args.extend(hosts)
    xml = _run_nmap_args(args, max(t * len(hosts) + 60, 300))
    return parse_nmap_xml(xml) if xml else []


def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    root = ET.fromstring(xml_text)
    results: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") != "up":
            continue
        ip = mac = vendor = hostname = None
        for address in host.findall("address"):
            if address.attrib.get("addrtype") == "ipv4":
                ip = address.attrib.get("addr")
            if address.attrib.get("addrtype") == "mac":
                mac = normalize_mac(address.attrib.get("addr"))
                vendor = address.attrib.get("vendor")
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            first = hostnames_el.find("hostname")
            hostname = first.attrib.get("name") if first is not None else None
        services = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                svc = port.find("service")
                service = {
                    "port": int(port.attrib["portid"]),
                    "protocol": port.attrib.get("protocol", "tcp"),
                    "state": "open",
                    "service_name": svc.attrib.get("name") if svc is not None else None,
                    "product": svc.attrib.get("product") if svc is not None else None,
                    "version": svc.attrib.get("version") if svc is not None else None,
                    "banner": " ".join(filter(None, [svc.attrib.get("product"), svc.attrib.get("version")])) if svc is not None else None,
                }
                services.append(service)
        if ip and is_usable_host_ip(ip):
            detected_vendor, confidence = vendor_from_mac(mac)
            if vendor:
                detected_vendor, confidence = vendor, 60
            results.append({
                "ip": ip, "mac": mac, "hostname": hostname,
                "detected_vendor": detected_vendor, "vendor_confidence": confidence,
                "services": services,
                "category": classify_device(services, hostname),
                "raw_source": "nmap",
            })
    return results


def merge_results(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for group in groups:
        for item in group:
            ip = item["ip"]
            if not is_usable_host_ip(str(ip)):
                continue
            existing = merged.setdefault(ip, {"ip": ip, "services": []})
            for key in ["mac", "hostname", "detected_vendor", "vendor_confidence", "category", "raw_source", "fingerprints"]:
                if item.get(key) and not existing.get(key):
                    existing[key] = item[key]
            services_by_key = {(s.get("protocol", "tcp"), int(s.get("port", 0))): s for s in existing.get("services", [])}
            for service in item.get("services") or []:
                services_by_key[(service.get("protocol", "tcp"), int(service.get("port", 0)))] = service
            existing["services"] = sorted(services_by_key.values(), key=lambda s: (str(s.get("protocol", "tcp")), int(s.get("port", 0))))
            existing["category"] = classify_device(existing["services"], existing.get("hostname"))
    return list(merged.values())


def fingerprint_for(item: dict[str, Any]) -> str | None:
    parts = []
    if item.get("hostname"):
        parts.append(str(item["hostname"]).lower())
    for service in item.get("services") or []:
        specific = " ".join(str(service.get(k) or "") for k in ("product", "version", "banner")).strip()
        http_info = service.get("http") or {}
        tls_info = service.get("tls") or {}
        ssh_info = service.get("ssh") or {}
        specific = " ".join(filter(None, [specific, http_info.get("title"), http_info.get("server"),
                                           http_info.get("favicon_sha256"), tls_info.get("sha256"), ssh_info.get("sha256")])).strip()
        if specific:
            parts.append(f"{service.get('protocol','tcp')}:{service.get('port')}:{service.get('service_name') or ''}:{specific}".lower())
    for group in (item.get("fingerprints") or {}).values():
        parts.append(json.dumps(group, sort_keys=True, default=str)[:1000].lower())
    if len(parts) < 2:
        return None
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]


def find_existing_device(item: dict[str, Any]) -> dict[str, Any] | None:
    db = mongo()
    mac = normalize_mac(item.get("mac"))
    if mac:
        doc = db.devices.find_one({"identifiers.mac": mac})
        if doc:
            return doc
    hostname = (item.get("hostname") or "").lower()
    if hostname:
        doc = db.devices.find_one({"identifiers.hostnames": hostname})
        if doc:
            return doc
    fp = fingerprint_for(item)
    if fp:
        doc = db.devices.find_one({"identifiers.fingerprints": fp})
        if doc:
            return doc
    ip = item.get("ip")
    if ip:
        return db.devices.find_one({"current_ips": ip})
    return None


def device_id_for(item: dict[str, Any], existing: dict[str, Any] | None = None) -> str:
    if existing:
        return str(existing["device_id"])
    mac = normalize_mac(item.get("mac"))
    if mac:
        return "mac:" + mac.replace(":", "").lower()
    hostname = (item.get("hostname") or "").lower()
    if hostname:
        return "host:" + hashlib.sha256(hostname.encode()).hexdigest()[:24]
    fp = fingerprint_for(item)
    if fp:
        return "fp:" + fp
    return "ip-observed:" + str(item["ip"])


def search_text_for(doc: dict[str, Any]) -> str:
    detected = doc.get("detected") or {}
    overrides = doc.get("overrides") or {}
    identifiers = doc.get("identifiers") or {}
    parts = [
        doc.get("device_id"), doc.get("display_name"), doc.get("category"),
        detected.get("vendor"), detected.get("model"), detected.get("os"),
        overrides.get("vendor"), overrides.get("model"),
        identifiers.get("mac"),
        " ".join(identifiers.get("hostnames") or []),
        " ".join(doc.get("current_ips") or []),
        " ".join(doc.get("tags") or []),
    ]
    for service in doc.get("services") or []:
        parts.extend([str(service.get("port") or ""), service.get("service_name"),
                      service.get("product"), service.get("version"), service.get("banner")])
        parts.append(json.dumps(service.get("http") or {}, sort_keys=True, default=str))
        parts.append(json.dumps(service.get("tls") or {}, sort_keys=True, default=str))
        parts.append(json.dumps(service.get("ssh") or {}, sort_keys=True, default=str))
    parts.append(json.dumps(doc.get("fingerprints") or {}, sort_keys=True, default=str))
    return " ".join(str(part) for part in parts if part).lower()


def upsert_defensive_findings(device_id: str, item: dict[str, Any]) -> None:
    db = mongo()
    risky_ports = {
        23: ("high", "Telnet service exposed"),
        445: ("medium", "SMB service exposed"),
        3389: ("medium", "Remote Desktop service exposed"),
        3306: ("medium", "MySQL/MariaDB service exposed"),
        5432: ("medium", "PostgreSQL service exposed"),
        6379: ("high", "Redis service exposed"),
        9200: ("high", "Elasticsearch service exposed"),
        5985: ("medium", "WinRM HTTP service exposed"),
        5986: ("medium", "WinRM HTTPS service exposed"),
    }
    for service in item.get("services") or []:
        port = int(service.get("port") or 0)
        if port in risky_ports:
            severity, title = risky_ports[port]
            key = f"{device_id}:port:{port}:exposed"
            db.findings.update_one(
                {"finding_key": key},
                {"$set": {"device_id": device_id, "title": title, "severity": severity, "status": "open",
                           "source": "scanner", "evidence": service, "last_seen_at": now(), "updated_at": now()},
                 "$setOnInsert": {"finding_key": key, "created_at": now()}},
                upsert=True,
            )
        http_info = service.get("http") or {}
        if http_info.get("title") or http_info.get("server"):
            title_text = " ".join(str(http_info.get(k) or "") for k in ("title", "server")).lower()
            if any(w in title_text for w in ["login", "admin", "router", "nas", "camera", "ubiquiti", "mikrotik", "openwrt", "proxmox"]):
                key = f"{device_id}:port:{port}:admin-http"
                db.findings.update_one(
                    {"finding_key": key},
                    {"$set": {"device_id": device_id, "title": "Administrative web interface detected",
                               "severity": "info", "status": "open", "source": "scanner",
                               "evidence": http_info, "last_seen_at": now(), "updated_at": now()},
                     "$setOnInsert": {"finding_key": key, "created_at": now()}},
                    upsert=True,
                )


def upsert_device(item: dict[str, Any], scan_run_id: str | None, network_id: str | None, source: str = "scan") -> str:
    db = mongo()
    existing = find_existing_device(item)
    device_id = device_id_for(item, existing)
    mac = normalize_mac(item.get("mac"))
    hostname = (item.get("hostname") or "").lower() or None
    fp = fingerprint_for(item)
    old_ips = set(existing.get("current_ips", [])) if existing else set()
    old_ports = {int(s.get("port", 0)) for s in existing.get("services", [])} if existing else set()
    new_ports = {int(s.get("port", 0)) for s in item.get("services", [])}
    vendor = item.get("detected_vendor")
    confidence = int(item.get("vendor_confidence") or 0)
    update = {
        "$set": {
            "device_id": device_id,
            "display_name": hostname or item.get("ip"),
            "category": item.get("category") or (existing or {}).get("category") or "unknown",
            "fingerprints": item.get("fingerprints") or (existing or {}).get("fingerprints") or {},
            "last_seen_at": now(), "is_present": True, "updated_at": now(),
        },
        "$setOnInsert": {
            "first_seen_at": now(), "created_at": now(),
            "tags": [], "notes": None,
            "overrides": {"vendor": None, "model": None},
            "identity_sources": [],
        },
        "$addToSet": {"current_ips": item["ip"]},
    }
    if mac:
        update["$set"]["identifiers.mac"] = mac
    if hostname:
        update["$addToSet"]["identifiers.hostnames"] = hostname
    if fp:
        update["$addToSet"]["identifiers.fingerprints"] = fp
    if vendor and confidence >= int(((existing or {}).get("detected") or {}).get("confidence") or 0):
        update["$set"]["detected.vendor"] = vendor
        update["$set"]["detected.confidence"] = confidence
    if item.get("detected_model"):
        update["$set"]["detected.model"] = item.get("detected_model")
    if item.get("detected_os"):
        update["$set"]["detected.os"] = item.get("detected_os")
    if item.get("services"):
        update["$set"]["services"] = item["services"]
    doc = db.devices.find_one_and_update({"device_id": device_id}, update, upsert=True, return_document=ReturnDocument.AFTER)
    doc["search_text"] = search_text_for(doc)
    db.devices.update_one({"_id": doc["_id"]}, {"$set": {"search_text": doc["search_text"]}})
    event_types = ["device_seen"]
    if not existing:
        event_types.append("device_first_seen")
    if item["ip"] not in old_ips:
        event_types.append("ip_seen")
    if old_ports != new_ports:
        event_types.append("ports_changed")
    db.observations.insert_one({
        "device_id": device_id, "scan_run_id": scan_run_id, "network_id": network_id,
        "type": "scan_observation", "events": event_types,
        "ip": item.get("ip"), "mac": mac, "hostname": hostname,
        "services": item.get("services") or [],
        "detected": {"vendor": vendor, "model": item.get("detected_model"), "os": item.get("detected_os"), "confidence": confidence},
        "fingerprints": item.get("fingerprints") or {}, "raw": item,
        "source": source, "observed_at": now(), "created_at": now(),
    })
    upsert_defensive_findings(device_id, item)
    return device_id


def parse_local_arp(path: str = "/proc/net/arp") -> list[dict[str, Any]]:
    rows = []
    try:
        lines = Path(path).read_text().splitlines()[1:]
    except Exception:
        return rows
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
            rows.append({"ip": parts[0], "mac": normalize_mac(parts[3]),
                         "source_detail": {"device": parts[5] if len(parts) > 5 else None}})
    return rows


def parse_dhcp_leases(path: str) -> list[dict[str, Any]]:
    rows = []
    try:
        text = Path(path).read_text(errors="ignore")
    except Exception:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 4 and re.match(r"^[0-9a-fA-F:.-]{11,17}$", parts[1]) and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[2]):
            rows.append({"ip": parts[2], "mac": normalize_mac(parts[1]),
                         "hostname": None if parts[3] == "*" else parts[3],
                         "source_detail": {"lease": parts[0]}})
            continue
        host_match = re.search(r"hardware ethernet\s+([0-9a-fA-F:.-]+);", line)
        if host_match:
            rows.append({"mac": normalize_mac(host_match.group(1)), "source_detail": {"raw": line}})
    return rows


def parse_inventory_file(path: str) -> list[dict[str, Any]]:
    try:
        raw = Path(path).read_text(errors="ignore")
    except Exception:
        return []
    if path.endswith(".json"):
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("devices") or data.get("leases") or []
        return [item for item in data if isinstance(item, dict)]
    rows = []
    for row in csv.DictReader(raw.splitlines()):
        rows.append({"ip": row.get("ip") or row.get("address"),
                     "mac": normalize_mac(row.get("mac") or row.get("mac_address")),
                     "hostname": row.get("hostname") or row.get("name"),
                     "detected_vendor": row.get("vendor"), "detected_model": row.get("model"),
                     "source_detail": row})
    return rows


def run_snmpwalk(host: str, community: str, oid_text: str, timeout: int = 5) -> str | None:
    try:
        completed = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-t", str(timeout), "-r", "1", host, oid_text],
            capture_output=True, text=True, timeout=timeout + 3, check=False,
        )
        return completed.stdout.strip() if completed.returncode == 0 and completed.stdout.strip() else None
    except Exception:
        return None


def parse_snmp_system(host: str, community: str) -> list[dict[str, Any]]:
    sys_descr = run_snmpwalk(host, community, "1.3.6.1.2.1.1.1.0")
    sys_name = run_snmpwalk(host, community, "1.3.6.1.2.1.1.5.0")
    result: dict[str, Any] = {"ip": host, "hostname": None,
                               "fingerprints": {"snmp": {"sysDescr": sys_descr, "sysName": sys_name}},
                               "source_detail": {"host": host}}
    if sys_name:
        result["hostname"] = sys_name.split("=", 1)[-1].replace("STRING:", "").strip().strip('"')[:120]
    if sys_descr:
        clean = sys_descr.split("=", 1)[-1].replace("STRING:", "").strip().strip('"')
        result["detected_model"] = clean[:240]
        result["category"] = "network-device"
    return [result]


def sync_identity_source(source: dict[str, Any]) -> dict[str, Any]:
    config = source.get("config") or {}
    source_type = source.get("type")
    rows: list[dict[str, Any]] = []
    if source_type == "arp":
        rows = parse_local_arp(config.get("path") or "/proc/net/arp")
    elif source_type == "dhcp":
        path = config.get("path")
        rows = parse_dhcp_leases(path) if path else []
    elif source_type == "file":
        path = config.get("path")
        rows = parse_inventory_file(path) if path else []
    elif source_type == "snmp":
        credential = None
        credential_id = source.get("credential_id") or config.get("credential_id")
        if credential_id:
            try:
                credential = mongo().credentials.find_one({"_id": oid(credential_id), "is_active": True})
            except Exception:
                credential = None
        secret_fields = decrypt_secret_fields((credential or {}).get("encrypted_secret_fields"))
        host = config.get("host") or secret_fields.get("host")
        community = config.get("community") or secret_fields.get("community")
        rows = parse_snmp_system(host, community) if host and community else []
    elif source_type == "ssdp":
        rows = [{"ip": ip, "fingerprints": {"ssdp": data}} for ip, data in ssdp_discover(float(config.get("timeout", 2))).items()]
    elif source_type == "mdns":
        rows = [{"ip": ip, "fingerprints": {"mdns": data}} for ip, data in mdns_discover(float(config.get("timeout", 2))).items()]
    imported = 0
    for row in rows:
        if not row.get("ip") and not row.get("mac") and not row.get("hostname"):
            continue
        if not row.get("ip"):
            row["ip"] = "source-only:" + (row.get("mac") or row.get("hostname") or
                                           hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:12])
        row.setdefault("services", [])
        row.setdefault("category", row.get("category") or "unknown")
        upsert_device(row, None, None, source=f"identity:{source_type}")
        imported += 1
    mongo().identity_sources.update_one(
        {"_id": source["_id"]},
        {"$set": {"last_sync_at": now(), "last_sync_result": {"imported": imported, "seen": len(rows)}, "updated_at": now()}},
    )
    return {"imported": imported, "seen": len(rows)}


def create_scan_run(mode: str, network_id: str | None = None, profile_id: str | None = None,
                    requested_by_type: str = "system", requested_by_id: str | None = None,
                    cidr: str | None = None, job_id: str | None = None,
                    options: dict[str, Any] | None = None) -> str:
    target_label = cidr
    if not target_label and network_id:
        try:
            network = mongo().networks.find_one({"_id": oid(network_id)})
            target_label = (network or {}).get("cidr")
        except Exception:
            target_label = None
    if not target_label:
        cidrs = [row.get("cidr") for row in mongo().networks.find({"is_active": True}, {"cidr": 1}).sort("created_at", 1)]
        target_label = ", ".join([c for c in cidrs if c]) or "Keine aktiven Zielnetze"
    result = mongo().scan_runs.insert_one({
        "mode": mode,
        "network_id": str(network_id) if network_id else None,
        "profile_id": str(profile_id) if profile_id else None,
        "job_id": str(job_id) if job_id else None,
        "cidr": cidr, "target_label": target_label,
        "requested_by_type": requested_by_type,
        "requested_by_id": str(requested_by_id) if requested_by_id else None,
        "status": "queued", "progress": 0, "message": None, "logs": [],
        "options": options or {},
        "created_at": now(), "started_at": None, "finished_at": None,
    })
    return str(result.inserted_id)


def update_scan_run(scan_run_id: str, status: str, progress: int,
                    message: str | None = None, logs: list[str] | None = None) -> None:
    updates: dict[str, Any] = {"status": status, "progress": progress,
                                "message": message, "logs": logs or [], "updated_at": now()}
    row = mongo().scan_runs.find_one({"_id": oid(scan_run_id)}, {"started_at": 1})
    if status == "running" and row and not row.get("started_at"):
        updates["started_at"] = now()
    if status in {"completed", "failed", "cancelled"}:
        updates["finished_at"] = now()
    mongo().scan_runs.update_one({"_id": oid(scan_run_id)}, {"$set": updates})


def scan_state(scan_run_id: str) -> str | None:
    row = mongo().scan_runs.find_one({"_id": oid(scan_run_id)}, {"status": 1})
    return row.get("status") if row else None


async def wait_if_paused_or_cancelled(scan_run_id: str, logs: list[str]) -> bool:
    while True:
        state = scan_state(scan_run_id)
        if state == "cancelled":
            logs.append("Cancelled before next subnet")
            update_scan_run(scan_run_id, "cancelled", 100, "Cancelled", logs)
            return False
        if state != "paused":
            return True
        await asyncio.sleep(5)


def due_jobs(limit: int) -> list[dict[str, Any]]:
    return list(
        mongo().scan_jobs.find({"kind": "discovery", "next_due_at": {"$lte": now()}, "status": {"$ne": "running"}})
        .sort([("last_finished_at", 1), ("order", 1), ("next_due_at", 1)])
        .limit(limit)
    )


def recover_stale_jobs() -> int:
    stale_before = now() - timedelta(seconds=settings.discovery_job_lease_seconds)
    result = mongo().scan_jobs.update_many(
        {"kind": "discovery", "status": "running", "updated_at": {"$lt": stale_before}},
        {"$set": {"status": "queued", "progress": 0, "message": "Lease expired; queued again",
                  "current_scan_id": None, "next_due_at": now(), "updated_at": now()}},
    )
    return int(result.modified_count)


def reset_failed_scan_jobs() -> int:
    """Reset all failed scan jobs so they will be retried on next scheduler tick."""
    result = mongo().scan_jobs.update_many(
        {"kind": "discovery", "status": "failed"},
        {"$set": {"status": "queued", "progress": 0, "message": "Reset by user request",
                  "current_scan_id": None, "next_due_at": now(), "updated_at": now(), "last_error": None}},
    )
    return int(result.modified_count)


def reset_single_scan_job(job_id: str) -> dict[str, Any] | None:
    """Reset a single job to queued so it runs on next scheduler tick."""
    mongo().scan_jobs.update_one(
        {"_id": oid(job_id)},
        {"$set": {"status": "queued", "progress": 0, "message": "Reset by user request",
                  "current_scan_id": None, "next_due_at": now(), "updated_at": now(), "last_error": None}},
    )
    return mongo().scan_jobs.find_one({"_id": oid(job_id)})


def reserve_job(job: dict[str, Any]) -> dict[str, Any] | None:
    return mongo().scan_jobs.find_one_and_update(
        {"_id": job["_id"], "kind": "discovery", "status": {"$ne": "running"}, "next_due_at": {"$lte": now()}},
        {"$set": {"status": "running", "progress": 0, "message": "Queued by scheduler",
                  "last_started_at": now(), "updated_at": now(),
                  "next_due_at": now() + timedelta(seconds=settings.discovery_job_lease_seconds)}},
        return_document=ReturnDocument.AFTER,
    )


def update_scan_job(job_id: str | None, **fields: Any) -> None:
    if not job_id:
        return
    fields["updated_at"] = now()
    mongo().scan_jobs.update_one({"_id": oid(job_id)}, {"$set": fields})


async def run_scan(
    scan_run_id: str,
    network_id: str | None,
    mode: str,
    cidr: str | None = None,
    job_id: str | None = None,
    options: dict[str, Any] | None = None,
) -> None:
    """
    Execute a scan run with configurable options.

    options keys (all optional):
      discovery_timeout_s  – nmap per-host timeout (default 12)
      tcp_timeout_ms       – fallback TCP probe timeout (default 750)
      retry_count          – times to retry a failed subnet (default 1)
      rate_limit           – nmap rate limit / min (not yet plumbed into nmap args, reserved)
    """
    opts = options or {}
    discovery_timeout_s = int(opts.get("discovery_timeout_s") or DEFAULT_DISCOVERY_TIMEOUT_S)
    tcp_timeout_ms = int(opts.get("tcp_timeout_ms") or DEFAULT_TCP_PROBE_TIMEOUT_MS)
    retry_count = int(opts.get("retry_count") if opts.get("retry_count") is not None else DEFAULT_RETRY_COUNT)

    logs: list[str] = []
    result_count = 0
    final_status = "running"
    final_message = "Starting scan"
    try:
        update_scan_run(scan_run_id, "running", 1, "Starting scan", logs)
        update_scan_job(job_id, status="running", current_scan_id=scan_run_id, progress=1,
                        message="Starting scan", started_at=now())
        db = mongo()
        if network_id:
            network = db.networks.find_one({"_id": oid(network_id)})
            networks = [network] if network else []
        else:
            networks = list(db.networks.find({"is_active": True}).sort("created_at", 1))
        ports = ports_for_default_profile()

        # Ambient discovery (SSDP/mDNS)
        ambient_results: dict[str, dict[str, Any]] = {}
        if mode in {"discovery", "service", "deep"}:
            ssdp = await asyncio.to_thread(ssdp_discover, 1.5)
            mdns = await asyncio.to_thread(mdns_discover, 1.5)
            for ip, data in ssdp.items():
                ambient_results.setdefault(ip, {"ip": ip, "services": [], "fingerprints": {}})["fingerprints"]["ssdp"] = data
            for ip, data in mdns.items():
                ambient_results.setdefault(ip, {"ip": ip, "services": [], "fingerprints": {}})["fingerprints"]["mdns"] = data

        targets: list[tuple[dict[str, Any], str]] = []
        for network in networks:
            if not network:
                continue
            chunks = [cidr] if cidr else subnet_chunks(network["cidr"])
            targets.extend((network, chunk) for chunk in chunks if chunk)

        if not targets:
            raise RuntimeError("No active network targets found")

        for index, (network, target_cidr) in enumerate(targets):
            if not await wait_if_paused_or_cancelled(scan_run_id, logs):
                return

            host_count = ipaddress.ip_network(target_cidr, strict=False).num_addresses
            logs.append(f"Scanning {target_cidr} ({host_count} addresses, timeout={discovery_timeout_s}s, retry={retry_count})")
            progress = min(95, int((index / max(len(targets), 1)) * 90) + 5)
            update_scan_run(scan_run_id, "running", progress, logs[-1], logs)
            update_scan_job(job_id, status="running", current_scan_id=scan_run_id, progress=progress, message=logs[-1])

            # Retry loop for this subnet
            ping_results: list[dict[str, Any]] = []
            last_exc: Exception | None = None
            for attempt in range(retry_count + 1):
                try:
                    if mode in {"discovery", "service", "deep"}:
                        ping_results = await asyncio.to_thread(
                            run_ping_discovery, target_cidr,
                            discovery_timeout_s, None, None, tcp_timeout_ms
                        )
                    if ping_results:
                        if attempt > 0:
                            logs.append(f"{target_cidr}: succeeded on attempt {attempt + 1}")
                        break
                    elif attempt < retry_count:
                        logs.append(f"{target_cidr}: no hosts found on attempt {attempt + 1}, retrying…")
                        await asyncio.sleep(2 ** attempt)
                except Exception as exc:
                    last_exc = exc
                    if attempt < retry_count:
                        logs.append(f"{target_cidr}: error on attempt {attempt + 1} ({exc}), retrying…")
                        await asyncio.sleep(2 ** attempt)
                    else:
                        logs.append(f"{target_cidr}: failed after {retry_count + 1} attempts: {exc}")

            responsive_hosts = sorted({item["ip"] for item in ping_results if item.get("ip")})
            if mode == "discovery":
                hosts = responsive_hosts
            else:
                hosts = responsive_hosts or hosts_for_cidr(target_cidr)

            scan_ports = DISCOVERY_PORTS if mode == "discovery" else ports
            port_results = await asyncio.to_thread(
                run_port_scan, hosts, scan_ports, mode != "discovery", discovery_timeout_s
            ) if hosts else []

            ambient_for_subnet = []
            target_net = ipaddress.ip_network(target_cidr, strict=False)
            for ip, item in ambient_results.items():
                try:
                    if ipaddress.ip_address(ip) in target_net:
                        ambient_for_subnet.append(item)
                except ValueError:
                    pass

            results = merge_results(ping_results, port_results, ambient_for_subnet)
            if mode in {"discovery", "service", "deep"}:
                results = await asyncio.gather(*(asyncio.to_thread(enrich_device_item, item) for item in results))

            valid_results = [item for item in results if has_positive_device_evidence(item)]
            dropped = len(results) - len(valid_results)
            if dropped:
                logs.append(f"{target_cidr}: dropped {dropped} weak/false-positive candidates")
            for item in valid_results:
                upsert_device(item, scan_run_id, str(network["_id"]), "scheduled" if job_id else "manual")
            result_count += len(valid_results)
            logs.append(f"{target_cidr}: {len(valid_results)} responsive devices found")
            update_scan_run(scan_run_id, "running", progress, logs[-1], logs)
            update_scan_job(job_id, status="running", current_scan_id=scan_run_id,
                            progress=min(99, progress + 20), message=logs[-1],
                            last_result_count=len(valid_results))

        final_status = "completed"
        final_message = f"Scan completed – {result_count} devices"
        update_scan_run(scan_run_id, "completed", 100, final_message, logs)
        audit("scan.completed", resource_type="scan_run", resource_id=scan_run_id,
              details={"mode": mode, "devices": result_count})

    except Exception as exc:
        final_status = "failed"
        final_message = str(exc)
        logs.append(f"ERROR: {exc}")
        update_scan_run(scan_run_id, "failed", 100, final_message, logs)
        update_scan_job(job_id, status="failed", current_scan_id=scan_run_id,
                        progress=100, message=final_message, last_error=final_message)
        audit("scan.failed", resource_type="scan_run", resource_id=scan_run_id,
              details={"mode": mode, "error": str(exc)})

    finally:
        if job_id:
            interval = settings.discovery_interval_seconds
            if network_id:
                network = mongo().networks.find_one({"_id": oid(network_id)})
                interval = int((network or {}).get("discovery_interval_seconds") or interval)
            next_due = now() + timedelta(seconds=interval)
            terminal_status = "idle" if final_status == "completed" else "failed"
            mongo().scan_jobs.update_one(
                {"_id": oid(job_id)},
                {"$set": {"status": terminal_status, "current_scan_id": None, "progress": 100,
                           "message": final_message, "last_finished_at": now(),
                           "last_result_count": result_count, "priority": 0, "next_due_at": next_due}},
            )


class ScannerScheduler:
    def __init__(self) -> None:
        self.tasks: set[asyncio.Task[Any]] = set()
        self.last_tick = 0.0

    async def start(self) -> None:
        while True:
            await asyncio.sleep(5)
            if time.time() - self.last_tick < 5:
                continue
            self.last_tick = time.time()
            recover_stale_jobs()
            active = [task for task in self.tasks if not task.done()]
            self.tasks = set(active)
            slots = max(0, settings.discovery_parallel_jobs - len(self.tasks))
            if slots <= 0:
                continue
            for job in due_jobs(slots):
                reserved = reserve_job(job)
                if not reserved:
                    continue
                network = mongo().networks.find_one({"_id": oid(reserved["network_id"]), "is_active": True})
                if not network:
                    update_scan_job(str(reserved["_id"]), status="skipped", progress=0,
                                    message="Network inactive", current_scan_id=None)
                    continue
                scan_id = create_scan_run("discovery", str(network["_id"]),
                                          cidr=reserved["cidr"], job_id=str(reserved["_id"]))
                update_scan_job(str(reserved["_id"]), current_scan_id=scan_id, progress=1,
                                message=f"Started {reserved['cidr']}")
                task = asyncio.create_task(
                    run_scan(scan_id, str(network["_id"]), "discovery",
                             cidr=reserved["cidr"], job_id=str(reserved["_id"]))
                )
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)

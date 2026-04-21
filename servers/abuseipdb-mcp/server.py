"""
AbuseIPDB MCP Server

Exposes AbuseIPDB API v2 endpoints as MCP tools for threat intelligence
on IP addresses. Runs as a Streamable HTTP server with per-request
credential passthrough via X-AbuseIPDB-Key header.
"""

import ipaddress
import json
import logging
import os
import re
import sys

import requests
from mcp.server.fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("abuseipdb-mcp")

HOST = os.environ.get("FASTMCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("FASTMCP_PORT", "8008"))
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() != "false"

mcp = FastMCP(
    "abuseipdb-mcp",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)

BASE_URL = "https://api.abuseipdb.com/api/v2"


def _validate_ip(ip_address: str) -> str:
    try:
        return str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address: '{ip_address}'")


def _validate_cidr(network: str) -> str:
    try:
        return str(ipaddress.ip_network(network.strip(), strict=False))
    except ValueError:
        raise ValueError(f"Invalid CIDR network: '{network}'")


def _clamp(value: int, low: int, high: int) -> int:
    return max(low, min(high, value))


def _get_api_key() -> str:
    try:
        headers = get_http_headers()
        if headers:
            key = headers.get("x-abuseipdb-key", "")
            if key:
                return key
    except Exception:
        pass
    raise RuntimeError(
        "Missing X-AbuseIPDB-Key header. "
        "Pass your API key via the X-AbuseIPDB-Key HTTP header."
    )


def _abuseipdb_headers() -> dict:
    return {
        "Accept": "application/json",
        "Key": _get_api_key(),
    }


def _format_response(data: dict) -> str:
    return json.dumps(data, indent=2, default=str)


@mcp.tool()
def check_ip(ip_address: str, max_age_days: int = 90, verbose: bool = True) -> str:
    """Check an IP address against the AbuseIPDB database.

    Returns abuse confidence score (0-100), country, ISP, usage type,
    total reports, whether it's a Tor exit node, and optionally recent
    individual reports.

    Args:
        ip_address: IPv4 or IPv6 address to check.
        max_age_days: Only consider reports from the last N days (1-365, default 90).
        verbose: If True, include individual report details in the response.
    """
    ip_address = _validate_ip(ip_address)
    max_age_days = _clamp(max_age_days, 1, 365)

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
    }
    if verbose:
        params["verbose"] = ""

    logger.info("check_ip: %s (max_age=%d)", ip_address, max_age_days)
    resp = requests.get(
        f"{BASE_URL}/check",
        headers=_abuseipdb_headers(),
        params=params,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    return _format_response(resp.json())


@mcp.tool()
def check_block(network: str, max_age_days: int = 30) -> str:
    """Check a CIDR network block for reported IP addresses.

    Returns a list of IPs within the subnet that have been reported,
    along with their report counts and confidence scores.

    Args:
        network: CIDR notation subnet (e.g. '192.168.1.0/24'). Max /24 on free tier.
        max_age_days: Only consider reports from the last N days (1-365, default 30).
    """
    network = _validate_cidr(network)
    max_age_days = _clamp(max_age_days, 1, 365)

    params = {
        "network": network,
        "maxAgeInDays": max_age_days,
    }

    logger.info("check_block: %s (max_age=%d)", network, max_age_days)
    resp = requests.get(
        f"{BASE_URL}/check-block",
        headers=_abuseipdb_headers(),
        params=params,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    return _format_response(resp.json())


@mcp.tool()
def get_reports(
    ip_address: str,
    max_age_days: int = 30,
    page: int = 1,
    per_page: int = 25,
) -> str:
    """Get paginated abuse reports for a specific IP address.

    Returns detailed individual reports including reporter info,
    attack categories, and comments.

    Args:
        ip_address: IPv4 or IPv6 address to look up.
        max_age_days: Only return reports from the last N days (1-365, default 30).
        page: Page number for pagination (default 1).
        per_page: Results per page, 1-100 (default 25).
    """
    ip_address = _validate_ip(ip_address)
    max_age_days = _clamp(max_age_days, 1, 365)
    per_page = _clamp(per_page, 1, 100)

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "page": max(1, page),
        "perPage": per_page,
    }

    logger.info("get_reports: %s (page=%d, per_page=%d)", ip_address, page, per_page)
    resp = requests.get(
        f"{BASE_URL}/reports",
        headers=_abuseipdb_headers(),
        params=params,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    return _format_response(resp.json())


@mcp.tool()
def get_blacklist(confidence_minimum: int = 90, limit: int = 50) -> str:
    """Get a list of the most reported IP addresses from AbuseIPDB.

    Returns IPs sorted by abuse confidence score descending. Useful for
    building block lists or checking against known bad actors.

    Args:
        confidence_minimum: Minimum abuse confidence score, 25-100 (default 90).
        limit: Maximum number of IPs to return (default 50, max 10000).
    """
    confidence_minimum = _clamp(confidence_minimum, 25, 100)
    limit = _clamp(limit, 1, 10000)

    params = {
        "confidenceMinimum": confidence_minimum,
        "limit": limit,
    }

    logger.info("get_blacklist: confidence>=%d, limit=%d", confidence_minimum, limit)
    resp = requests.get(
        f"{BASE_URL}/blacklist",
        headers=_abuseipdb_headers(),
        params=params,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    return _format_response(resp.json())


ABUSE_CATEGORIES = {
    "dns compromise": 1,
    "dns poisoning": 2,
    "fraud orders": 3,
    "ddos attack": 4,
    "ddos": 4,
    "ftp brute-force": 5,
    "ping of death": 6,
    "phishing": 7,
    "fraud voip": 8,
    "open proxy": 9,
    "web spam": 10,
    "email spam": 11,
    "blog spam": 12,
    "vpn ip": 13,
    "vpn": 13,
    "port scan": 14,
    "hacking": 15,
    "sql injection": 16,
    "spoofing": 17,
    "brute-force": 18,
    "brute force": 18,
    "bad web bot": 19,
    "exploited host": 20,
    "web app attack": 21,
    "ssh": 22,
    "iot targeted": 23,
    "iot": 23,
}


def _resolve_categories(categories: str) -> str:
    resolved = []
    for entry in categories.split(","):
        entry = entry.strip()
        if entry.isdigit():
            resolved.append(entry)
        else:
            cat_id = ABUSE_CATEGORIES.get(entry.lower())
            if cat_id is None:
                valid = ", ".join(
                    f"{name} ({cid})"
                    for name, cid in sorted(ABUSE_CATEGORIES.items(), key=lambda x: x[1])
                    if len(name) > 3
                )
                raise ValueError(
                    f"Unknown category: '{entry}'. Valid categories: {valid}"
                )
            resolved.append(str(cat_id))
    return ",".join(resolved)


@mcp.tool()
def report_ip(ip_address: str, categories: str, comment: str = "") -> str:
    """Report an abusive IP address to AbuseIPDB.

    WARNING: This submits a real abuse report. Use responsibly.

    Categories can be names, IDs, or a mix (comma-separated).
    Examples: 'Brute-Force,SSH', '18,22', 'DDoS,Port Scan'

    Available categories:
      DNS Compromise (1), DNS Poisoning (2), Fraud Orders (3), DDoS (4),
      FTP Brute-Force (5), Ping of Death (6), Phishing (7), Fraud VoIP (8),
      Open Proxy (9), Web Spam (10), Email Spam (11), Blog Spam (12),
      VPN (13), Port Scan (14), Hacking (15), SQL Injection (16),
      Spoofing (17), Brute-Force (18), Bad Web Bot (19),
      Exploited Host (20), Web App Attack (21), SSH (22), IoT Targeted (23)

    Args:
        ip_address: IPv4 or IPv6 address to report.
        categories: Comma-separated category names or IDs (e.g. 'Brute-Force,SSH' or '18,22').
        comment: Optional description of the observed attack (e.g. server log excerpt).
    """
    ip_address = _validate_ip(ip_address)
    resolved = _resolve_categories(categories)
    data = {
        "ip": ip_address,
        "categories": resolved,
    }
    if comment:
        data["comment"] = comment[:1024]

    logger.info("report_ip: %s categories=%s", ip_address, resolved)
    resp = requests.post(
        f"{BASE_URL}/report",
        headers=_abuseipdb_headers(),
        data=data,
        verify=VERIFY_SSL,
    )
    resp.raise_for_status()
    return _format_response(resp.json())


@mcp.tool()
def ping() -> str:
    """Health check for the AbuseIPDB MCP server."""
    from datetime import datetime

    return json.dumps({
        "status": "ok",
        "server": "abuseipdb-mcp",
        "version": "0.1.0",
        "timestamp": datetime.now().isoformat(),
    })


if __name__ == "__main__":
    logger.info("Starting AbuseIPDB MCP server (streamable-http) on %s:%d", HOST, PORT)

    app = mcp.streamable_http_app()

    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)

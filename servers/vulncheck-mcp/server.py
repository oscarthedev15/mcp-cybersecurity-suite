"""
VulnCheck MCP Server

Exploit intelligence and vulnerability prioritization via the VulnCheck
API.  Provides KEV lookup, exploit maturity assessment, CVE enrichment,
and recent-KEV monitoring.  Runs as a Streamable HTTP server with
per-request credential passthrough via X-VulnCheck-Token header.

IMPORTANT: Responses are deliberately trimmed to avoid flooding LLM
context windows.  Large list fields (reported_exploitation, xdb) are
capped and summarised with counts so the agent knows more data exists
without consuming tokens on thousands of reference URLs.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from mcp.server.fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("vulncheck-mcp")

HOST = os.environ.get("FASTMCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("FASTMCP_PORT", "8013"))
VERIFY_SSL = os.environ.get("VERIFY_SSL", "true").lower() != "false"
REQUEST_TIMEOUT = float(os.environ.get("VULNCHECK_TIMEOUT", "30"))

API_BASE = "https://api.vulncheck.com/v3"

mcp = FastMCP(
    "vulncheck-mcp",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

MAX_XDB = 10
MAX_EXPLOITATION_REFS = 5
MAX_BATCH = 25


def _get_token() -> str:
    try:
        headers = get_http_headers()
        if headers:
            token = headers.get("x-vulncheck-token", "")
            if token:
                return token
    except Exception:
        pass
    raise RuntimeError(
        "Missing X-VulnCheck-Token header. "
        "Pass your VulnCheck API token via the X-VulnCheck-Token HTTP header."
    )


def _api_headers() -> dict:
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {_get_token()}",
    }


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def _validate_cve(cve_id: str) -> str:
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(
            f"Invalid CVE ID: '{cve_id}'. Expected CVE-YYYY-NNNNN."
        )
    return cve_id


def _fmt(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), default=str)


def _query(path: str, params: dict) -> dict:
    url = f"{API_BASE}/{path}"
    with httpx.Client(timeout=REQUEST_TIMEOUT, verify=VERIFY_SSL) as client:
        resp = client.get(url, params=params, headers=_api_headers())

    if resp.status_code == 400:
        return {"_meta": {"total_documents": 0}, "data": []}
    if resp.status_code == 401:
        return {"error": "Invalid or expired VulnCheck token."}
    if resp.status_code == 402:
        return {"error": f"Endpoint '{path}' requires a paid VulnCheck subscription."}
    if resp.status_code == 429:
        return {"error": "VulnCheck rate limit exceeded. Try again shortly."}
    if resp.status_code == 404:
        return {"_meta": {"total_documents": 0}, "data": []}

    resp.raise_for_status()
    return resp.json()


def _trim_kev(item: dict) -> dict:
    xdb = item.get("vulncheck_xdb") or []
    exploitation = item.get("vulncheck_reported_exploitation") or []

    trimmed_xdb = [
        {"xdb_url": e.get("xdb_url"), "exploit_type": e.get("exploit_type")}
        for e in xdb[:MAX_XDB]
    ]

    trimmed_refs = [
        {"url": e.get("url"), "date_added": e.get("date_added")}
        for e in exploitation[:MAX_EXPLOITATION_REFS]
    ]

    return {
        "cve": item.get("cve"),
        "vendor": item.get("vendorProject"),
        "product": item.get("product"),
        "vulnerability_name": item.get("vulnerabilityName"),
        "description": item.get("shortDescription"),
        "known_ransomware": item.get("knownRansomwareCampaignUse"),
        "cisa_date_added": item.get("cisa_date_added"),
        "date_added": item.get("date_added"),
        "due_date": item.get("dueDate"),
        "required_action": item.get("required_action"),
        "cwes": item.get("cwes"),
        "canary_exploited": item.get("reported_exploited_by_vulncheck_canaries"),
        "exploit_count": len(xdb),
        "exploits": trimmed_xdb if trimmed_xdb else None,
        "exploitation_ref_count": len(exploitation),
        "exploitation_refs": trimmed_refs if trimmed_refs else None,
    }


def _trim_nvd(item: dict) -> dict:
    descriptions = item.get("descriptions") or []
    desc = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    metrics = item.get("metrics") or {}
    cvss = {}
    for key, label in [
        ("cvssMetricV40", "v4"),
        ("cvssMetricV31", "v3.1"),
        ("cvssMetricV2", "v2"),
    ]:
        entries = metrics.get(key, [])
        if not entries:
            continue
        primary = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        cd = primary.get("cvssData", {})
        cvss[label] = {
            "score": cd.get("baseScore"),
            "severity": cd.get("baseSeverity") or primary.get("baseSeverity"),
            "vector": cd.get("vectorString"),
        }

    weaknesses = item.get("weaknesses") or []
    cwes = []
    for w in weaknesses:
        for d in w.get("description", []):
            v = d.get("value", "")
            if v and v != "NVD-CWE-noinfo" and v not in cwes:
                cwes.append(v)

    return {
        "cve_id": item.get("id"),
        "description": desc[:500],
        "published": item.get("published"),
        "last_modified": item.get("lastModified"),
        "status": item.get("vulnStatus"),
        "cvss": cvss or None,
        "cwes": cwes or None,
        "cisa_exploit_add": item.get("cisaExploitAdd"),
        "cisa_action_due": item.get("cisaActionDue"),
    }


@mcp.tool()
def cve_exploit_intel(cve_id: str) -> str:
    """Look up exploit intelligence for a specific CVE from VulnCheck KEV.

    Returns exploit maturity (number of public exploits), whether the
    vulnerability is on the CISA KEV list, known ransomware usage, active
    honeypot exploitation (canary), required remediation action, and
    references (capped to conserve tokens).

    Args:
        cve_id: CVE identifier, e.g. 'CVE-2021-44228'.
    """
    cve_id = _validate_cve(cve_id)
    logger.info("cve_exploit_intel: %s", cve_id)

    data = _query("index/vulncheck-kev", {"cve": cve_id})
    if "error" in data:
        return _fmt({"cve_id": cve_id, **data})

    items = data.get("data") or []
    if not items:
        return _fmt({"cve_id": cve_id, "in_kev": False, "message": "CVE not found in VulnCheck KEV catalog."})

    result = _trim_kev(items[0])
    result["in_kev"] = True
    return _fmt(result)


@mcp.tool()
def cve_enrich(cve_id: str) -> str:
    """Enrich a CVE with both NVD details and VulnCheck exploit intel.

    Combines NIST NVD2 data (description, CVSS, CWEs) with VulnCheck
    KEV data (exploit status, ransomware, canary) in a single call.

    Args:
        cve_id: CVE identifier, e.g. 'CVE-2024-3400'.
    """
    cve_id = _validate_cve(cve_id)
    logger.info("cve_enrich: %s", cve_id)

    result: dict[str, Any] = {"cve_id": cve_id}

    nvd = _query("index/nist-nvd2", {"cve": cve_id})
    if "error" in nvd:
        result["nvd_error"] = nvd["error"]
    else:
        nvd_items = nvd.get("data") or []
        if nvd_items:
            result["nvd"] = _trim_nvd(nvd_items[0])

    kev = _query("index/vulncheck-kev", {"cve": cve_id})
    if "error" in kev:
        result["kev_error"] = kev["error"]
    else:
        kev_items = kev.get("data") or []
        if kev_items:
            result["kev"] = _trim_kev(kev_items[0])
            result["in_kev"] = True
        else:
            result["in_kev"] = False

    return _fmt(result)


@mcp.tool()
def vulnerability_prioritization(cve_ids: str) -> str:
    """Batch-prioritize CVEs by exploit risk.

    Accepts up to 25 comma-separated CVE IDs and returns a sorted list
    with the highest-risk (in KEV, ransomware-linked, most exploits)
    first.  Only summary fields are returned to conserve tokens.

    Sorting: in_kev desc, ransomware=Known desc, exploit_count desc.

    Args:
        cve_ids: Comma-separated CVE IDs, e.g. 'CVE-2021-44228,CVE-2024-3400'.
    """
    raw = [c.strip() for c in cve_ids.split(",") if c.strip()]
    if not raw:
        return _fmt({"error": "No CVE IDs provided."})
    if len(raw) > MAX_BATCH:
        return _fmt({"error": f"Maximum {MAX_BATCH} CVEs per call."})

    ids = []
    for r in raw:
        try:
            ids.append(_validate_cve(r))
        except ValueError as e:
            return _fmt({"error": str(e)})

    logger.info("vulnerability_prioritization: %d CVEs", len(ids))

    results = []
    for cve_id in ids:
        kev = _query("index/vulncheck-kev", {"cve": cve_id})
        if "error" in kev:
            results.append({"cve_id": cve_id, "in_kev": False, "error": kev["error"]})
            continue

        items = kev.get("data") or []
        if items:
            item = items[0]
            results.append({
                "cve_id": cve_id,
                "in_kev": True,
                "vendor": item.get("vendorProject"),
                "product": item.get("product"),
                "known_ransomware": item.get("knownRansomwareCampaignUse"),
                "canary_exploited": item.get("reported_exploited_by_vulncheck_canaries"),
                "exploit_count": len(item.get("vulncheck_xdb") or []),
                "exploitation_ref_count": len(item.get("vulncheck_reported_exploitation") or []),
                "due_date": item.get("dueDate"),
            })
        else:
            results.append({"cve_id": cve_id, "in_kev": False})

    def _sort_key(r):
        in_kev = 1 if r.get("in_kev") else 0
        ransomware = 1 if r.get("known_ransomware") == "Known" else 0
        canary = 1 if r.get("canary_exploited") else 0
        exploits = r.get("exploit_count", 0)
        return (in_kev, ransomware, canary, exploits)

    results.sort(key=_sort_key, reverse=True)

    return _fmt({
        "total_queried": len(ids),
        "in_kev_count": sum(1 for r in results if r.get("in_kev")),
        "results": results,
    })


@mcp.tool()
def kev_recent(days: int = 7, limit: int = 20) -> str:
    """Get recently added entries from the VulnCheck KEV catalog.

    Args:
        days: Look-back window in days (1-120, default 7).
        limit: Max results to return (1-100, default 20).
    """
    days = _clamp(days, 1, 120)
    limit = _clamp(limit, 1, 100)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%d"),
        "pubEndDate": end.strftime("%Y-%m-%d"),
        "limit": str(limit),
    }

    logger.info("kev_recent: days=%d limit=%d", days, limit)
    data = _query("index/vulncheck-kev", params)
    if "error" in data:
        return _fmt(data)

    total = data.get("_meta", {}).get("total_documents", 0)
    items = data.get("data") or []

    results = []
    for item in items:
        results.append({
            "cve": item.get("cve"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "vulnerability_name": item.get("vulnerabilityName"),
            "known_ransomware": item.get("knownRansomwareCampaignUse"),
            "canary_exploited": item.get("reported_exploited_by_vulncheck_canaries"),
            "exploit_count": len(item.get("vulncheck_xdb") or []),
            "date_added": item.get("date_added"),
            "due_date": item.get("dueDate"),
        })

    return _fmt({
        "period_start": start.strftime("%Y-%m-%d"),
        "period_end": end.strftime("%Y-%m-%d"),
        "total_in_period": total,
        "returned": len(results),
        "results": results,
    })


@mcp.tool()
def kev_search(
    cve: str = "",
    vendor: str = "",
    date_start: str = "",
    date_end: str = "",
    limit: int = 20,
) -> str:
    """Search the VulnCheck KEV catalog with flexible filters.

    At least one filter (cve, vendor, or date range) must be provided.

    Args:
        cve: Optional CVE ID filter (e.g. 'CVE-2024-3400').
        vendor: Optional vendor/project name -- applied client-side.
        date_start: Optional start date YYYY-MM-DD for date_added range.
        date_end: Optional end date YYYY-MM-DD for date_added range.
        limit: Max results (1-100, default 20).
    """
    limit = _clamp(limit, 1, 100)
    params: dict[str, str] = {"limit": str(limit)}

    if cve:
        params["cve"] = _validate_cve(cve)
    if date_start:
        params["pubStartDate"] = date_start.strip()
    if date_end:
        params["pubEndDate"] = date_end.strip()

    if not cve and not date_start and not date_end and not vendor:
        return _fmt({"error": "Provide at least one filter: cve, vendor, date_start, or date_end."})

    logger.info("kev_search: params=%s vendor_filter=%s", params, vendor)
    data = _query("index/vulncheck-kev", params)
    if "error" in data:
        return _fmt(data)

    items = data.get("data") or []

    if vendor:
        vendor_lower = vendor.strip().lower()
        items = [
            i for i in items
            if vendor_lower in (i.get("vendorProject") or "").lower()
            or vendor_lower in (i.get("product") or "").lower()
        ]

    results = []
    for item in items:
        results.append({
            "cve": item.get("cve"),
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "description": (item.get("shortDescription") or "")[:300],
            "known_ransomware": item.get("knownRansomwareCampaignUse"),
            "exploit_count": len(item.get("vulncheck_xdb") or []),
            "date_added": item.get("date_added"),
            "due_date": item.get("dueDate"),
        })

    return _fmt({
        "total_api": data.get("_meta", {}).get("total_documents", 0),
        "returned": len(results),
        "results": results,
    })


@mcp.tool()
def nvd_cve_lookup(cve_id: str) -> str:
    """Look up a CVE in VulnCheck's NVD2 mirror.

    Faster than querying NIST directly and not subject to NVD rate limits.

    Args:
        cve_id: CVE identifier, e.g. 'CVE-2024-3400'.
    """
    cve_id = _validate_cve(cve_id)
    logger.info("nvd_cve_lookup: %s", cve_id)

    data = _query("index/nist-nvd2", {"cve": cve_id})
    if "error" in data:
        return _fmt({"cve_id": cve_id, **data})

    items = data.get("data") or []
    if not items:
        return _fmt({"cve_id": cve_id, "error": "CVE not found in NVD."})

    return _fmt(_trim_nvd(items[0]))


@mcp.tool()
def nvd_recent(days: int = 7, limit: int = 20) -> str:
    """Get recently published CVEs from VulnCheck's NVD2 mirror.

    Args:
        days: Look-back window in days (1-120, default 7).
        limit: Max results (1-100, default 20).
    """
    days = _clamp(days, 1, 120)
    limit = _clamp(limit, 1, 100)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%d"),
        "pubEndDate": end.strftime("%Y-%m-%d"),
        "limit": str(limit),
    }

    logger.info("nvd_recent: days=%d limit=%d", days, limit)
    data = _query("index/nist-nvd2", params)
    if "error" in data:
        return _fmt(data)

    total = data.get("_meta", {}).get("total_documents", 0)
    items = data.get("data") or []
    results = [_trim_nvd(i) for i in items]

    return _fmt({
        "period_start": start.strftime("%Y-%m-%d"),
        "period_end": end.strftime("%Y-%m-%d"),
        "total_in_period": total,
        "returned": len(results),
        "results": results,
    })


@mcp.tool()
def ping() -> str:
    """Health check for the VulnCheck MCP server."""
    return json.dumps({
        "status": "ok",
        "server": "vulncheck-mcp",
        "version": "0.1.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


if __name__ == "__main__":
    logger.info("Starting VulnCheck MCP server on %s:%d", HOST, PORT)
    app = mcp.streamable_http_app()
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)

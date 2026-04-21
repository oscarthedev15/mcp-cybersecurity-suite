"""
WHOIS MCP Server

Performs WHOIS and DNS lookups entirely within the server using standard
protocols (WHOIS port 43, DNS).  No external API key required.  Runs as
a Streamable HTTP server behind the shared nginx ingress.
"""

import json
import logging
import os
import re
from datetime import datetime
from typing import Any

import dns.resolver
import whois
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("whois-mcp")

HOST = os.environ.get("FASTMCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("FASTMCP_PORT", "8009"))

mcp = FastMCP(
    "whois-mcp",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)

_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.[A-Za-z0-9-]{1,63})*"
    r"\.[A-Za-z]{2,63}$"
)

VALID_RECORD_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"}

MAX_BULK_DOMAINS = 50


def _validate_domain(domain: str) -> str:
    domain = domain.strip().lower().rstrip(".")
    if not domain:
        raise ValueError("Domain name cannot be empty")
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain name: '{domain}'")
    return domain


def _validate_record_type(record_type: str) -> str:
    record_type = record_type.strip().upper()
    if record_type not in VALID_RECORD_TYPES:
        raise ValueError(
            f"Unsupported record type: '{record_type}'. "
            f"Supported: {', '.join(sorted(VALID_RECORD_TYPES))}"
        )
    return record_type


def _serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, list):
        return [_serialize(item) for item in obj]
    if isinstance(obj, set):
        return sorted(_serialize(item) for item in obj)
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return str(obj)


def _format_response(data: Any) -> str:
    return json.dumps(data, separators=(",", ":"), default=str)


_RELEVANT_FIELDS = [
    "domain_name",
    "registrar",
    "creation_date",
    "expiration_date",
    "updated_date",
    "name_servers",
    "status",
    "org",
    "country",
    "state",
    "city",
    "dnssec",
    "emails",
    "registrant",
    "registrant_country",
]


def _whois_for_domain(domain: str) -> dict:
    w = whois.whois(domain)

    result: dict[str, Any] = {"domain": domain}
    for field in _RELEVANT_FIELDS:
        value = getattr(w, field, None)
        if value is not None:
            result[field] = _serialize(value)

    for key in ("domain_name", "creation_date", "expiration_date", "updated_date"):
        val = result.get(key)
        if isinstance(val, list) and len(val) == 1:
            result[key] = val[0]

    return result


@mcp.tool()
def whois_lookup(domain: str) -> str:
    """Look up WHOIS registration data for a single domain.

    Returns registrar, registration/expiration dates, name servers,
    status codes, registrant organization, and country.

    Args:
        domain: Fully qualified domain name (e.g. 'example.com').
    """
    domain = _validate_domain(domain)
    logger.info("whois_lookup: %s", domain)

    try:
        result = _whois_for_domain(domain)
    except Exception as exc:
        logger.error("whois_lookup failed for %s: %s", domain, exc)
        result = {"domain": domain, "error": str(exc)}

    return _format_response(result)


@mcp.tool()
def bulk_whois_lookup(domains: str, max_domains: int = 50) -> str:
    """Look up WHOIS data for multiple domains at once.

    Accepts a comma-separated or newline-separated list of domains.
    Each domain is looked up independently; one failure does not
    affect the others.

    Args:
        domains: Comma or newline-separated list of domain names.
        max_domains: Maximum number of domains to process (1-50, default 50).
    """
    max_domains = max(1, min(MAX_BULK_DOMAINS, max_domains))
    raw = re.split(r"[,\n]+", domains)
    raw = [d.strip() for d in raw if d.strip()]

    if not raw:
        return _format_response({"error": "No valid domains provided"})

    if len(raw) > max_domains:
        raw = raw[:max_domains]
        logger.warning("bulk_whois_lookup: truncated to %d domains", max_domains)

    logger.info("bulk_whois_lookup: %d domains", len(raw))
    results = []
    for entry in raw:
        try:
            domain = _validate_domain(entry)
            result = _whois_for_domain(domain)
        except Exception as exc:
            result = {"domain": entry, "error": str(exc)}
        results.append(result)

    return _format_response({"count": len(results), "results": results})


@mcp.tool()
def dns_lookup(domain: str, record_type: str = "A") -> str:
    """Look up DNS records for a domain.

    Supports A, AAAA, MX, NS, TXT, CNAME, SOA, and PTR record types.

    Args:
        domain: Fully qualified domain name (e.g. 'example.com').
        record_type: DNS record type to query (default 'A').
    """
    domain = _validate_domain(domain)
    record_type = _validate_record_type(record_type)

    logger.info("dns_lookup: %s %s", domain, record_type)

    try:
        answers = dns.resolver.resolve(domain, record_type)
        records = []
        for rdata in answers:
            if record_type == "MX":
                records.append({
                    "priority": rdata.preference,
                    "exchange": str(rdata.exchange),
                })
            elif record_type == "SOA":
                records.append({
                    "mname": str(rdata.mname),
                    "rname": str(rdata.rname),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum,
                })
            else:
                records.append(str(rdata))

        return _format_response({
            "domain": domain,
            "record_type": record_type,
            "records": records,
            "ttl": answers.rrset.ttl if answers.rrset else None,
        })

    except dns.resolver.NXDOMAIN:
        return _format_response({
            "domain": domain,
            "record_type": record_type,
            "error": "Domain does not exist (NXDOMAIN)",
        })
    except dns.resolver.NoAnswer:
        return _format_response({
            "domain": domain,
            "record_type": record_type,
            "error": f"No {record_type} records found",
        })
    except dns.resolver.NoNameservers:
        return _format_response({
            "domain": domain,
            "record_type": record_type,
            "error": "No nameservers available for this domain",
        })
    except Exception as exc:
        logger.error("dns_lookup failed for %s %s: %s", domain, record_type, exc)
        return _format_response({
            "domain": domain,
            "record_type": record_type,
            "error": str(exc),
        })


@mcp.tool()
def ping() -> str:
    """Health check for the WHOIS MCP server."""
    return json.dumps({
        "status": "ok",
        "server": "whois-mcp",
        "version": "0.1.0",
        "timestamp": datetime.now().isoformat(),
    })


if __name__ == "__main__":
    logger.info("Starting WHOIS MCP server on %s:%d", HOST, PORT)
    app = mcp.streamable_http_app()
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)

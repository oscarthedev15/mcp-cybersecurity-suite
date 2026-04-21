"""
Shodan MCP Server

Exposes Shodan APIs as MCP tools across three tiers:

Free (no API key):
  - InternetDB: fast IP lookups for open ports, vulnerabilities, CPEs,
    hostnames, and tags.
  - EntityDB: company/entity metadata, financials, and executive
    compensation sourced from SEC filings.

Paid (requires API key via X-Shodan-Key header):
  - Host lookup, search, search count, search facets, search filters,
    and search token analysis against the full Shodan database.

Runs as a Streamable HTTP server with per-request credential passthrough.
"""

import ipaddress
import json
import logging
import os
import ssl
from datetime import datetime
from typing import Any

import certifi
import httpx
from fastmcp.server.dependencies import get_http_headers
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("shodan-mcp")

HOST = os.environ.get("FASTMCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("FASTMCP_PORT", "8011"))
_ssl_enabled = os.environ.get("VERIFY_SSL", "true").lower() != "false"
if _ssl_enabled:
    SSL_CTX = ssl.create_default_context(cafile=certifi.where())
else:
    SSL_CTX = False

mcp = FastMCP(
    "shodan-mcp",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)

SHODAN_API_URL = "https://api.shodan.io"
INTERNETDB_URL = "https://internetdb.shodan.io"
ENTITYDB_URL = "https://entitydb.shodan.io/api"
REQUEST_TIMEOUT = 30.0


def _get_api_key() -> str:
    try:
        headers = get_http_headers()
        if headers:
            key = headers.get("x-shodan-key", "")
            if key:
                return key
    except Exception:
        pass
    raise RuntimeError(
        "Missing X-Shodan-Key header. "
        "Pass your Shodan API key via the X-Shodan-Key HTTP header."
    )


def _get(url: str) -> dict | list:
    with httpx.Client(timeout=REQUEST_TIMEOUT, verify=SSL_CTX) as client:
        resp = client.get(url)

    if resp.status_code == 404:
        return {"error": "Not found", "detail": resp.text.strip() or "No results for this query"}
    if resp.status_code == 429:
        return {"error": "Rate limit exceeded. Try again shortly."}

    resp.raise_for_status()
    return resp.json()


def _shodan_get(path: str, params: dict[str, Any] | None = None) -> dict | list:
    api_key = _get_api_key()
    if params is None:
        params = {}
    params["key"] = api_key

    url = f"{SHODAN_API_URL}{path}"
    with httpx.Client(timeout=REQUEST_TIMEOUT, verify=SSL_CTX) as client:
        resp = client.get(url, params=params)

    if resp.status_code == 401:
        return {"error": "Invalid Shodan API key."}
    if resp.status_code == 402:
        return {"error": "Shodan API request requires a paid plan or query credits."}
    if resp.status_code == 429:
        return {"error": "Shodan API rate limit exceeded. Try again shortly."}

    resp.raise_for_status()
    return resp.json()


def _format_response(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _validate_ip(ip_address: str) -> str:
    try:
        return str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        raise ValueError(f"Invalid IP address: '{ip_address}'")


def _validate_entity_id(entity_id: int) -> int:
    if entity_id < 1:
        raise ValueError(f"Entity ID must be a positive integer, got {entity_id}")
    return entity_id


def _validate_symbol(symbol: str) -> str:
    symbol = symbol.strip().upper()
    if not symbol:
        raise ValueError("Stock symbol cannot be empty")
    if not symbol.isalpha() or len(symbol) > 10:
        raise ValueError(f"Invalid stock symbol: '{symbol}'")
    return symbol


@mcp.tool()
def internetdb_lookup(ip_address: str) -> str:
    """Look up an IP address in Shodan's InternetDB for a quick overview
    of open ports, known vulnerabilities, CPEs, hostnames, and tags.

    This is a free API -- no Shodan API key is required.

    Args:
        ip_address: The IP address to look up (e.g. '1.1.1.1').
    """
    ip_address = _validate_ip(ip_address)
    logger.info("internetdb_lookup: %s", ip_address)

    try:
        data = _get(f"{INTERNETDB_URL}/{ip_address}")
        return _format_response(data)
    except Exception as exc:
        logger.error("internetdb_lookup failed for %s: %s", ip_address, exc)
        return _format_response({"ip": ip_address, "error": str(exc)})


@mcp.tool()
def entity_lookup(entity_id: int) -> str:
    """Look up a company/entity by its Shodan EntityDB numeric ID.

    Returns entity metadata (name, CIK, SIC, tickers, addresses),
    financial data (revenue, net income, EBITDA, EPS from SEC filings),
    and executive compensation tables.

    This is a free API -- no Shodan API key is required.

    Args:
        entity_id: The EntityDB numeric ID (e.g. 3 for Alphabet Inc.).
    """
    entity_id = _validate_entity_id(entity_id)
    logger.info("entity_lookup: id=%d", entity_id)

    try:
        data = _get(f"{ENTITYDB_URL}/entities/{entity_id}")
        return _format_response(data)
    except Exception as exc:
        logger.error("entity_lookup failed for id=%d: %s", entity_id, exc)
        return _format_response({"entity_id": entity_id, "error": str(exc)})


@mcp.tool()
def entity_lookup_by_symbol(symbol: str) -> str:
    """Look up a company/entity by its stock ticker symbol.

    Returns entity metadata (name, CIK, SIC, tickers, addresses),
    financial data (revenue, net income, EBITDA, EPS from SEC filings),
    and executive compensation tables.

    This is a free API -- no Shodan API key is required.

    Args:
        symbol: Stock ticker symbol (e.g. 'GOOGL', 'AAPL', 'MSFT').
    """
    symbol = _validate_symbol(symbol)
    logger.info("entity_lookup_by_symbol: %s", symbol)

    try:
        data = _get(f"{ENTITYDB_URL}/entities/symbol/{symbol}")
        return _format_response(data)
    except Exception as exc:
        logger.error("entity_lookup_by_symbol failed for %s: %s", symbol, exc)
        return _format_response({"symbol": symbol, "error": str(exc)})


@mcp.tool()
def host_lookup(
    ip_address: str,
    minify: bool = False,
    history: bool = False,
) -> str:
    """Return all services and open ports found on a host IP address.

    Returns banners, geolocation, ASN, organization, hostnames,
    operating system, and known vulnerabilities.  Requires a Shodan
    API key via X-Shodan-Key header.

    Args:
        ip_address: The IP address to look up (e.g. '8.8.8.8').
        minify: True to return only ports and general host info, no banners.
        history: True to include all historical banners.
    """
    ip_address = _validate_ip(ip_address)
    logger.info("host_lookup: %s (minify=%s, history=%s)", ip_address, minify, history)

    try:
        params: dict[str, Any] = {}
        if minify:
            params["minify"] = "true"
        if history:
            params["history"] = "true"

        data = _shodan_get(f"/shodan/host/{ip_address}", params)
        if isinstance(data, dict) and "error" in data:
            return _format_response({"ip": ip_address, **data})

        if isinstance(data, dict) and not minify:
            banners = data.get("data", [])
            if len(banners) > 20:
                data["data"] = banners[:20]
                data["_truncated"] = f"Showing 20 of {len(banners)} banners"

        return _format_response(data)
    except Exception as exc:
        logger.error("host_lookup failed for %s: %s", ip_address, exc)
        return _format_response({"ip": ip_address, "error": str(exc)})


@mcp.tool()
def search(
    query: str,
    facets: str = "",
    page: int = 1,
    minify: bool = True,
    fields: str = "",
) -> str:
    """Search the Shodan database of internet-connected devices.

    Uses the same query syntax as the Shodan website.  Supports filters
    like 'product:nginx country:DE port:443'.  Each page returns up to
    100 results.  May consume query credits depending on usage.
    Requires a Shodan API key via X-Shodan-Key header.

    Args:
        query: Shodan search query string (e.g. 'apache country:US').
        facets: Optional comma-separated facet properties (e.g. 'country,org:10').
        page: Page number for pagination (default 1, 100 results per page).
        minify: Whether to truncate large fields (default True).
        fields: Optional comma-separated list of fields to return (e.g. 'tags,http.title').
    """
    query = query.strip()
    if not query:
        return _format_response({"error": "Search query cannot be empty"})

    page = max(1, min(100, page))
    logger.info("search: query=%r facets=%r page=%d", query, facets, page)

    try:
        params: dict[str, Any] = {
            "query": query,
            "page": page,
            "minify": str(minify).lower(),
        }
        if facets.strip():
            params["facets"] = facets.strip()
        if fields.strip():
            params["fields"] = fields.strip()

        data = _shodan_get("/shodan/host/search", params)
        if isinstance(data, dict) and "error" in data:
            return _format_response(data)

        if isinstance(data, dict):
            matches = data.get("matches", [])
            if len(matches) > 25:
                data["matches"] = matches[:25]
                data["_truncated"] = f"Showing 25 of {len(matches)} matches on this page"

        return _format_response(data)
    except Exception as exc:
        logger.error("search failed for query=%r: %s", query, exc)
        return _format_response({"query": query, "error": str(exc)})


@mcp.tool()
def search_count(
    query: str,
    facets: str = "",
) -> str:
    """Count the number of Shodan results for a search query.

    Returns the total result count and optional facet breakdowns
    without consuming query credits or returning host results.
    Requires a Shodan API key via X-Shodan-Key header.

    Args:
        query: Shodan search query string (e.g. 'port:22 org:Google').
        facets: Optional comma-separated facet properties (e.g. 'country:10,org:5').
    """
    query = query.strip()
    if not query:
        return _format_response({"error": "Search query cannot be empty"})

    logger.info("search_count: query=%r facets=%r", query, facets)

    try:
        params: dict[str, Any] = {"query": query}
        if facets.strip():
            params["facets"] = facets.strip()

        data = _shodan_get("/shodan/host/count", params)
        return _format_response(data)
    except Exception as exc:
        logger.error("search_count failed for query=%r: %s", query, exc)
        return _format_response({"query": query, "error": str(exc)})


@mcp.tool()
def search_facets() -> str:
    """List all available search facets that can be used with search and
    search_count to get breakdowns of the top values for a property.

    Requires a Shodan API key via X-Shodan-Key header.
    """
    logger.info("search_facets")

    try:
        data = _shodan_get("/shodan/host/search/facets")
        return _format_response(data)
    except Exception as exc:
        logger.error("search_facets failed: %s", exc)
        return _format_response({"error": str(exc)})


@mcp.tool()
def search_filters() -> str:
    """List all search filters that can be used in Shodan search queries.

    Returns the available filter:value pairs (e.g. 'port', 'country',
    'product', 'org', etc.) for constructing search queries.
    Requires a Shodan API key via X-Shodan-Key header.
    """
    logger.info("search_filters")

    try:
        data = _shodan_get("/shodan/host/search/filters")
        return _format_response(data)
    except Exception as exc:
        logger.error("search_filters failed: %s", exc)
        return _format_response({"error": str(exc)})


@mcp.tool()
def search_tokens(query: str) -> str:
    """Break a Shodan search query into tokens to see which filters and
    parameters are being used.

    Useful for validating and debugging complex search queries.
    Requires a Shodan API key via X-Shodan-Key header.

    Args:
        query: Shodan search query string (e.g. 'Raspbian port:22').
    """
    query = query.strip()
    if not query:
        return _format_response({"error": "Search query cannot be empty"})

    logger.info("search_tokens: query=%r", query)

    try:
        data = _shodan_get("/shodan/host/search/tokens", {"query": query})
        return _format_response(data)
    except Exception as exc:
        logger.error("search_tokens failed for query=%r: %s", query, exc)
        return _format_response({"query": query, "error": str(exc)})


@mcp.tool()
def ping() -> str:
    """Health check for the Shodan MCP server."""
    return json.dumps({
        "status": "ok",
        "server": "shodan-mcp",
        "version": "0.2.0",
        "apis": ["InternetDB", "EntityDB", "Shodan Search API"],
        "timestamp": datetime.now().isoformat(),
    })


if __name__ == "__main__":
    logger.info("Starting Shodan MCP server on %s:%d", HOST, PORT)
    app = mcp.streamable_http_app()
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)

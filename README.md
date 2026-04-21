# MCP Cybersecurity Suite

A suite of open-source Model Context Protocol (MCP) servers purpose-built for cybersecurity operations. Each server exposes domain-specific threat intelligence, vulnerability, and reconnaissance tools to AI agents (Claude, Cursor, or any MCP-compatible client) via the MCP streamable-http transport.

## Servers

| Server | Port | Purpose | API Key Required |
|--------|------|---------|-----------------|
| [abuseipdb-mcp](#abuseipdb-mcp) | 8008 | IP threat intelligence | Yes (`X-AbuseIPDB-Key`) |
| [whois-mcp](#whois-mcp) | 8009 | WHOIS + DNS lookups | No |
| [nvd-cve-mcp](#nvd-cve-mcp) | 8010 | NIST NVD CVE lookup & search | Optional (`X-NVD-Api-Key`) |
| [shodan-mcp](#shodan-mcp) | 8011 | Internet device reconnaissance | Partial (`X-Shodan-Key` for paid) |
| [mitre-attack-mcp](#mitre-attack-mcp) | 8012 | MITRE ATT&CK knowledge base | No (offline) |
| [vulncheck-mcp](#vulncheck-mcp) | 8013 | KEV exploit intelligence | Yes (`X-VulnCheck-Token`) |

---

## Architecture

```
AI Agent (Claude / Cursor / Custom)
  │
  │  HTTPS + Authorization: Basic <token>
  │  + per-service credential headers (X-AbuseIPDB-Key, X-Shodan-Key, etc.)
  ▼
nginx (TLS termination, path-based routing)
  │
  ├─► abuseipdb-mcp  :8008
  ├─► whois-mcp      :8009
  ├─► nvd-cve-mcp    :8010
  ├─► shodan-mcp     :8011
  ├─► mitre-attack-mcp :8012
  └─► vulncheck-mcp  :8013
        │
        ▼
  External APIs (AbuseIPDB, NIST NVD, Shodan, VulnCheck)
  or local STIX data (MITRE ATT&CK)
```

**Key design principles:**
- **Stateless** — no API keys stored server-side; credentials arrive per-request via HTTP headers
- **Multi-tenant safe** — multiple clients with different API keys share the same server instances
- **Offline-capable** — MITRE ATT&CK operates entirely offline against a bundled STIX JSON file
- **Non-root, hardened** — read-only rootfs, all capabilities dropped, non-root user in containers

---

## Quick Start (Local Development)

### Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) package manager
- Docker + Docker Compose (for containerized deployment)

### Run a single server

```bash
cd servers/abuseipdb-mcp
uv sync
uv run python server.py
```

The server starts on `http://localhost:8008/mcp`.

### Run all servers with Docker Compose

```bash
cd deployments/http
docker-compose up -d --build
```

Verify all servers are up:

```bash
for PORT in 8008 8009 8010 8011 8012 8013; do
  echo -n "Port $PORT: "
  curl -s -X POST http://localhost:$PORT/mcp/ \
    -H "Content-Type: application/json" \
    -H "Accept: application/json, text/event-stream" \
    -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}' \
    | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if 'result' in d else 'FAIL')"
done
```

---

## Client Configuration

### Connect to all servers (Claude Desktop / Cursor)

Copy `client-config-local.json` into your MCP client settings for local development:

```json
{
  "mcpServers": {
    "abuseipdb": {
      "type": "streamable-http",
      "url": "http://localhost:8008/mcp",
      "headers": { "X-AbuseIPDB-Key": "your-key" }
    },
    "whois": {
      "type": "streamable-http",
      "url": "http://localhost:8009/mcp"
    },
    "nvd-cve": {
      "type": "streamable-http",
      "url": "http://localhost:8010/mcp"
    },
    "shodan": {
      "type": "streamable-http",
      "url": "http://localhost:8011/mcp",
      "headers": { "X-Shodan-Key": "your-key" }
    },
    "mitre-attack": {
      "type": "streamable-http",
      "url": "http://localhost:8012/mcp"
    },
    "vulncheck": {
      "type": "streamable-http",
      "url": "http://localhost:8013/mcp",
      "headers": { "X-VulnCheck-Token": "your-token" }
    }
  }
}
```

For production with nginx TLS + basic auth, see `client-config.json`.

---

## Server Reference & Examples

### abuseipdb-mcp

IP threat intelligence via the [AbuseIPDB](https://www.abuseipdb.com/) API v2.

**Tools:** `check_ip`, `check_block`, `get_reports`, `get_blacklist`, `report_ip`, `ping`

**Example prompts to your AI agent:**

> "Check if 192.0.2.1 has been reported for abuse in the last 30 days"

> "Get the top 20 most abusive IPs with a confidence score above 95"

> "Show me all abuse reports for 10.0.0.1 with details"

**Direct tool call:**
```json
{
  "tool": "check_ip",
  "arguments": {
    "ip_address": "192.0.2.1",
    "max_age_days": 30,
    "verbose": true
  }
}
```

**Example response:**
```json
{
  "data": {
    "ipAddress": "192.0.2.1",
    "abuseConfidenceScore": 87,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "isp": "Example ISP",
    "totalReports": 142,
    "lastReportedAt": "2024-11-01T14:23:00+00:00",
    "isTor": false
  }
}
```

---

### whois-mcp

WHOIS registration lookups and DNS queries with no external API key required.

**Tools:** `whois_lookup`, `bulk_whois_lookup`, `dns_lookup`, `ping`

**Example prompts:**

> "Look up WHOIS data for example.com and tell me when it expires"

> "Check the MX records for gmail.com"

> "Do a bulk WHOIS lookup on these domains: apple.com, google.com, microsoft.com"

**Direct tool call:**
```json
{
  "tool": "dns_lookup",
  "arguments": {
    "domain": "example.com",
    "record_type": "MX"
  }
}
```

**Example response:**
```json
{
  "domain": "example.com",
  "record_type": "MX",
  "records": [
    { "priority": 10, "exchange": "mail.example.com." }
  ],
  "ttl": 3600
}
```

**Supported DNS record types:** `A`, `AAAA`, `MX`, `NS`, `TXT`, `CNAME`, `SOA`, `PTR`

---

### nvd-cve-mcp

Query the [NIST National Vulnerability Database](https://nvd.nist.gov/) (NVD) API 2.0.

**Tools:** `cve_lookup`, `cve_search`, `cve_recent`, `cve_by_cpe`, `ping`

> **Tip:** Providing an `X-NVD-Api-Key` header raises the rate limit from 5 req/30s to 50 req/30s.

**Example prompts:**

> "Look up CVE-2021-44228 (Log4Shell) and give me the CVSS score and affected products"

> "Find critical CVEs related to remote code execution published in the last 7 days"

> "What CVEs affect Apache Log4j? Use CPE cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"

**Direct tool call:**
```json
{
  "tool": "cve_lookup",
  "arguments": {
    "cve_id": "CVE-2021-44228"
  }
}
```

**Example response:**
```json
{
  "cve_id": "CVE-2021-44228",
  "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features...",
  "published": "2021-12-10T10:15:00.000",
  "cvss": {
    "cvss_v3_1": {
      "score": 10.0,
      "severity": "CRITICAL",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    }
  },
  "cwes": ["CWE-917", "CWE-400"],
  "affected_products": ["cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"]
}
```

---

### shodan-mcp

Internet device reconnaissance across three tiers — InternetDB and EntityDB are free, the Shodan Search API requires a paid key.

**Tools:** `internetdb_lookup`, `entity_lookup`, `entity_lookup_by_symbol`, `host_lookup`, `search`, `search_count`, `search_facets`, `search_filters`, `search_tokens`, `ping`

**Example prompts:**

> "Look up 8.8.8.8 in InternetDB — what ports are open and are there any known CVEs?"

> "Search Shodan for nginx servers in Germany on port 443" *(requires paid key)*

> "How many internet-facing Redis instances are there in the US?" *(requires paid key)*

> "Look up the EntityDB record for Apple Inc. by ticker symbol AAPL"

**Direct tool call (free tier):**
```json
{
  "tool": "internetdb_lookup",
  "arguments": {
    "ip_address": "8.8.8.8"
  }
}
```

**Example response:**
```json
{
  "ip": "8.8.8.8",
  "ports": [53, 443],
  "hostnames": ["dns.google"],
  "cpes": ["cpe:/a:google:dns"],
  "vulns": [],
  "tags": ["cdn"]
}
```

**Direct tool call (paid tier):**
```json
{
  "tool": "search",
  "arguments": {
    "query": "product:nginx country:DE port:443",
    "facets": "org:5",
    "page": 1
  }
}
```

---

### mitre-attack-mcp

Offline access to the [MITRE ATT&CK](https://attack.mitre.org/) knowledge base using a STIX 2.0 bundle loaded at startup. No internet connection required after the Docker image is built.

**Tools:** `lookup_technique`, `search_techniques`, `get_tactic_techniques`, `get_technique_mitigations`, `get_technique_detections`, `get_subtechniques`, `lookup_group`, `get_technique_groups`, `lookup_software`, `get_kill_chain_phases`, `ping`

**Example prompts:**

> "What ATT&CK technique covers PowerShell execution? Give me the kill chain phase and detection guidance"

> "Look up T1059.001 and list all recommended mitigations"

> "What techniques does APT29 (Cozy Bear) use?"

> "Show me all techniques in the Credential Access tactic"

> "What threat groups are known to use Mimikatz?"

**Direct tool call:**
```json
{
  "tool": "lookup_technique",
  "arguments": {
    "attack_id": "T1059.001"
  }
}
```

**Example response:**
```json
{
  "attack_id": "T1059.001",
  "name": "Command and Scripting Interpreter: PowerShell",
  "kill_chain_phases": ["execution"],
  "platforms": ["Windows"],
  "detection": "If proper execution policy is set, adversaries will likely be able to define their own execution policy if they obtain administrator or system access...",
  "url": "https://attack.mitre.org/techniques/T1059/001/"
}
```

**Valid tactic shortnames:**
```
reconnaissance, resource-development, initial-access, execution,
persistence, privilege-escalation, defense-evasion, credential-access,
discovery, lateral-movement, collection, command-and-control,
exfiltration, impact
```

---

### vulncheck-mcp

Exploit intelligence and vulnerability prioritization via the [VulnCheck](https://vulncheck.com/) API. Responses are trimmed to conserve LLM context window tokens.

**Tools:** `cve_exploit_intel`, `cve_enrich`, `vulnerability_prioritization`, `kev_recent`, `kev_search`, `nvd_cve_lookup`, `nvd_recent`, `ping`

**Example prompts:**

> "Is CVE-2021-44228 in the CISA KEV catalog? How many public exploits exist?"

> "Enrich CVE-2024-3400 with both NVD CVSS data and exploit intelligence"

> "Prioritize these CVEs by exploit risk: CVE-2021-44228, CVE-2023-44487, CVE-2024-3400"

> "What vulnerabilities were added to the KEV catalog in the last 7 days?"

**Direct tool call:**
```json
{
  "tool": "cve_enrich",
  "arguments": {
    "cve_id": "CVE-2021-44228"
  }
}
```

**Example response:**
```json
{
  "cve_id": "CVE-2021-44228",
  "in_kev": true,
  "nvd": {
    "description": "Apache Log4j2 JNDI features do not protect against...",
    "cvss": {
      "v3.1": { "score": 10.0, "severity": "CRITICAL" }
    }
  },
  "kev": {
    "vendor": "Apache",
    "product": "Log4j2",
    "known_ransomware": "Known",
    "exploit_count": 247,
    "canary_exploited": true,
    "due_date": "2021-12-24"
  }
}
```

**Batch prioritization example:**
```json
{
  "tool": "vulnerability_prioritization",
  "arguments": {
    "cve_ids": "CVE-2021-44228,CVE-2023-44487,CVE-2024-3400,CVE-2022-30190"
  }
}
```

---

## Repository Structure

```
.
├── servers/
│   ├── abuseipdb-mcp/
│   │   ├── pyproject.toml
│   │   └── server.py
│   ├── whois-mcp/
│   ├── nvd-cve-mcp/
│   ├── shodan-mcp/
│   ├── mitre-attack-mcp/
│   └── vulncheck-mcp/
├── deployments/
│   ├── http/
│   │   ├── Dockerfile.abuseipdb
│   │   ├── Dockerfile.whois
│   │   ├── Dockerfile.nvd-cve
│   │   ├── Dockerfile.shodan
│   │   ├── Dockerfile.mitre-attack
│   │   ├── Dockerfile.vulncheck
│   │   ├── docker-compose.yml
│   │   └── mendconfig/
│   └── kubernetes/
│       ├── base/
│       │   ├── ingress.yaml
│       │   └── network-policy.yaml
│       └── services/
│           └── <server-name>/
│               ├── deployment.yaml
│               ├── service.yaml
│               └── hpa.yaml
├── .github/
│   └── workflows/
│       └── ci-cd.yaml
├── client-config.json         # Production MCP client config
├── client-config-local.json   # Local dev MCP client config
└── README.md
```

---

## Dependency Management

Each server uses `uv` + `pyproject.toml` for reproducible builds. To generate or update a lock file:

```bash
cd servers/<server-name>
uv lock
```

Commit both `pyproject.toml` and `uv.lock`. The Dockerfiles use `uv sync --no-dev --frozen` to install exact pinned versions.

---

## Security Notes

- **No secrets at rest** — API keys are never stored in environment variables, config maps, or on disk. They arrive per-request via HTTP headers and are used exactly once.
- **Container hardening** — non-root `mcp` user, read-only root filesystem, all Linux capabilities dropped.
- **Network policy** — Kubernetes NetworkPolicy restricts ingress to the nginx-ingress namespace only, and egress to DNS (53), HTTPS (443), and WHOIS (43) to public IPs only. Private RFC1918 ranges are blocked on egress.
- **Platform auth** — in production, all MCP endpoints are protected by HTTP Basic Auth at the nginx ingress layer. Generate a token with `openssl rand -hex 32`.

---

## Known Gotchas

1. **Import path** — use `from mcp.server.fastmcp import FastMCP`, NOT `from fastmcp import FastMCP`. The latter class does not accept `transport_security` and will crash at startup.
2. **DNS rebinding protection** — must be disabled via `TransportSecuritySettings(enable_dns_rebinding_protection=False)`. The nginx ingress rewrites the `Host` header, which would otherwise cause requests to be rejected.
3. **K8s probes** — use `tcpSocket`, not `httpGet`. The MCP protocol returns HTTP 406 on plain GET requests.
4. **Dockerfile CMD** — use `["python", "server.py"]`, not `["uv", "run", "python", "server.py"]`. `uv run` attempts to write to the filesystem, which fails with `readOnlyRootFilesystem: true`.
5. **MITRE ATT&CK memory** — the STIX bundle is ~200MB loaded into memory. The pod needs at least 256Mi; the default 128Mi will OOMKill.
6. **Port conflict** — Shodan (8011) and VulnCheck were originally both assigned 8011. VulnCheck is reassigned to 8013 in this suite.

---

## License

MIT

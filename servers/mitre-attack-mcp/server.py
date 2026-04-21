"""
MITRE ATT&CK MCP Server

Exposes the MITRE ATT&CK knowledge base as MCP tools, enabling AI agents
to map alerts to kill chain stages, look up techniques/groups/software,
and query mitigations and detection data sources.

Operates entirely offline against a STIX 2.0 JSON bundle loaded into
memory at startup using the mitreattack-python library.
"""

import json
import logging
import os
import re

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mitreattack.stix20 import MitreAttackData

logging.basicConfig(
    level=getattr(logging, os.environ.get("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("mitre-attack-mcp")

HOST = os.environ.get("FASTMCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("FASTMCP_PORT", "8012"))

STIX_DATA_PATH = os.environ.get(
    "STIX_DATA_PATH", "/app/data/enterprise-attack.json"
)

mcp = FastMCP(
    "mitre-attack-mcp",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False,
    ),
)

logger.info("Loading MITRE ATT&CK STIX data from %s ...", STIX_DATA_PATH)
attack_data = MitreAttackData(stix_filepath=STIX_DATA_PATH)
logger.info("MITRE ATT&CK data loaded successfully")

ATTACK_ID_RE = re.compile(r"^[A-Z]{1,2}\d{4}(\.\d{3})?$")

VALID_TACTIC_SHORTNAMES = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

VALID_DOMAINS = ["enterprise-attack", "mobile-attack", "ics-attack"]


def _validate_attack_id(attack_id: str) -> str:
    attack_id = attack_id.strip().upper()
    if not ATTACK_ID_RE.match(attack_id):
        raise ValueError(
            f"Invalid ATT&CK ID format: '{attack_id}'. "
            "Expected format like T1059 or T1059.001."
        )
    return attack_id


def _validate_tactic(shortname: str) -> str:
    shortname = shortname.strip().lower()
    if shortname not in VALID_TACTIC_SHORTNAMES:
        raise ValueError(
            f"Invalid tactic shortname: '{shortname}'. "
            f"Valid values: {', '.join(VALID_TACTIC_SHORTNAMES)}"
        )
    return shortname


def _validate_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if domain not in VALID_DOMAINS:
        raise ValueError(
            f"Invalid domain: '{domain}'. "
            f"Valid values: {', '.join(VALID_DOMAINS)}"
        )
    return domain


def _stix_to_dict(obj) -> dict:
    if obj is None:
        return {}
    if hasattr(obj, "serialize"):
        return json.loads(obj.serialize())
    if isinstance(obj, dict):
        return obj
    return {"raw": str(obj)}


def _format_technique(technique) -> dict:
    d = _stix_to_dict(technique)
    kill_chain = []
    for phase in d.get("kill_chain_phases", []):
        kill_chain.append(phase.get("phase_name", ""))
    return {
        "attack_id": _extract_attack_id(d),
        "name": d.get("name", ""),
        "description": d.get("description", ""),
        "kill_chain_phases": kill_chain,
        "platforms": d.get("x_mitre_platforms", []),
        "detection": d.get("x_mitre_detection", ""),
        "is_subtechnique": d.get("x_mitre_is_subtechnique", False),
        "stix_id": d.get("id", ""),
        "url": _build_attack_url(d),
    }


def _extract_attack_id(d: dict) -> str:
    for ref in d.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _build_attack_url(d: dict) -> str:
    for ref in d.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("url"):
            return ref["url"]
    return ""


def _format_group(group) -> dict:
    d = _stix_to_dict(group)
    return {
        "attack_id": _extract_attack_id(d),
        "name": d.get("name", ""),
        "aliases": d.get("aliases", []),
        "description": d.get("description", ""),
        "stix_id": d.get("id", ""),
        "url": _build_attack_url(d),
    }


def _format_software(software) -> dict:
    d = _stix_to_dict(software)
    return {
        "attack_id": _extract_attack_id(d),
        "name": d.get("name", ""),
        "type": d.get("type", ""),
        "aliases": d.get("x_mitre_aliases", d.get("aliases", [])),
        "description": d.get("description", ""),
        "platforms": d.get("x_mitre_platforms", []),
        "stix_id": d.get("id", ""),
        "url": _build_attack_url(d),
    }


def _format_mitigation(mitigation) -> dict:
    d = _stix_to_dict(mitigation)
    return {
        "attack_id": _extract_attack_id(d),
        "name": d.get("name", ""),
        "description": d.get("description", ""),
        "stix_id": d.get("id", ""),
        "url": _build_attack_url(d),
    }


def _format_datacomponent(dc) -> dict:
    d = _stix_to_dict(dc)
    return {
        "name": d.get("name", ""),
        "description": d.get("description", ""),
        "stix_id": d.get("id", ""),
    }


def _format_relationship_entry(entry, formatter) -> dict:
    obj = entry.get("object") if isinstance(entry, dict) else getattr(entry, "object", None)
    rels = entry.get("relationships") if isinstance(entry, dict) else getattr(entry, "relationships", [])
    result = formatter(obj)
    if rels:
        rel_descriptions = []
        for r in (rels if isinstance(rels, list) else [rels]):
            rd = _stix_to_dict(r)
            desc = rd.get("description", "")
            if desc:
                rel_descriptions.append(desc)
        if rel_descriptions:
            result["relationship_descriptions"] = rel_descriptions
    return result


def _format_response(data) -> str:
    return json.dumps(data, indent=2, default=str)


@mcp.tool()
def lookup_technique(attack_id: str = "", name: str = "") -> str:
    """Look up a MITRE ATT&CK technique by its ATT&CK ID or name.

    Returns technique details including kill chain phases (tactics),
    platforms, detection guidance, and description. Use this to map an
    observed alert or behavior to a specific ATT&CK technique.

    Args:
        attack_id: ATT&CK ID like T1059, T1059.001, TA0001. Preferred lookup method.
        name: Technique name (case-sensitive). Used if attack_id is not provided.
    """
    if not attack_id and not name:
        raise ValueError("Provide either attack_id or name.")

    if attack_id:
        attack_id = _validate_attack_id(attack_id)
        technique = attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
        if technique is None:
            return _format_response({"error": f"No technique found for ATT&CK ID: {attack_id}"})
        result = _format_technique(technique)
        tactics = attack_data.get_tactics_by_technique(technique.id)
        if tactics:
            result["tactics"] = [
                {"name": t.name, "shortname": t.get("x_mitre_shortname", "")}
                for t in tactics
            ]
        return _format_response(result)

    techniques = attack_data.get_objects_by_name(name, "attack-pattern")
    if not techniques:
        return _format_response({"error": f"No technique found with name: {name}"})
    techniques = attack_data.remove_revoked_deprecated(techniques)
    results = [_format_technique(t) for t in techniques]
    return _format_response(results if len(results) > 1 else results[0])


@mcp.tool()
def search_techniques(keyword: str, max_results: int = 20) -> str:
    """Search MITRE ATT&CK techniques by keyword across names and descriptions.

    Use this when you have an alert description (e.g. "PowerShell execution",
    "credential dumping", "lateral movement via RDP") and want to find
    matching ATT&CK techniques.

    Args:
        keyword: Search term to match against technique descriptions and names.
        max_results: Maximum results to return (1-100, default 20).
    """
    keyword = keyword.strip()
    if not keyword:
        raise ValueError("Keyword must not be empty.")
    max_results = max(1, min(100, max_results))

    matches = attack_data.get_objects_by_content(
        keyword, object_type="attack-pattern", remove_revoked_deprecated=True
    )

    results = []
    for t in matches[:max_results]:
        results.append(_format_technique(t))

    return _format_response({
        "query": keyword,
        "total_matches": len(matches),
        "returned": len(results),
        "techniques": results,
    })


@mcp.tool()
def get_tactic_techniques(
    tactic_shortname: str,
    domain: str = "enterprise-attack",
    include_subtechniques: bool = False,
) -> str:
    """List all ATT&CK techniques within a given tactic (kill chain phase).

    Args:
        tactic_shortname: The tactic shortname, e.g. 'initial-access',
            'execution', 'persistence', 'privilege-escalation',
            'defense-evasion', 'credential-access', 'discovery',
            'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact', 'reconnaissance', 'resource-development'.
        domain: ATT&CK domain. One of: enterprise-attack, mobile-attack, ics-attack.
        include_subtechniques: Whether to include sub-techniques (default False).
    """
    tactic_shortname = _validate_tactic(tactic_shortname)
    domain = _validate_domain(domain)

    techniques = attack_data.get_techniques_by_tactic(
        tactic_shortname, domain, remove_revoked_deprecated=True
    )

    if not include_subtechniques:
        techniques = [
            t for t in techniques
            if not getattr(t, "x_mitre_is_subtechnique", False)
        ]

    results = [_format_technique(t) for t in techniques]
    return _format_response({
        "tactic": tactic_shortname,
        "domain": domain,
        "technique_count": len(results),
        "techniques": results,
    })


@mcp.tool()
def get_technique_mitigations(attack_id: str) -> str:
    """Get recommended mitigations for a specific ATT&CK technique.

    Args:
        attack_id: ATT&CK technique ID, e.g. T1059, T1059.001.
    """
    attack_id = _validate_attack_id(attack_id)
    technique = attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
    if technique is None:
        return _format_response({"error": f"No technique found for ATT&CK ID: {attack_id}"})

    mitigations = attack_data.get_mitigations_mitigating_technique(technique.id)
    results = [_format_relationship_entry(m, _format_mitigation) for m in mitigations]

    return _format_response({
        "technique": attack_id,
        "technique_name": technique.name,
        "mitigation_count": len(results),
        "mitigations": results,
    })


@mcp.tool()
def get_technique_detections(attack_id: str) -> str:
    """Get data sources and components that can detect a specific ATT&CK technique.

    Args:
        attack_id: ATT&CK technique ID, e.g. T1059, T1059.001.
    """
    attack_id = _validate_attack_id(attack_id)
    technique = attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
    if technique is None:
        return _format_response({"error": f"No technique found for ATT&CK ID: {attack_id}"})

    datacomponents = attack_data.get_datacomponents_detecting_technique(technique.id)
    results = [_format_relationship_entry(dc, _format_datacomponent) for dc in datacomponents]

    technique_dict = _stix_to_dict(technique)
    detection_text = technique_dict.get("x_mitre_detection", "")

    return _format_response({
        "technique": attack_id,
        "technique_name": technique.name,
        "detection_guidance": detection_text,
        "datacomponent_count": len(results),
        "data_components": results,
    })


@mcp.tool()
def get_subtechniques(attack_id: str) -> str:
    """Get all sub-techniques of a parent ATT&CK technique.

    Args:
        attack_id: Parent ATT&CK technique ID, e.g. T1059.
    """
    attack_id = _validate_attack_id(attack_id)
    technique = attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
    if technique is None:
        return _format_response({"error": f"No technique found for ATT&CK ID: {attack_id}"})

    subtechniques = attack_data.get_subtechniques_of_technique(technique.id)
    results = []
    for entry in subtechniques:
        obj = entry.get("object") if isinstance(entry, dict) else getattr(entry, "object", None)
        if obj:
            results.append(_format_technique(obj))

    return _format_response({
        "parent_technique": attack_id,
        "parent_name": technique.name,
        "subtechnique_count": len(results),
        "subtechniques": results,
    })


@mcp.tool()
def lookup_group(name: str) -> str:
    """Look up a MITRE ATT&CK threat group by name or alias.

    Returns group details and the techniques the group is known to use.

    Args:
        name: Group name or alias, e.g. 'APT29', 'Lazarus Group', 'FIN7'.
    """
    name = name.strip()
    if not name:
        raise ValueError("Group name must not be empty.")

    groups = attack_data.get_groups_by_alias(name)
    if not groups:
        groups = attack_data.get_objects_by_name(name, "intrusion-set")
    if not groups:
        groups = attack_data.get_objects_by_content(
            name, object_type="intrusion-set", remove_revoked_deprecated=True
        )
    if not groups:
        return _format_response({"error": f"No group found matching: {name}"})

    groups = attack_data.remove_revoked_deprecated(groups)
    if not groups:
        return _format_response({"error": f"No active group found matching: {name}"})

    results = []
    for group in groups[:5]:
        g = _format_group(group)
        techniques = attack_data.get_techniques_used_by_group(group.id)
        g["techniques_used"] = []
        for entry in techniques[:30]:
            obj = entry.get("object") if isinstance(entry, dict) else getattr(entry, "object", None)
            if obj:
                g["techniques_used"].append({
                    "attack_id": _extract_attack_id(_stix_to_dict(obj)),
                    "name": getattr(obj, "name", ""),
                })
        g["technique_count"] = len(techniques)
        results.append(g)

    return _format_response(results if len(results) > 1 else results[0])


@mcp.tool()
def get_technique_groups(attack_id: str) -> str:
    """Get all threat groups known to use a specific ATT&CK technique.

    Args:
        attack_id: ATT&CK technique ID, e.g. T1059, T1059.001.
    """
    attack_id = _validate_attack_id(attack_id)
    technique = attack_data.get_object_by_attack_id(attack_id, "attack-pattern")
    if technique is None:
        return _format_response({"error": f"No technique found for ATT&CK ID: {attack_id}"})

    groups = attack_data.get_groups_using_technique(technique.id)
    results = [_format_relationship_entry(g, _format_group) for g in groups]

    return _format_response({
        "technique": attack_id,
        "technique_name": technique.name,
        "group_count": len(results),
        "groups": results,
    })


@mcp.tool()
def lookup_software(name: str) -> str:
    """Look up MITRE ATT&CK software (malware or tool) by name or alias.

    Args:
        name: Software name or alias, e.g. 'Cobalt Strike', 'Mimikatz', 'Empire'.
    """
    name = name.strip()
    if not name:
        raise ValueError("Software name must not be empty.")

    software_list = attack_data.get_software_by_alias(name)
    if not software_list:
        software_list = attack_data.get_objects_by_name(name, "malware")
        if not software_list:
            software_list = attack_data.get_objects_by_name(name, "tool")
    if not software_list:
        software_list = attack_data.get_objects_by_content(
            name, object_type="malware", remove_revoked_deprecated=True
        )
        tool_matches = attack_data.get_objects_by_content(
            name, object_type="tool", remove_revoked_deprecated=True
        )
        software_list.extend(tool_matches)
    if not software_list:
        return _format_response({"error": f"No software found matching: {name}"})

    software_list = attack_data.remove_revoked_deprecated(software_list)
    if not software_list:
        return _format_response({"error": f"No active software found matching: {name}"})

    results = []
    for sw in software_list[:5]:
        s = _format_software(sw)
        techniques = attack_data.get_techniques_used_by_software(sw.id)
        s["techniques_used"] = []
        for entry in techniques[:30]:
            obj = entry.get("object") if isinstance(entry, dict) else getattr(entry, "object", None)
            if obj:
                s["techniques_used"].append({
                    "attack_id": _extract_attack_id(_stix_to_dict(obj)),
                    "name": getattr(obj, "name", ""),
                })
        s["technique_count"] = len(techniques)
        results.append(s)

    return _format_response(results if len(results) > 1 else results[0])


@mcp.tool()
def get_kill_chain_phases(domain: str = "enterprise-attack") -> str:
    """List all ATT&CK tactics (kill chain phases) in order.

    Args:
        domain: ATT&CK domain. One of: enterprise-attack, mobile-attack, ics-attack.
    """
    domain = _validate_domain(domain)

    tactics_by_matrix = attack_data.get_tactics_by_matrix()
    matrix_key = None
    for key in tactics_by_matrix:
        if domain.replace("-", " ").lower() in key.lower() or domain.lower() in key.lower():
            matrix_key = key
            break

    if matrix_key is None:
        all_tactics = attack_data.get_tactics(remove_revoked_deprecated=True)
        results = []
        for t in all_tactics:
            td = _stix_to_dict(t)
            results.append({
                "name": td.get("name", ""),
                "shortname": td.get("x_mitre_shortname", ""),
                "description": td.get("description", ""),
                "stix_id": td.get("id", ""),
            })
        return _format_response({"domain": domain, "tactics": results})

    tactics = tactics_by_matrix[matrix_key]
    results = []
    for idx, t in enumerate(tactics):
        td = _stix_to_dict(t)
        results.append({
            "order": idx + 1,
            "name": td.get("name", ""),
            "shortname": td.get("x_mitre_shortname", ""),
            "description": td.get("description", ""),
            "stix_id": td.get("id", ""),
        })

    return _format_response({
        "matrix": matrix_key,
        "domain": domain,
        "tactic_count": len(results),
        "tactics": results,
    })


@mcp.tool()
def ping() -> str:
    """Health check for the MITRE ATT&CK MCP server."""
    from datetime import datetime

    return json.dumps({
        "status": "ok",
        "server": "mitre-attack-mcp",
        "version": "0.1.0",
        "timestamp": datetime.now().isoformat(),
    })


if __name__ == "__main__":
    logger.info("Starting MITRE ATT&CK MCP server on %s:%d", HOST, PORT)
    app = mcp.streamable_http_app()
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)

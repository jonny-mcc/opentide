"""Import Elastic Security detection rules into OpenTide YAML.

Run through ``opentide generate extract elastic_security``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide
from opentide.platforms.elastic_security.client import ElasticSecurityClient

logger = get_logger(__name__)


class IndentedYamlDumper(yaml.SafeDumper):
    """YAML dumper preserving list indents and formatting."""

    def increase_indent(self, flow: bool = False, indentless: bool = False):
        return super().increase_indent(flow, False)


def _represent_str(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
    if "\n" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


IndentedYamlDumper.add_representer(str, _represent_str)


def sanitize_filename(name: str) -> str:
    """Sanitize string for cross-platform filenames."""
    invalid_chars = '<>:"/\\|?*'
    sanitized = "".join(" " if c in invalid_chars else c for c in name)
    return " ".join(sanitized.split())


def is_custom_rule(rule: dict[str, Any]) -> bool:
    """Check if an exported Elastic rule is a custom rule."""
    if rule.get("immutable") is True:
        return False
    if rule.get("rule_source"):
        return False
    return True


def extract_techniques(threats: list[dict[str, Any]]) -> list[str]:
    """Collapse Elastic threat[] array back into ATT&CK technique IDs."""
    techniques: list[str] = []
    for threat in threats:
        for tech in threat.get("technique", []):
            subtechniques = tech.get("subtechnique", [])
            if subtechniques:
                for sub in subtechniques:
                    if sub_id := sub.get("id"):
                        techniques.append(sub_id)
            elif tech_id := tech.get("id"):
                techniques.append(tech_id)
    return list(dict.fromkeys(techniques))


def _find_existing_files_by_uuid(destination: Path) -> dict[str, Path]:
    """Index existing OpenTide rule files by their metadata.uuid."""
    uuid_map: dict[str, Path] = {}
    if not destination.exists():
        return uuid_map
    for p in destination.glob("*.y*ml"):
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8")
            match = re.search(r"^\s*uuid:\s*['\"]?([a-zA-Z0-9_-]+)['\"]?", content, re.MULTILINE)
            if match:
                uuid_map[match.group(1)] = p
        except Exception:
            continue
    return uuid_map


def render_rule_doc(rule: dict[str, Any], tenant_name: str) -> tuple[str, str, dict[str, Any]]:
    """Convert an exported Elastic rule dict into an OpenTide rule document.

    Returns:
        (rule_id, rule_name, rule_doc)
    """
    rule_id = str(rule.get("rule_id") or rule.get("id") or "")
    rule_name = str(rule.get("name", "Unnamed Rule"))
    description = str(rule.get("description", ""))

    authors = rule.get("author", [])
    if isinstance(authors, list) and authors:
        author = str(authors[0])
        contributors = [str(a) for a in authors[1:]]
    elif isinstance(authors, str):
        author = authors
        contributors = []
    else:
        author = "OpenTide Elastic Security Importer"
        contributors = []

    created = str(rule.get("created_at", "")).split("T")[0] or "2026-01-01"
    modified = str(rule.get("updated_at", "")).split("T")[0] or created

    status = "PRODUCTION" if rule.get("enabled", True) else "DISABLED"
    severity = str(rule.get("severity", "medium")).title()

    elastic_cfg: dict[str, Any] = {
        "schema": "platform::elastic_security::1.0",
        "status": status,
        "tenants": [tenant_name],
        "type": rule.get("type", "query"),
    }

    optional_mappings = [
        "language",
        "query",
        "index",
        "data_view_id",
        "from",
        "interval",
        "to",
        "severity",
        "risk_score",
        "tags",
        "filters",
        "setup",
        "max_signals",
        "timestamp_override",
        "timestamp_override_fallback_disabled",
        "building_block_type",
        "timestamp_field",
        "event_category_override",
        "tiebreaker_field",
        "threshold",
        "threat_index",
        "threat_mapping",
        "threat_query",
        "threat_language",
        "new_terms_fields",
        "history_window_start",
        "machine_learning_job_id",
        "anomaly_threshold",
        "alert_suppression",
        "exceptions_list",
        "actions",
        "response_actions",
    ]

    for key in optional_mappings:
        val = rule.get(key)
        if val is not None:
            elastic_cfg[key] = val

    rule_doc: dict[str, Any] = {
        "name": rule_name,
        "metadata": {
            "uuid": rule_id,
            "schema": "rule::1.0",
            "version": 1,
            "created": created,
            "modified": modified,
            "tlp": "amber",
            "author": author,
        },
        "description": description,
        "response": {
            "alert_severity": severity,
        },
        "status": status,
        "configurations": {
            "elastic_security": elastic_cfg,
        },
    }

    if contributors:
        rule_doc["metadata"]["contributors"] = contributors

    if rule.get("note"):
        rule_doc["response"]["procedure"] = rule["note"]

    techniques = extract_techniques(rule.get("threat", []))
    if techniques:
        rule_doc["techniques"] = techniques

    return rule_id, rule_name, rule_doc


def import_rules_from_ndjson(
    ndjson_data: str,
    tenant_name: str,
    destination: Path = Path("Imported"),
) -> list[Path]:
    """Parse NDJSON rules export and write custom rules to YAML files in destination."""
    destination.mkdir(parents=True, exist_ok=True)
    existing_uuid_map = _find_existing_files_by_uuid(destination)
    written_paths: list[Path] = []

    for line in ndjson_data.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rule = json.loads(line)
        except Exception:
            continue

        if not is_custom_rule(rule):
            continue

        rule_id, rule_name, doc = render_rule_doc(rule, tenant_name)
        if not rule_id:
            continue

        if rule_id in existing_uuid_map:
            target_path = existing_uuid_map[rule_id]
        else:
            base_name = sanitize_filename(rule_name) or rule_id
            candidate = destination / f"{base_name}.yaml"
            if candidate.exists():
                short_id = rule_id.split("-")[0] if "-" in rule_id else rule_id[:8]
                target_path = destination / f"{base_name}_{short_id}.yaml"
            else:
                target_path = candidate
            existing_uuid_map[rule_id] = target_path

        yaml_content = yaml.dump(doc, Dumper=IndentedYamlDumper, sort_keys=False)
        target_path.write_text(yaml_content, encoding="utf-8")
        written_paths.append(target_path)
        logger.info("imported_elastic_security_rule", detail=target_path.name, arg0=tenant_name)

    return written_paths


def import_elastic_security_rules(
    tenant_name: str | None = None,
    space: str | None = None,
    destination: Path = Path("Imported"),
) -> list[Path]:
    """Connect to Kibana detection engine, export rules, and write them to disk."""
    tenants = OpenTide.Configurations.Systems.ElasticSecurity.tenants
    if not tenants:
        logger.critical(
            "elastic_security_tenants_not_configured",
            detail="You must first have Elastic Security tenants configured to initiate the import",
            advice="run 'opentide setup platforms --elastic-security'",
        )
        raise RuntimeError("No Elastic Security tenants are configured")

    if tenant_name:
        selected_tenants = [t for t in tenants if t.name == tenant_name]
        if not selected_tenants:
            raise RuntimeError(f"Tenant '{tenant_name}' is not configured for Elastic Security")
    else:
        selected_tenants = tenants

    written_paths: list[Path] = []

    for tenant in selected_tenants:
        setup = tenant.setup
        # If tenant config defines multiple spaces, space is a required argument
        tenant_spaces = getattr(setup, "spaces", None)
        if isinstance(tenant_spaces, list) and len(tenant_spaces) > 1:
            if not space:
                raise RuntimeError(
                    f"Tenant '{tenant.name}' defines multiple spaces; specify space parameter to select one"
                )
            target_space = space
        elif space is not None:
            target_space = space
        else:
            target_space = getattr(setup, "space", "") or ""

        client = ElasticSecurityClient(
            url=setup.kibana_url,
            api_key=setup.api_key,
            space=target_space,
        )

        ndjson = client.export_rules()
        paths = import_rules_from_ndjson(ndjson, tenant_name=tenant.name, destination=destination)
        written_paths.extend(paths)

    return written_paths


def run(
    tenant: str | None = None,
    space: str | None = None,
    destination: Path | None = None,
) -> None:
    """Entry point used by ``opentide generate extract elastic_security``."""
    dest = destination if destination is not None else Path("Imported")
    import_elastic_security_rules(tenant_name=tenant, space=space, destination=dest)


if __name__ == "__main__":
    run()

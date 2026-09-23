"""Unit tests for Elastic Security extract importer."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from opentide.extraction.elastic_security_importer import (
    extract_techniques,
    import_elastic_security_rules,
    import_rules_from_ndjson,
    is_custom_rule,
    render_rule_doc,
    sanitize_filename,
)


def test_sanitize_filename() -> None:
    assert sanitize_filename('Rule: With <Bad> "Chars" / Pipe | Test') == "Rule With Bad Chars Pipe Test"


def test_is_custom_rule() -> None:
    assert is_custom_rule({"name": "Custom"}) is True
    assert is_custom_rule({"name": "Prebuilt", "immutable": True}) is False
    assert is_custom_rule({"name": "Elastic Builtin", "rule_source": "elastic"}) is False
    assert is_custom_rule({"name": "Package Rule", "rule_source": "prebuilt"}) is False


def test_extract_techniques() -> None:
    threat = [
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0004", "name": "Privilege Escalation"},
            "technique": [
                {
                    "id": "T1548",
                    "name": "Abuse Elevation Control Mechanism",
                    "subtechnique": [
                        {"id": "T1548.002", "name": "Bypass User Account Control"}
                    ],
                },
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                },
            ],
        },
        {
            "framework": "MITRE ATT&CK",
            "tactic": {"id": "TA0002", "name": "Execution"},
            "technique": [
                {
                    "id": "T1059",
                    "name": "Command and Scripting Interpreter",
                }
            ],
        },
    ]
    techniques = extract_techniques(threat)
    assert techniques == ["T1548.002", "T1059"]


def test_render_rule_doc() -> None:
    rule = {
        "rule_id": "test-uuid-1234",
        "name": "Suspicious PowerShell Execution",
        "description": "Detects unusual powershell flags",
        "author": ["Security Team", "Jane Doe"],
        "severity": "high",
        "risk_score": 73,
        "type": "query",
        "language": "kuery",
        "query": "process.name: powershell.exe and process.args: -enc",
        "index": ["logs-endpoint.events.*"],
        "enabled": True,
        "note": "Investigate parent process.",
        "threat": [
            {
                "framework": "MITRE ATT&CK",
                "technique": [{"id": "T1059.001"}],
            }
        ],
    }
    rule_id, rule_name, doc = render_rule_doc(rule, "primary")
    assert rule_id == "test-uuid-1234"
    assert rule_name == "Suspicious PowerShell Execution"
    assert doc["metadata"]["uuid"] == "test-uuid-1234"
    assert doc["metadata"]["author"] == "Security Team"
    assert doc["metadata"]["contributors"] == ["Jane Doe"]
    assert doc["response"]["alert_severity"] == "High"
    assert doc["response"]["procedure"] == "Investigate parent process."
    assert doc["techniques"] == ["T1059.001"]
    assert doc["status"] == "PRODUCTION"

    config = doc["configurations"]["elastic_security"]
    assert config["type"] == "query"
    assert config["language"] == "kuery"
    assert config["query"] == "process.name: powershell.exe and process.args: -enc"
    assert config["index"] == ["logs-endpoint.events.*"]
    assert config["tenants"] == ["primary"]


def test_import_rules_from_ndjson_filtering_and_collision(tmp_path: Path) -> None:
    rule1 = {
        "rule_id": "uuid-1",
        "name": "Duplicate Name Rule",
        "description": "Rule 1 description",
        "severity": "medium",
        "type": "query",
        "query": "test query 1",
    }
    # Prebuilt rule to be skipped
    rule_prebuilt = {
        "rule_id": "uuid-prebuilt",
        "name": "Prebuilt Rule",
        "immutable": True,
        "type": "query",
        "query": "prebuilt query",
    }
    # Rule with collision on name
    rule2 = {
        "rule_id": "uuid-2-collision",
        "name": "Duplicate Name Rule",
        "description": "Rule 2 description",
        "severity": "low",
        "type": "query",
        "query": "test query 2",
    }

    ndjson_data = "\n".join([json.dumps(r) for r in [rule1, rule_prebuilt, rule2]])
    paths = import_rules_from_ndjson(ndjson_data, tenant_name="test_tenant", destination=tmp_path)

    assert len(paths) == 2
    # Verify prebuilt was skipped
    assert not (tmp_path / "Prebuilt Rule.yaml").exists()

    # Verify rule1 took the base name
    file1 = tmp_path / "Duplicate Name Rule.yaml"
    assert file1.exists()
    doc1 = yaml.safe_load(file1.read_text(encoding="utf-8"))
    assert doc1["metadata"]["uuid"] == "uuid-1"

    # Verify rule2 resolved collision with short rule_id
    file2 = tmp_path / "Duplicate Name Rule_uuid.yaml"
    assert file2.exists()
    doc2 = yaml.safe_load(file2.read_text(encoding="utf-8"))
    assert doc2["metadata"]["uuid"] == "uuid-2-collision"

    # Re-export rule1 with updated description - should update file1 in place without creating new file
    rule1_updated = dict(rule1)
    rule1_updated["description"] = "Updated description"
    paths_reimport = import_rules_from_ndjson(
        json.dumps(rule1_updated), tenant_name="test_tenant", destination=tmp_path
    )
    assert len(paths_reimport) == 1
    assert paths_reimport[0] == file1
    doc1_updated = yaml.safe_load(file1.read_text(encoding="utf-8"))
    assert doc1_updated["description"] == "Updated description"


def test_import_elastic_security_rules_no_tenants() -> None:
    with patch("opentide.extraction.elastic_security_importer.OpenTide") as mock_opentide:
        mock_opentide.Configurations.Systems.ElasticSecurity.tenants = []
        with pytest.raises(RuntimeError, match="No Elastic Security tenants are configured"):
            import_elastic_security_rules()


def test_import_elastic_security_rules_multiple_spaces_requires_space() -> None:
    mock_tenant = MagicMock()
    mock_tenant.name = "prod"
    mock_tenant.setup.spaces = ["space_a", "space_b"]
    with patch("opentide.extraction.elastic_security_importer.OpenTide") as mock_opentide:
        mock_opentide.Configurations.Systems.ElasticSecurity.tenants = [mock_tenant]
        with pytest.raises(RuntimeError, match="defines multiple spaces; specify space parameter"):
            import_elastic_security_rules()


def test_import_elastic_security_rules_success(tmp_path: Path) -> None:
    mock_tenant = MagicMock()
    mock_tenant.name = "primary"
    mock_tenant.setup.kibana_url = "http://localhost:5601"
    mock_tenant.setup.api_key = "fake-key"
    mock_tenant.setup.space = "soc"
    mock_tenant.setup.spaces = None

    sample_rule = {
        "rule_id": "rule-999",
        "name": "Custom Space Rule",
        "description": "Rule from space",
        "severity": "high",
        "type": "query",
        "query": "event.category: process",
    }

    with patch("opentide.extraction.elastic_security_importer.OpenTide") as mock_opentide:
        mock_opentide.Configurations.Systems.ElasticSecurity.tenants = [mock_tenant]
        with patch("opentide.extraction.elastic_security_importer.ElasticSecurityClient") as mock_client_cls:
            mock_client = mock_client_cls.return_value
            mock_client.export_rules.return_value = json.dumps(sample_rule)

            paths = import_elastic_security_rules(destination=tmp_path)
            assert len(paths) == 1
            assert paths[0].exists()
            mock_client_cls.assert_called_once_with(
                url="http://localhost:5601",
                api_key="fake-key",
                space="soc",
            )

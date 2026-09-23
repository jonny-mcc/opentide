"""Unit tests for Elastic Security rule compilation."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.compile import (
    SERVER_OWNED_FIELDS,
    check_version_compatibility,
    compile_rule,
    compile_rule_ndjson,
)


def _tenant(min_version: str = "8.14.0") -> ConfigurationModels.Systems.ElasticSecurity.Tenant:
    return ConfigurationModels.Systems.ElasticSecurity.Tenant(
        name="primary",
        description="Primary tenant",
        deployment="ALWAYS",
        setup=ConfigurationModels.Systems.ElasticSecurity.Tenant.Setup(
            proxy=False,
            ssl=False,
            kibana_url="http://localhost:5601",
            api_key="api_key_123",
            space="default",
            min_version=min_version,
        ),
    )


def _base_rule_dict(uuid: str = "00000000-0000-4000-8003-000000000001") -> dict:
    return {
        "name": "Test Rule",
        "metadata": {
            "uuid": uuid,
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "amber",
            "author": "Security Engineer",
            "contributors": ["Alice", "Bob"],
        },
        "description": "Rule description",
        "response": {
            "alert_severity": "High",
            "procedure": {"analysis": "Investigate immediately"},
        },
        "status": "PRODUCTION",
        "configurations": {
            "elastic_security": {
                "schema": "platform::elastic_security::1.0",
                "enabled": True,
                "type": "query",
                "language": "kuery",
                "query": "process.name: cmd.exe",
                "index": ["logs-endpoint.events.*"],
            }
        },
    }


def test_compile_query_rule(snapshot) -> None:
    data = _base_rule_dict()
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert compiled["rule_id"] == "00000000-0000-4000-8003-000000000001"
    assert compiled["name"] == "Test Rule"
    assert compiled["description"] == "Rule description"
    assert compiled["type"] == "query"
    assert compiled["language"] == "kuery"
    assert compiled["query"] == "process.name: cmd.exe"
    assert compiled["index"] == ["logs-endpoint.events.*"]
    assert compiled["author"] == ["Security Engineer", "Alice", "Bob"]
    assert compiled["severity"] == "high"
    assert compiled["risk_score"] == 73  # High default
    assert compiled["note"] == "Investigate immediately"
    assert compiled["enabled"] is True
    assert compiled == snapshot(name="compile_query")


def test_compile_eql_rule(snapshot) -> None:
    data = _base_rule_dict()
    data["configurations"]["elastic_security"] = {
        "schema": "platform::elastic_security::1.0",
        "type": "eql",
        "language": "eql",
        "query": "process where process.name == 'whoami.exe'",
        "index": ["winlogbeat-*"],
        "timestamp_field": "@timestamp",
        "event_category_override": "process",
        "tiebreaker_field": "event.sequence",
    }
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert compiled["type"] == "eql"
    assert compiled["language"] == "eql"
    assert compiled["query"] == "process where process.name == 'whoami.exe'"
    assert compiled["timestamp_field"] == "@timestamp"
    assert compiled["event_category_override"] == "process"
    assert compiled["tiebreaker_field"] == "event.sequence"
    assert compiled == snapshot(name="compile_eql")


def test_compile_esql_rule(snapshot) -> None:
    data = _base_rule_dict()
    data["configurations"]["elastic_security"] = {
        "schema": "platform::elastic_security::1.0",
        "type": "esql",
        "language": "esql",
        "query": "FROM logs-* | WHERE process.name == 'powershell.exe' | STATS count() BY user.name",
    }
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert compiled["type"] == "esql"
    assert compiled["language"] == "esql"
    assert "FROM logs-*" in compiled["query"]
    assert "index" not in compiled
    assert compiled == snapshot(name="compile_esql")


def test_compile_threshold_rule(snapshot) -> None:
    data = _base_rule_dict()
    data["configurations"]["elastic_security"] = {
        "schema": "platform::elastic_security::1.0",
        "type": "threshold",
        "query": "event.category: authentication",
        "index": ["logs-auth.*"],
        "threshold": {
            "field": "user.name",
            "value": 5,
            "cardinality": [{"field": "source.ip", "value": 3}],
        },
    }
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert compiled["type"] == "threshold"
    assert compiled["threshold"]["field"] == "user.name"
    assert compiled["threshold"]["value"] == 5
    assert compiled["threshold"]["cardinality"] == [{"field": "source.ip", "value": 3}]
    assert compiled == snapshot(name="compile_threshold")


def test_compile_threat_match_rule(snapshot) -> None:
    data = _base_rule_dict()
    data["configurations"]["elastic_security"] = {
        "schema": "platform::elastic_security::1.0",
        "type": "threat_match",
        "query": "file.hash.sha256: *",
        "index": ["logs-endpoint.*"],
        "threat_index": ["threat-intel-*"],
        "threat_mapping": [
            {
                "entries": [
                    {"field": "file.hash.sha256", "type": "mapping", "value": "threat.indicator.file.hash.sha256"}
                ]
            }
        ],
        "threat_query": "threat.indicator.type: hash",
        "threat_language": "kuery",
    }
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert compiled["type"] == "threat_match"
    assert compiled["threat_index"] == ["threat-intel-*"]
    assert compiled["threat_query"] == "threat.indicator.type: hash"
    assert compiled["threat_language"] == "kuery"
    assert len(compiled["threat_mapping"]) == 1
    assert compiled == snapshot(name="compile_threat_match")


def test_compile_new_terms_rule(snapshot) -> None:
    data = _base_rule_dict()
    data["configurations"]["elastic_security"] = {
        "schema": "platform::elastic_security::1.0",
        "type": "new_terms",
        "query": "process.name: *",
        "index": ["logs-endpoint.*"],
        "new_terms_fields": ["user.name", "process.name"],
        "history_window_start": "now-7d",
    }
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert compiled["type"] == "new_terms"
    assert compiled["new_terms_fields"] == ["user.name", "process.name"]
    assert compiled["history_window_start"] == "now-7d"
    assert compiled == snapshot(name="compile_new_terms")


def test_compile_machine_learning_rule(snapshot) -> None:
    data = _base_rule_dict()
    data["configurations"]["elastic_security"] = {
        "schema": "platform::elastic_security::1.0",
        "type": "machine_learning",
        "machine_learning_job_id": "v3_rare_process_by_user",
        "anomaly_threshold": 75,
    }
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert compiled["type"] == "machine_learning"
    assert compiled["machine_learning_job_id"] == "v3_rare_process_by_user"
    assert compiled["anomaly_threshold"] == 75
    assert "query" not in compiled
    assert "index" not in compiled
    assert compiled == snapshot(name="compile_machine_learning")


def test_compile_actions_and_exceptions_payload() -> None:
    data = _base_rule_dict()
    data["configurations"]["elastic_security"]["actions"] = [
        {
            "id": "slack-connector-1",
            "action_type_id": ".slack",
            "group": "default",
            "params": {"message": "Alert fired: {{rule.name}}"},
        }
    ]
    data["configurations"]["elastic_security"]["response_actions"] = [
        {
            "id": "isolate-host-1",
            "action_type_id": ".response-action",
            "group": "default",
            "params": {"action": "isolate"},
        }
    ]
    data["configurations"]["elastic_security"]["exceptions_list"] = [
        {
            "id": "rule-exc-1",
            "list_id": "endpoint-allowed-processes",
            "type": "detection",
            "namespace_type": "single",
        }
    ]
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    assert len(compiled["actions"]) == 1
    assert compiled["actions"][0]["id"] == "slack-connector-1"
    assert len(compiled["response_actions"]) == 1
    assert compiled["response_actions"][0]["id"] == "isolate-host-1"
    assert len(compiled["exceptions_list"]) == 1
    assert compiled["exceptions_list"][0]["list_id"] == "endpoint-allowed-processes"


def test_server_owned_fields_dropped() -> None:
    data = _base_rule_dict()
    rule = load_rule_from_dict(data)
    compiled = compile_rule(rule, _tenant())

    for server_field in SERVER_OWNED_FIELDS:
        assert server_field not in compiled, f"Server-owned field {server_field} was not dropped"


def test_compile_ndjson() -> None:
    data = _base_rule_dict()
    rule = load_rule_from_dict(data)
    ndjson = compile_rule_ndjson(rule, _tenant())

    assert isinstance(ndjson, str)
    assert "\n" not in ndjson.strip()
    parsed = json.loads(ndjson)
    assert parsed["rule_id"] == "00000000-0000-4000-8003-000000000001"


def test_version_compatibility_gating() -> None:
    # 8.14.0 baseline supports esql, alert_suppression, response_actions
    check_version_compatibility(
        {"type": "esql", "alert_suppression": {}, "response_actions": []}, "8.14.0"
    )
    # 9.0.0 supports everything
    check_version_compatibility(
        {"type": "esql", "alert_suppression": {}, "response_actions": []}, "9.0.0"
    )

    # ES|QL requires >= 8.11.0
    with pytest.raises(ValueError, match="ES\\|QL rules require Kibana 8.11.0+"):
        check_version_compatibility({"type": "esql"}, "8.10.0")

    # Alert suppression requires >= 8.6.0
    with pytest.raises(ValueError, match="alert_suppression requires Kibana 8.6.0+"):
        check_version_compatibility({"alert_suppression": {}}, "8.5.0")

    # Response actions require >= 8.14.0
    with pytest.raises(ValueError, match="response_actions require Kibana 8.14.0+"):
        check_version_compatibility({"response_actions": []}, "8.13.0")

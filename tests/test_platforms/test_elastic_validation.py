"""Tests for ElasticValidator and Elasticsearch checks (RFC 0007 §6)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest
import requests

from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.es_checks import (
    esql_from_sources,
    run_aggregation_fields_check,
    run_esql_preflight,
)
from opentide.platforms.elastic.validator import ElasticValidator


def _mock_response(status_code: int = 200, json_data: dict | list | None = None, text: str = ""):
    resp = requests.Response()
    resp.status_code = status_code
    if json_data is not None:
        resp._content = json.dumps(json_data).encode("utf-8")
        resp.headers["content-type"] = "application/json"
    else:
        resp._content = text.encode("utf-8")
    return resp


def test_esql_preflight_parsing_exception_fails_rule() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    with patch.object(client.session, "post") as mock_post:
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "parsing_exception",
                    "reason": "line 1:20: mismatched input 'WHER'",
                }
            },
        )
        with pytest.raises(ValueError, match="ES\\|QL parsing exception"):
            run_esql_preflight(client, "FROM logs-* | WHER process.name == 'test'")


def test_esql_preflight_unonboarded_sources_warns_and_passes() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    with (
        patch.object(client.session, "post") as mock_post,
        patch.object(client.session, "get") as mock_get,
    ):
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "verification_exception",
                    "reason": "Unknown index [logs-*]",
                }
            },
        )
        mock_get.return_value = _mock_response(
            200,
            json_data={"indices": [], "aliases": [], "data_streams": []},
        )
        # Should not raise, returns empty columns
        columns = run_esql_preflight(client, "FROM logs-* | WHERE process.name == 'test'")
        assert columns == []


def test_aggregation_fields_check_misspelt_field_fails() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "threshold",
        "threshold": {"field": ["source.misspelt"], "value": 5},
        "index": ["logs-*"],
    }
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": ["logs-2026.10"],
                "fields": {
                    "source.ip": {"ip": {"aggregatable": True}},
                },
            },
        )
        with pytest.raises(ValueError, match="Field 'source.misspelt' not found in mappings"):
            run_aggregation_fields_check(client, block)


def test_aggregation_fields_check_non_aggregatable_field_fails() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "threshold",
        "threshold": {"field": ["message"], "value": 5},
        "index": ["logs-*"],
    }
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": ["logs-2026.10"],
                "fields": {
                    "message": {"text": {"aggregatable": False}},
                },
            },
        )
        with pytest.raises(ValueError, match="Field 'message' is not aggregatable"):
            run_aggregation_fields_check(client, block)


def test_aggregation_fields_check_unonboarded_sources_warns_and_passes() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    block = {
        "type": "threshold",
        "threshold": {"field": ["source.ip"], "value": 5},
        "index": ["logs-*"],
    }
    with patch.object(client.session, "get") as mock_get:
        mock_get.return_value = _mock_response(
            200,
            json_data={
                "indices": [],
                "fields": {},
            },
        )
        # Should not raise exception
        run_aggregation_fields_check(client, block)


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks")
def test_validator_preview_reports_log_errors(mock_checks, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.delenv("VALIDATION_WARNING_RAISED", raising=False)
    mock_checks.return_value = []
    setup = ConfigurationModels.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.test:5601",
        elasticsearch_url="https://es.test:9200",
        api_key="test-key",
        space="default",
    )
    tenant = ConfigurationModels.Systems.Elastic.Tenant(
        name="test-tenant",
        description="test",
        deployment=DeploymentStrategy.ALWAYS,
        setup=setup,
    )
    raw = {
        "name": "Preview Broken Rule",
        "metadata": {
            "uuid": "00000000-0000-4000-8003-000000000009",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "clear",
            "author": "Author",
        },
        "description": "Test description",
        "techniques": [],
        "response": {"alert_severity": "High"},
        "configurations": {
            "elastic": {
                "enabled": True,
                "schema": "platform::elastic::1.0",
                "status": "STAGING",
                "type": "query",
                "query": "process.name: *",
                "index": ["logs-*"],
            }
        },
    }
    from opentide.loading.rule_loader import load_rule_from_dict

    rule = load_rule_from_dict(raw)
    batch = MagicMock(tenant=tenant, rules=[rule])

    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(
            200,
            json_data={"logs": [{"errors": ["Unknown field 'foo.bar' in query"]}]},
        )
        validator.validate([rule])
        assert os.environ.get("VALIDATION_ERROR_RAISED") == "1"


def _clear_validation_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VALIDATION_ERROR_RAISED", raising=False)
    monkeypatch.delenv("VALIDATION_WARNING_RAISED", raising=False)


def _elastic_rule(
    name: str,
    uuid: str,
    *,
    rule_type: str = "query",
    query: str = "process.name: *",
    lookback: str | None = None,
    index: list[str] | None = None,
) -> object:
    from opentide.loading.rule_loader import load_rule_from_dict

    elastic: dict = {
        "enabled": True,
        "schema": "platform::elastic::1.0",
        "status": "STAGING",
        "type": rule_type,
        "query": query,
    }
    if rule_type not in ("esql", "machine_learning"):
        elastic["index"] = index or ["logs-*"]
    if lookback is not None:
        elastic["scheduling"] = {"interval": "5m", "lookback": lookback}
    return load_rule_from_dict(
        {
            "name": name,
            "metadata": {
                "uuid": uuid,
                "schema": "rule::1.0",
                "version": 1,
                "created": "2026-01-01",
                "modified": "2026-01-02",
                "tlp": "clear",
                "author": "Author",
            },
            "description": "Test description",
            "techniques": [],
            "response": {"alert_severity": "High"},
            "configurations": {"elastic": elastic},
        }
    )


def _tenant() -> ConfigurationModels.Systems.Elastic.Tenant:
    setup = ConfigurationModels.Systems.Elastic.Tenant.Setup(
        ssl=True,
        url="https://kibana.test:5601",
        elasticsearch_url="https://es.test:9200",
        api_key="test-key",
        space="default",
    )
    return ConfigurationModels.Systems.Elastic.Tenant(
        name="test-tenant",
        description="test",
        deployment=DeploymentStrategy.ALWAYS,
        setup=setup,
    )


def test_esql_from_sources_stops_before_metadata() -> None:
    query = 'FROM logs-* METADATA _id, _version | WHER process.name == "test"'
    assert esql_from_sources(query) == "logs-*"


def test_esql_preflight_metadata_query_parsing_exception_fails() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    query = 'FROM logs-* METADATA _id, _version | WHER process.name == "test"'
    with patch.object(client.session, "post") as mock_post:
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "parsing_exception",
                    "reason": "line 1:20: mismatched input 'WHER'",
                }
            },
        )
        with pytest.raises(ValueError, match="ES\\|QL parsing exception"):
            run_esql_preflight(client, query)


def test_esql_preflight_verification_resolves_sources_without_metadata() -> None:
    client = ElasticClient(url="https://kibana.test", elasticsearch_url="https://es.test")
    query = 'FROM logs-* METADATA _id, _version | WHER process.name == "test"'
    with (
        patch.object(client.session, "post") as mock_post,
        patch.object(client.session, "get") as mock_get,
    ):
        mock_post.return_value = _mock_response(
            400,
            json_data={
                "error": {
                    "type": "verification_exception",
                    "reason": "Unknown index [logs-*]",
                }
            },
        )
        mock_get.return_value = _mock_response(
            200,
            json_data={"indices": [], "aliases": [], "data_streams": []},
        )
        assert run_esql_preflight(client, query) == []
        requested = mock_get.call_args[0][0]
        assert "/_resolve/index/logs-%2A" in requested
        assert "METADATA" not in requested


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_checks_every_rule_when_the_first_preview_fails(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    first = _elastic_rule("First", "00000000-0000-4000-8003-000000000001")
    second = _elastic_rule("Second", "00000000-0000-4000-8003-000000000002")
    batch = MagicMock(tenant=_tenant(), rules=[first, second])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.side_effect = [
            _mock_response(200, json_data={"logs": [{"errors": ["bad query"]}]}),
            _mock_response(200, json_data={"logs": []}),
        ]
        validator.validate([first, second])
    assert mock_preview.call_count == 2
    assert os.environ.get("VALIDATION_ERROR_RAISED") == "1"


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_warnings_set_the_warning_flag(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    rule = _elastic_rule(
        "Lookback",
        "00000000-0000-4000-8003-000000000003",
        rule_type="esql",
        query="FROM logs-* | WHERE process.name == 'x'",
        lookback="0m",
    )
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(
            200,
            json_data={"logs": [{"warnings": ["index logs-* does not exist"]}]},
        )
        validator.validate([rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") == "1"
    assert os.environ.get("VALIDATION_ERROR_RAISED") is None


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_lowercase_metadata_id_does_not_warn(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    rule = _elastic_rule(
        "Deduped",
        "00000000-0000-4000-8003-000000000004",
        rule_type="esql",
        query="FROM logs-* metadata _id | WHERE process.name == 'x'",
    )
    batch = MagicMock(tenant=_tenant(), rules=[rule])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(200, json_data={"logs": []})
        validator.validate([rule])
    assert os.environ.get("VALIDATION_WARNING_RAISED") is None


@patch("opentide.platforms.elastic.validator.run_elasticsearch_checks", return_value=[])
def test_validator_preview_403_skips_the_rest_of_the_tenant(
    _mock_checks, monkeypatch: pytest.MonkeyPatch
) -> None:
    _clear_validation_flags(monkeypatch)
    first = _elastic_rule("Denied", "00000000-0000-4000-8003-000000000005")
    second = _elastic_rule("Later", "00000000-0000-4000-8003-000000000006")
    batch = MagicMock(tenant=_tenant(), rules=[first, second])
    validator = ElasticValidator()
    with (
        patch("opentide.platforms.elastic.validator.TideDeployment") as mock_deployment,
        patch.object(ElasticClient, "preview_rule") as mock_preview,
    ):
        mock_deployment.return_value.rule_deployment = [batch]
        mock_preview.return_value = _mock_response(403, text="forbidden")
        validator.validate([first, second])
    assert mock_preview.call_count == 1
    assert os.environ.get("VALIDATION_ERROR_RAISED") == "1"

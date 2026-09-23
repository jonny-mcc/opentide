"""Unit tests for Elastic Security client and deployer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.client import ElasticSecurityClient
from opentide.platforms.elastic_security.deployer import ElasticSecurityDeploy


def _tenant(
    space: str = "default",
    min_version: str = "8.14.0",
) -> ConfigurationModels.Systems.ElasticSecurity.Tenant:
    return ConfigurationModels.Systems.ElasticSecurity.Tenant(
        name="primary",
        description="Primary tenant",
        deployment="ALWAYS",
        setup=ConfigurationModels.Systems.ElasticSecurity.Tenant.Setup(
            proxy=False,
            ssl=False,
            kibana_url="https://kibana.example.com:5601",
            api_key="secret-api-key",
            space=space,
            overwrite_exceptions=True,
            overwrite_action_connectors=True,
            min_version=min_version,
        ),
    )


def test_client_url_construction() -> None:
    # Default space
    client_default = ElasticSecurityClient("https://kibana.example.com:5601", "key", space="default")
    assert client_default.url_for("/api/detection_engine/rules") == "https://kibana.example.com:5601/api/detection_engine/rules"

    # Empty space
    client_empty = ElasticSecurityClient("https://kibana.example.com:5601", "key", space="")
    assert client_empty.url_for("/api/detection_engine/rules") == "https://kibana.example.com:5601/api/detection_engine/rules"

    # Named space
    client_space = ElasticSecurityClient("https://kibana.example.com:5601", "key", space="soc")
    assert client_space.url_for("/api/detection_engine/rules") == "https://kibana.example.com:5601/s/soc/api/detection_engine/rules"


def test_client_headers() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    headers = client.session.headers
    assert headers["kbn-xsrf"] == "true"
    assert headers["Authorization"] == "ApiKey secret-key"


def test_client_import_rules_multipart() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True, "success_count": 1}

    with patch.object(client.session, "post", return_value=mock_resp) as mock_post:
        result = client.import_rules(
            '{"rule_id": "test-1"}',
            overwrite=True,
            overwrite_exceptions=True,
            overwrite_action_connectors=False,
        )

    assert result["success"] is True
    mock_post.assert_called_once()
    _, kwargs = mock_post.call_args
    assert kwargs["params"] == {
        "overwrite": "true",
        "overwrite_exceptions": "true",
        "overwrite_action_connectors": "false",
    }
    assert "files" in kwargs
    file_tuple = kwargs["files"]["file"]
    assert file_tuple[0] == "rules.ndjson"
    assert file_tuple[1] == b'{"rule_id": "test-1"}'
    assert file_tuple[2] == "application/x-ndjson"


def test_client_patch_rule() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"rule_id": "rule-1", "enabled": False}

    with patch.object(client.session, "patch", return_value=mock_resp) as mock_patch:
        result = client.patch_rule({"rule_id": "rule-1", "enabled": False})

    assert result["enabled"] is False
    mock_patch.assert_called_once_with(
        "https://kibana.example.com:5601/api/detection_engine/rules",
        json={"rule_id": "rule-1", "enabled": False},
        timeout=30,
    )


def test_client_delete_rule() -> None:
    client = ElasticSecurityClient("https://kibana.example.com:5601", "secret-key")
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"rule_id": "rule-1"}

    with patch.object(client.session, "delete", return_value=mock_resp) as mock_delete:
        result = client.delete_rule(rule_id="rule-1")

    assert result["rule_id"] == "rule-1"
    mock_delete.assert_called_once_with(
        "https://kibana.example.com:5601/api/detection_engine/rules",
        params={"rule_id": "rule-1"},
        timeout=30,
    )


def test_deployer_active_rules() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.RELEASE

    rule = load_rule_from_dict({
        "name": "Test Rule",
        "description": "Test description",
        "metadata": {
            "uuid": "00000000-0000-4000-8003-000000000001",
            "schema": "rule::1.0",
            "version": 1,
            "created": "2026-01-01",
            "modified": "2026-01-02",
            "tlp": "amber",
            "author": "SecEng",
        },
        "response": {"alert_severity": "High"},
        "status": "PRODUCTION",
        "configurations": {
            "elastic_security": {
                "schema": "platform::elastic_security::1.0",
                "type": "query",
                "query": "process.name: cmd.exe",
                "index": ["logs-*"],
            }
        },
    })
    mock_batch.rules = [rule]

    with patch("opentide.platforms.elastic_security.deployer.check_status", return_value=StatusStrategy.RELEASE):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)

    mock_client.import_rules.assert_called_once()


def test_deployer_disablement() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.DISABLEMENT

    mock_rule = MagicMock()
    mock_rule.name = "Disabled Rule"
    mock_rule.status = "DISABLED"
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000002"
    mock_rule.configurations.elastic_security.status = "DISABLED"
    mock_rule.configurations.elastic_security.rule_id = None

    mock_batch.rules = [mock_rule]

    with patch("opentide.platforms.elastic_security.deployer.check_status", return_value=StatusStrategy.DISABLEMENT):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)

    mock_client.patch_rule.assert_called_once_with({"rule_id": "00000000-0000-4000-8003-000000000002", "enabled": False})


def test_deployer_deletion() -> None:
    tenant = _tenant()
    deployer = ElasticSecurityDeploy()
    mock_client = MagicMock(spec=ElasticSecurityClient)

    mock_batch = MagicMock()
    mock_batch.tenant = tenant
    mock_batch.strategy = StatusStrategy.DELETION

    mock_rule = MagicMock()
    mock_rule.name = "Deleted Rule"
    mock_rule.status = "DELETED"
    mock_rule.metadata.uuid = "00000000-0000-4000-8003-000000000003"
    mock_rule.configurations.elastic_security.status = "DELETED"
    mock_rule.configurations.elastic_security.rule_id = None

    mock_batch.rules = [mock_rule]

    with patch("opentide.platforms.elastic_security.deployer.check_status", return_value=StatusStrategy.DELETION):
        deployer.deploy_mdr(mock_batch, mock_client, tenant)

    mock_client.delete_rule.assert_called_once_with("00000000-0000-4000-8003-000000000003")

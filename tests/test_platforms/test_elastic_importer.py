"""Tests for Elastic Security rule extraction (`opentide.extraction.elastic_importer`)."""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

from opentide.extraction.elastic_importer import (
    OPENTIDE_MIGRATION_NS,
    kibana_to_opentide,
    run,
)
from opentide.loading.rule_loader import load_rule_from_dict


def _sample_kibana_rule(
    *,
    rule_id: str = "6b2e9c14-7a31-4f58-9d0c-1e8a4b7c2d90",
    name: str = "Suspicious PowerShell",
    enabled: bool = True,
    immutable: bool = False,
    response_actions: list[dict] | None = None,
) -> dict:
    return {
        "rule_id": rule_id,
        "name": name,
        "description": "Detects suspicious PowerShell execution.",
        "type": "query",
        "language": "kuery",
        "query": 'process.name : "powershell.exe"',
        "index": ["logs-endpoint.events.process-*"],
        "interval": "5m",
        "from": "now-6m",
        "severity": "high",
        "risk_score": 73,
        "enabled": enabled,
        "immutable": immutable,
        "author": ["Elastic"],
        "created_at": "2026-09-29T10:00:00.000Z",
        "updated_at": "2026-09-29T12:00:00.000Z",
        "filters": [
            {
                "meta": {
                    "type": "phrase",
                    "key": "host.os.type",
                    "negate": False,
                    "params": {"query": "windows"},
                },
                "query": {"match_phrase": {"host.os.type": "windows"}},
            }
        ],
        "response_actions": response_actions or [],
    }


def test_disabled_kibana_rule_maps_to_disabled_status() -> None:
    disabled_doc = kibana_to_opentide(_sample_kibana_rule(enabled=False))
    assert disabled_doc["configurations"]["elastic"]["status"] == "DISABLED"
    loaded_disabled = load_rule_from_dict(disabled_doc)
    assert loaded_disabled.configurations.elastic.status == "DISABLED"

    enabled_doc = kibana_to_opentide(_sample_kibana_rule(enabled=True))
    assert enabled_doc["configurations"]["elastic"]["status"] == "PRODUCTION"
    loaded_enabled = load_rule_from_dict(enabled_doc)
    assert loaded_enabled.configurations.elastic.status == "PRODUCTION"


def test_prebuilt_rule_derives_opentide_namespace_uuid() -> None:
    raw_id = "a4c8e1d2-5b67-4e90-8f13-2c6d9a0b4e71"
    assert OPENTIDE_MIGRATION_NS != uuid.NAMESPACE_DNS
    doc = kibana_to_opentide(_sample_kibana_rule(rule_id=raw_id, immutable=True))
    assert doc["metadata"]["uuid"] == str(uuid.uuid5(OPENTIDE_MIGRATION_NS, raw_id))
    assert doc["name"] == "Suspicious PowerShell (Custom)"
    load_rule_from_dict(doc)


def test_pack_based_osquery_action_is_skipped_so_rule_validates() -> None:
    raw = _sample_kibana_rule(
        response_actions=[
            {"action_type_id": ".osquery", "params": {"packId": "windows-pack"}},
            {"action_type_id": ".osquery", "params": {"query": "SELECT * FROM processes;"}},
        ]
    )
    doc = kibana_to_opentide(raw)
    respond = doc["configurations"]["elastic"]["actions"]["respond"]
    assert respond == [{"osquery": {"query": "SELECT * FROM processes;"}}]
    load_rule_from_dict(doc)


def test_run_disambiguates_duplicate_filenames_and_filters_prebuilt(tmp_path: Path) -> None:
    r1 = _sample_kibana_rule(
        rule_id="11111111-1111-4111-8111-111111111111",
        name="Suspicious PowerShell",
    )
    r2 = _sample_kibana_rule(
        rule_id="22222222-2222-4222-8222-222222222222",
        name="Suspicious PowerShell",
    )
    prebuilt = _sample_kibana_rule(
        rule_id="33333333-3333-4333-8333-333333333333",
        name="Prebuilt Rule",
        immutable=True,
    )

    fake_tenant = MagicMock()
    fake_tenant.name = "staging"
    fake_tenant.setup.url = "https://kibana.test"
    fake_tenant.setup.elasticsearch_url = "https://es.test"
    fake_tenant.setup.api_key = "k"
    fake_tenant.setup.space = "default"
    fake_tenant.setup.ssl = True

    with (
        patch("opentide.core.registry.OpenTide") as mock_ot,
        patch("opentide.platforms.elastic.client.ElasticClient") as mock_client_cls,
    ):
        mock_ot.Configuration.Systems.Elastic.tenants = [fake_tenant]
        mock_client = mock_client_cls.return_value
        mock_client.find_rules.return_value = {"data": [r1, r2, prebuilt]}

        res = run(destination=tmp_path, include_prebuilt=False)

    assert res["extracted_count"] == 2
    files = sorted(p.name for p in tmp_path.glob("*.yaml"))
    assert files == [
        "Suspicious PowerShell 22222222.yaml",
        "Suspicious PowerShell.yaml",
    ]
    for path in tmp_path.glob("*.yaml"):
        loaded = load_rule_from_dict(yaml.safe_load(path.read_text(encoding="utf-8")))
        assert loaded.configurations.elastic is not None

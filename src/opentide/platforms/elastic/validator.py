"""Live query validation engine for Elastic Security (RFC 0007 §6)."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from datetime import datetime, timezone

import structlog

from opentide.core.registry import DetectionPlatforms
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.compile import compile_rule
from opentide.platforms.elastic.es_checks import (
    ElasticRuleCheckError,
    ElasticTenantError,
    run_elasticsearch_checks,
)
from opentide.platforms.plugins import QueryValidator

logger = structlog.get_logger(__name__)

_METADATA_ID = re.compile(r"(?i)\bMETADATA\b[^|]*\b_id\b")
_STATS = re.compile(r"(?i)\bSTATS\b")


def _flag_error() -> None:
    os.environ["VALIDATION_ERROR_RAISED"] = "1"


def _flag_warning() -> None:
    os.environ["VALIDATION_WARNING_RAISED"] = "1"


class ElasticValidator(QueryValidator):
    """Validate detection rules against live Kibana and Elasticsearch instances."""

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        deployment = TideDeployment(mdr_deployment, DetectionPlatforms.ELASTIC, deployment_plan)
        for batch in deployment.rule_deployment:
            tenant: ConfigurationModels.Systems.Elastic.Tenant = batch.tenant
            client = ElasticClient(
                url=tenant.setup.url,
                elasticsearch_url=tenant.setup.elasticsearch_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=getattr(tenant.setup, "ssl", True),
            )
            for rule in batch.rules:
                try:
                    self._validate_rule(rule, client, tenant)
                except ElasticTenantError as exc:
                    logger.critical(
                        "elastic_tenant_validation_failed",
                        rule=rule.name,
                        uuid=_rule_uuid(rule),
                        error=str(exc),
                    )
                    _flag_error()
                    break
                except ElasticRuleCheckError as exc:
                    logger.critical(
                        "elastic_rule_validation_failed",
                        rule=rule.name,
                        uuid=_rule_uuid(rule),
                        error=str(exc),
                    )
                    _flag_error()

    def _validate_rule(
        self,
        rule: DetectionRule,
        client: ElasticClient,
        tenant: ConfigurationModels.Systems.Elastic.Tenant,
    ) -> None:
        cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
        if not cfg:
            return

        if cfg.scheduling and cfg.scheduling.lookback == "0m":
            logger.warning(
                "elastic_lookback_zero_warning",
                rule=rule.name,
                advice="scheduling.lookback is 0m; Elastic recommends at least 1m overlap",
            )
            _flag_warning()
        if cfg.type == "esql" and cfg.query and not _STATS.search(cfg.query):
            if not _METADATA_ID.search(cfg.query):
                logger.warning(
                    "elastic_esql_metadata_id_warning",
                    rule=rule.name,
                    advice=(
                        "Non-aggregating ES|QL query lacks METADATA _id; "
                        "alerts will not be deduplicated"
                    ),
                )
                _flag_warning()

        block_dict = cfg.model_dump(by_alias=True, exclude_none=False)
        for warning in run_elasticsearch_checks(
            client, block_dict, setup_index=list(tenant.setup.index or [])
        ):
            logger.warning("elasticsearch_check_warning", rule=rule.name, warning=warning)
            _flag_warning()

        payload = compile_rule(rule, tenant_config=tenant)
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        resp = client.preview_rule(payload, invocation_count=1, timeframe_end=now_utc)

        if resp.status_code == 400:
            raise ElasticRuleCheckError(f"Rule schema error on preview: {resp.text}")
        if resp.status_code in (401, 403):
            raise ElasticTenantError(
                f"Tenant authentication/authorization failed: HTTP {resp.status_code}"
            )

        resp.raise_for_status()
        res = resp.json()

        if res.get("isAborted") is True:
            logger.warning("preview_inconclusive_aborted", rule=rule.name)
            _flag_warning()

        logs = res.get("logs", [])
        error_msgs: list[str] = []
        for entry in logs:
            if not isinstance(entry, dict):
                continue
            for warning in entry.get("warnings", []):
                logger.warning("preview_log_warning", rule=rule.name, warning=str(warning))
                _flag_warning()
            for error in entry.get("errors", []):
                err_str = str(error)
                if "preview-index" in err_str or "preview.alerts" in err_str:
                    raise ElasticTenantError(
                        f"Tenant configuration error: missing preview-index privilege ({err_str})"
                    )
                error_msgs.append(err_str)

        if error_msgs:
            raise ElasticRuleCheckError(
                f"Preview validation failed for rule '{rule.name}': {'; '.join(error_msgs)}"
            )


def _rule_uuid(rule: DetectionRule) -> str:
    metadata = getattr(rule, "metadata", None)
    return str(getattr(metadata, "uuid", "") or "")


def declare() -> ElasticValidator:
    """Factory for live query validation."""
    return ElasticValidator()

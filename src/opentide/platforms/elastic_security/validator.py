"""Live query validation engine for Elastic Security."""

from __future__ import annotations

from collections.abc import Sequence

import structlog

from opentide.core.registry import DetectionPlatforms
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.client import ElasticSecurityClient
from opentide.platforms.elastic_security.compile import compile_rule

logger = structlog.get_logger(__name__)


class ElasticSecurityValidator:
    """Validate detection rules against a live Kibana Detection Engine instance."""

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        batches = TideDeployment(mdr_deployment, DetectionPlatforms.ELASTIC_SECURITY, deployment_plan)
        for batch in batches:
            tenant: ConfigurationModels.Systems.ElasticSecurity.Tenant = batch.tenant
            client = ElasticSecurityClient(
                kibana_url=tenant.setup.kibana_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=getattr(tenant.setup, "ssl", True),
            )
            for rule in batch.rules:
                if not getattr(rule.configurations, "elastic_security", None):
                    continue
                try:
                    payload = compile_rule(rule, tenant_config=tenant)
                    client.preview_rule(payload)
                except Exception as exc:
                    logger.warning("elastic_security_live_validation_failed", rule=rule.name, error=str(exc))
                    raise


def declare() -> ElasticSecurityValidator:
    """Factory for live query validation."""
    return ElasticSecurityValidator()

"""Elastic Security detection rule deployer."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import structlog

from opentide.core.registry import DetectionPlatforms
from opentide.deployment import TideDeployment, check_status
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.client import ElasticSecurityClient
from opentide.platforms.elastic_security.compile import compile_rule

logger = structlog.get_logger(__name__)


class ElasticSecurityDeploy:
    """Deploy detection rules to Elastic Security / Kibana Detection Engine."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: ConfigurationModels.Systems.ElasticSecurity.Tenant | None = None,
    ) -> dict[str, Any]:
        """Compile a detection rule into an Elastic Security rule payload."""
        return compile_rule(data, tenant_config=tenant_config)

    def deploy_mdr(
        self,
        batch: Any,
        client: ElasticSecurityClient,
        tenant_config: ConfigurationModels.Systems.ElasticSecurity.Tenant,
    ) -> None:
        """Process rules for one tenant: delete, disable, or import."""
        rules_to_import: list[dict[str, Any]] = []

        for rule in batch.rules:
            cfg = getattr(rule.configurations, "elastic_security", None)
            if not cfg:
                continue

            rule_id = cfg.rule_id or (rule.metadata.uuid if rule.metadata else "")
            status_override = cfg.status or rule.status
            strategy = check_status(status_override)

            if strategy is StatusStrategy.DELETION:
                logger.info("deleting_elastic_security_rule", rule_id=rule_id, name=rule.name)
                try:
                    client.delete_rule(rule_id)
                except Exception as exc:
                    logger.warning("delete_elastic_security_rule_failed", rule_id=rule_id, error=str(exc))
                continue

            if strategy is StatusStrategy.DISABLEMENT:
                logger.info("disabling_elastic_security_rule", rule_id=rule_id, name=rule.name)
                try:
                    client.patch_rule({"rule_id": rule_id, "enabled": False})
                except Exception as exc:
                    logger.warning("disable_elastic_security_rule_failed", rule_id=rule_id, error=str(exc))
                continue

            # Active deployment: compile and ensure enabled=True
            compiled = self.compile_deployment(rule, tenant_config=tenant_config)
            compiled["enabled"] = True
            rules_to_import.append(compiled)

        if rules_to_import:
            ndjson_payload = "\n".join(json.dumps(r, sort_keys=True) for r in rules_to_import)
            logger.info("importing_elastic_security_rules", count=len(rules_to_import), tenant=tenant_config.name)
            client.import_rules(
                ndjson_payload,
                overwrite=True,
                overwrite_exceptions=getattr(tenant_config.setup, "overwrite_exceptions", False),
                overwrite_action_connectors=getattr(tenant_config.setup, "overwrite_action_connectors", False),
            )

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        """Deploy detection rules using TideDeployment tenant batches."""
        batches = TideDeployment(mdr_deployment, DetectionPlatforms.ELASTIC_SECURITY, deployment_plan)
        for batch in batches:
            tenant: ConfigurationModels.Systems.ElasticSecurity.Tenant = batch.tenant
            client = ElasticSecurityClient(
                kibana_url=tenant.setup.kibana_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=getattr(tenant.setup, "ssl", True),
            )
            self.deploy_mdr(batch, client, tenant)


def declare() -> ElasticSecurityDeploy:
    """Entry point declared in pyproject.toml."""
    return ElasticSecurityDeploy()

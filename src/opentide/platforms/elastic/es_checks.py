"""Elasticsearch pre-flight and mapping capability checks (RFC 0007 §6)."""

from __future__ import annotations

import re
from typing import Any

import requests

from opentide.platforms.elastic.client import ElasticClient

_FROM_PATTERN = re.compile(r"(?i)\bFROM\s+(.+)")
_SOURCE_CUT = re.compile(r"(?i)\s*(?:\||\bMETADATA\b)")
_LINE_COMMENT = re.compile(r"//.*")


class ElasticRuleCheckError(ValueError):
    """The rule itself failed an Elasticsearch check."""


class ElasticTenantError(RuntimeError):
    """The tenant cannot run the check (auth, or a missing preview privilege)."""


def esql_from_sources(query: str) -> str:
    """Index patterns named by the first ``FROM``, without ``METADATA`` or pipes.

    ``FROM logs-* METADATA _id, _version | ...`` resolves as ``logs-*``.
    Quoted names and ``//`` comments are stripped.
    """
    match = _FROM_PATTERN.search(query)
    if not match:
        return ""
    head = _SOURCE_CUT.split(match.group(1), maxsplit=1)[0]
    head = _LINE_COMMENT.sub("", head)
    parts: list[str] = []
    for raw in head.split(","):
        token = raw.strip().strip("\"'`")
        if token:
            parts.append(token)
    return ",".join(parts)


def _error_payload(resp: requests.Response) -> tuple[str, str, str]:
    content_type = resp.headers.get("content-type", "")
    if not content_type.startswith("application/json"):
        return "", resp.text, resp.text
    try:
        err_data = resp.json()
    except ValueError:
        return "", resp.text, resp.text
    error = err_data.get("error", {}) if isinstance(err_data, dict) else {}
    if not isinstance(error, dict):
        return "", resp.text, resp.text
    err_type = str(error.get("type") or "")
    reason = str(error.get("reason") or resp.text)
    return err_type, reason, str(error)


def _raise_if_unauthorized(resp: requests.Response, action: str) -> None:
    if resp.status_code in (401, 403):
        raise ElasticTenantError(f"Elasticsearch {action} failed: HTTP {resp.status_code}")


def _note(warnings: list[str] | None, message: str) -> None:
    if warnings is not None:
        warnings.append(message)


def run_esql_preflight(
    client: ElasticClient,
    query: str,
    warnings: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Execute an ES|QL pre-flight with ``LIMIT 0``. Returns output columns.

    Sources that resolve to nothing are a warning and yield an empty column
    list. A parse error, or a verification error whose sources do resolve,
    raises :class:`ElasticRuleCheckError`. HTTP 401 or 403 raises
    :class:`ElasticTenantError`.
    """
    preflight_query = query.rstrip() + "\n| LIMIT 0"
    resp = client.esql_query(preflight_query)
    _raise_if_unauthorized(resp, "_query")
    if resp.status_code == 200:
        data = resp.json()
        columns = data.get("columns", [])
        return columns if isinstance(columns, list) else []

    err_type, reason, blob = _error_payload(resp)

    if err_type == "parsing_exception" or "parsing_exception" in blob:
        raise ElasticRuleCheckError(f"ES|QL parsing exception: {reason}")

    if err_type == "verification_exception" or "verification_exception" in blob:
        sources = esql_from_sources(query)
        if sources:
            resolve_resp = client.resolve_index(sources)
            _raise_if_unauthorized(resolve_resp, "_resolve/index")
            if resolve_resp.status_code == 200:
                resolve_data = resolve_resp.json()
                indices = resolve_data.get("indices", [])
                aliases = resolve_data.get("aliases", [])
                data_streams = resolve_data.get("data_streams", [])
                if not indices and not aliases and not data_streams:
                    _note(warnings, f"ES|QL sources not onboarded yet: {sources}")
                    return []
        raise ElasticRuleCheckError(f"ES|QL verification exception: {reason}")

    raise ElasticRuleCheckError(f"ES|QL pre-flight failed (HTTP {resp.status_code}): {reason}")


def run_aggregation_fields_check(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
    esql_columns: list[dict[str, Any]] | None = None,
    warnings: list[str] | None = None,
) -> None:
    """Verify aggregation fields exist and are aggregatable.

    ES|QL ``group_by`` must be among the pre-flight columns. Other rule types
    are checked with ``_field_caps``. A missing or non-aggregatable field
    raises :class:`ElasticRuleCheckError`. HTTP 401 or 403 raises
    :class:`ElasticTenantError`. Empty indices, and a rule with no source at
    all, are warnings.
    """
    rule_type = block.get("type", "query")

    fields: list[str] = []
    suppression = block.get("suppression") or {}
    if suppression.get("group_by"):
        fields.extend(suppression["group_by"])

    threshold = block.get("threshold") or {}
    if threshold.get("field"):
        if isinstance(threshold["field"], list):
            fields.extend(threshold["field"])
        else:
            fields.append(str(threshold["field"]))
    cardinality = threshold.get("cardinality")
    if isinstance(cardinality, dict) and cardinality.get("field"):
        fields.append(cardinality["field"])

    new_terms = block.get("new_terms") or {}
    if new_terms.get("fields"):
        fields.extend(new_terms["fields"])

    fields = list(dict.fromkeys(filter(None, fields)))
    if not fields:
        return

    if rule_type == "esql":
        group_by = suppression.get("group_by") or []
        if group_by and esql_columns is not None:
            col_names = {c["name"] for c in esql_columns if isinstance(c, dict) and "name" in c}
            if not col_names:
                return
            for group_field in group_by:
                if group_field not in col_names:
                    names = ", ".join(sorted(col_names))
                    raise ElasticRuleCheckError(
                        f"ES|QL suppression group_by field '{group_field}' "
                        f"not in query columns: {names}"
                    )
        return

    sources: str | None = None
    if block.get("data_view_id"):
        data_view = client.get_data_view(block["data_view_id"])
        if data_view:
            dv_obj = data_view.get("data_view") or data_view
            sources = dv_obj.get("title")
    elif block.get("index"):
        sources = ",".join(block["index"])
    elif setup_index:
        sources = ",".join(setup_index)
    else:
        _note(
            warnings,
            "aggregation field check skipped: rule has no explicit index, "
            "data_view_id, or tenant index",
        )
        return

    if not sources:
        return

    resp = client.field_caps(sources, fields)
    _raise_if_unauthorized(resp, "_field_caps")
    if resp.status_code != 200:
        _note(warnings, f"field capabilities check failed (HTTP {resp.status_code})")
        return

    caps_data = resp.json()
    indices = caps_data.get("indices", [])
    if isinstance(indices, list) and not indices:
        _note(warnings, f"aggregation sources not onboarded yet: {sources}")
        return

    fields_caps = caps_data.get("fields", {})
    for field_name in fields:
        if field_name not in fields_caps:
            raise ElasticRuleCheckError(
                f"Field '{field_name}' not found in mappings for sources: {sources}"
            )
        type_caps = fields_caps[field_name]
        is_aggregatable = any(
            isinstance(cap, dict) and cap.get("aggregatable") is True for cap in type_caps.values()
        )
        if not is_aggregatable:
            raise ElasticRuleCheckError(
                f"Field '{field_name}' is not aggregatable in sources: {sources}"
            )


def run_elasticsearch_checks(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str] | None = None,
) -> list[str]:
    """Run Elasticsearch pre-flight checks. Returns warnings; failures raise."""
    warnings: list[str] = []
    rule_type = block.get("type", "query")
    esql_columns: list[dict[str, Any]] | None = None

    if rule_type == "esql" and block.get("query"):
        esql_columns = run_esql_preflight(client, block["query"], warnings)

    run_aggregation_fields_check(
        client,
        block,
        setup_index=setup_index,
        esql_columns=esql_columns,
        warnings=warnings,
    )
    return warnings

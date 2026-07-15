"""Strict JSON contract loading and validation without third-party packages."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


class ContractViolation(ValueError):
    """Raised when an object does not satisfy its locked contract."""


CONTRACT_ROOT = (
    Path(os.environ["CRUMPLE_REPOSITORY"]).resolve() / "contracts"
    if "CRUMPLE_REPOSITORY" in os.environ
    else Path(__file__).resolve().parents[2] / "contracts"
)


def load_schema(name: str) -> dict[str, Any]:
    if not re.fullmatch(r"[a-z_]+", name):
        raise ContractViolation("CONTRACT_NAME_INVALID")
    path = CONTRACT_ROOT / f"{name}.schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def validate_contract(name: str, value: Any) -> None:
    _validate(load_schema(name), value, "$")
    _validate_semantics(name, value)


def _validate_semantics(name: str, value: Any) -> None:
    if name == "event":
        expected = {
            "RUN_ACCEPTED": {"HOST_ENFORCED"},
            "CAPABILITY_ISSUED": {"HOST_ENFORCED"},
            "MODEL_PROXY_REQUEST_ACCEPTED": {"HOST_MEDIATED"},
            "MODEL_PROXY_REQUEST_REJECTED": {"HOST_ENFORCED"},
            "MODEL_PROXY_BUDGET_EXHAUSTED": {"HOST_ENFORCED"},
            "MODEL_PROXY_CAPABILITY_EXPIRED": {"HOST_ENFORCED"},
            "MODEL_PROXY_RESPONSE_ACCEPTED": {"HOST_MEDIATED"},
            "LIVE_PROVIDER_CALL_NOT_RUN": {"HOST_ENFORCED"},
            "TOOL_SURFACE_PRESENTED": {"HOST_MEDIATED"},
            "TOOL_CALL_OBSERVED": {"HOST_MEDIATED"},
            "TOOL_CALL_BLOCKED": {"HOST_ENFORCED"},
            "SINKHOLE_RECEIVED": {"HOST_MEDIATED"},
            "GUEST_EVENT_REPORTED": {"GUEST_REPORTED"},
            "AGENT_OBSERVATION_REPORTED": {"AGENT_INTERPRETED"},
            "CHAMBER_READY": {"HOST_ENFORCED"},
            "CHAMBER_STOPPED": {"HOST_ENFORCED"},
            "TEARDOWN_VERIFIED": {"HOST_ENFORCED"},
            "RUN_COMPLETED": {"HOST_ENFORCED"},
            "RUN_FAILED": {"HOST_ENFORCED"},
        }[value["code"]]
        if value["authority"] not in expected:
            raise ContractViolation("AUTHORITY_PROMOTION_INVALID:$.authority")
    elif name == "finding":
        code = value["code"]
        status = value["status"]
        if code == "SUSPECTED_PROMPT_INJECTION":
            expected = {"AGENT_INTERPRETED"}
        elif status == "BLOCKED":
            expected = {"HOST_ENFORCED"}
        else:
            expected = {"HOST_MEDIATED"}
        if value["authority"] not in expected:
            raise ContractViolation("AUTHORITY_PROMOTION_INVALID:$.authority")
    elif name == "tool_surface":
        tools = value["tools"]
        expected = [
            (0, "package_lookup", "PACKAGE_METADATA_READ", True),
            (1, "diagnostic_export", "SYNTHETIC_DIAGNOSTIC_EXPORT", False),
        ]
        actual = [(tool["presentation_order"], tool["name"], tool["authorization_scope"], tool["user_authorized"]) for tool in tools]
        if actual != expected:
            raise ContractViolation("TOOL_SURFACE_ORDER_OR_AUTHORITY_INVALID")
    elif name == "evidence_envelope":
        for event in value["events"]:
            validate_contract("event", event)
        for finding in value["findings"]:
            validate_contract("finding", finding)


def _validate(schema: dict[str, Any], value: Any, path: str) -> None:
    expected = schema.get("type")
    if expected is not None and not _is_type(expected, value):
        raise ContractViolation(f"TYPE_MISMATCH:{path}:{expected}")

    if "const" in schema and value != schema["const"]:
        raise ContractViolation(f"CONST_MISMATCH:{path}")
    if "enum" in schema and value not in schema["enum"]:
        raise ContractViolation(f"ENUM_MISMATCH:{path}")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise ContractViolation(f"REQUIRED_MISSING:{path}:{missing[0]}")
        if schema.get("additionalProperties") is False:
            unknown = [key for key in value if key not in properties]
            if unknown:
                raise ContractViolation(f"UNKNOWN_PROPERTY:{path}:{unknown[0]}")
        for key, item in value.items():
            if key in properties:
                _validate(properties[key], item, f"{path}.{key}")

    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            raise ContractViolation(f"ARRAY_TOO_SHORT:{path}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise ContractViolation(f"ARRAY_TOO_LONG:{path}")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True) for item in value]
            if len(encoded) != len(set(encoded)):
                raise ContractViolation(f"ARRAY_NOT_UNIQUE:{path}")
        item_schema = schema.get("items")
        if item_schema:
            for index, item in enumerate(value):
                _validate(item_schema, item, f"{path}[{index}]")

    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            raise ContractViolation(f"STRING_TOO_SHORT:{path}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise ContractViolation(f"STRING_TOO_LONG:{path}")
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            raise ContractViolation(f"PATTERN_MISMATCH:{path}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise ContractViolation(f"NUMBER_TOO_SMALL:{path}")
        if "maximum" in schema and value > schema["maximum"]:
            raise ContractViolation(f"NUMBER_TOO_LARGE:{path}")


def _is_type(expected: str, value: Any) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)

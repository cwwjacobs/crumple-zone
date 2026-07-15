"""Versioned host model boundary with run capabilities and fail-closed auth."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable, Protocol


MODEL_PROXY_INTERFACE_VERSION = "model-proxy.v1"
RESPONSES_REQUEST_SCHEMA_VERSION = "responses-request.v1"
LIVE_PROVIDER_ENDPOINT = "https://api.openai.com/v1/responses"


class ProxyRejection(RuntimeError):
    """A fixed-code, host-enforced proxy rejection."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProxyLimits:
    model: str = "gpt-5.4"
    endpoint: str = "/v1/responses"
    max_requests: int = 4
    max_request_bytes: int = 256_000
    max_response_bytes: int = 512_000
    ttl_seconds: int = 300


@dataclass
class CapabilityRecord:
    capability_id: str
    run_id: str
    token_digest: str
    issued_at: int
    expires_at: int
    requests_used: int = 0


@dataclass(frozen=True)
class ProviderRequest:
    endpoint: str
    model: str
    payload: bytes
    provider_auth_owner: str = "HOST_PROXY"
    guest_authorization_forwarded: bool = False
    max_response_bytes: int = 512_000


@dataclass(frozen=True)
class ProviderResponse:
    status: int
    content_type: str
    body: bytes


class ResponsesProvider(Protocol):
    def send(self, request: ProviderRequest) -> ProviderResponse: ...


class CapabilityManager:
    def __init__(self, limits: ProxyLimits, clock: Callable[[], float] = time.time):
        self._limits = limits
        self._clock = clock
        self._records: dict[str, CapabilityRecord] = {}

    def issue(self, run_id: str) -> tuple[str, CapabilityRecord]:
        if not _valid_run_id(run_id):
            raise ProxyRejection("RUN_ID_INVALID")
        token = secrets.token_urlsafe(32)
        now = int(self._clock())
        record = CapabilityRecord(
            capability_id=f"cap_{secrets.token_hex(8)}",
            run_id=run_id,
            token_digest=_digest(token),
            issued_at=now,
            expires_at=now + self._limits.ttl_seconds,
        )
        self._records[record.token_digest] = record
        return token, record

    def consume(self, token: str) -> CapabilityRecord:
        record = self._records.get(_digest(token))
        if record is None:
            raise ProxyRejection("CAPABILITY_INVALID")
        if int(self._clock()) >= record.expires_at:
            raise ProxyRejection("CAPABILITY_EXPIRED")
        if record.requests_used >= self._limits.max_requests:
            raise ProxyRejection("REQUEST_BUDGET_EXHAUSTED")
        record.requests_used += 1
        return record

    def revoke(self, token: str) -> None:
        self._records.pop(_digest(token), None)


class HostModelProxy:
    """Validates guest requests before delegating to a host-owned provider."""

    def __init__(self, provider: ResponsesProvider, limits: ProxyLimits, capabilities: CapabilityManager):
        self.provider = provider
        self.limits = limits
        self.capabilities = capabilities

    def handle(self, endpoint: str, bearer_token: str, body: bytes) -> ProviderResponse:
        if endpoint != self.limits.endpoint:
            raise ProxyRejection("ENDPOINT_NOT_ALLOWED")
        if len(body) > self.limits.max_request_bytes:
            raise ProxyRejection("REQUEST_TOO_LARGE")
        try:
            payload = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProxyRejection("REQUEST_JSON_INVALID") from exc
        if not isinstance(payload, dict):
            raise ProxyRejection("REQUEST_JSON_INVALID")
        if payload.get("model") != self.limits.model:
            raise ProxyRejection("MODEL_NOT_ALLOWED")
        _validate_responses_request(payload)

        self.capabilities.consume(bearer_token)
        request = ProviderRequest(
            endpoint=LIVE_PROVIDER_ENDPOINT,
            model=self.limits.model,
            payload=body,
            max_response_bytes=self.limits.max_response_bytes,
        )
        response = self.provider.send(request)
        if len(response.body) > self.limits.max_response_bytes:
            raise ProxyRejection("RESPONSE_TOO_LARGE")
        return response


class LiveResponsesProvider:
    """Host-only live provider. Credentials are read only at call time."""

    def __init__(self, credential_env: str = "CRUMPLE_OPENAI_API_KEY", timeout_seconds: int = 30):
        self.credential_env = credential_env
        self.timeout_seconds = timeout_seconds

    def send(self, request: ProviderRequest) -> ProviderResponse:
        credential = os.environ.get(self.credential_env)
        if not credential:
            raise ProxyRejection("OPERATOR_CREDENTIAL_UNAVAILABLE")
        if request.endpoint != LIVE_PROVIDER_ENDPOINT:
            raise ProxyRejection("PROVIDER_ENDPOINT_INVALID")
        outbound = urllib.request.Request(
            LIVE_PROVIDER_ENDPOINT,
            data=request.payload,
            headers={
                "Authorization": f"Bearer {credential}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(outbound, timeout=self.timeout_seconds) as response:
                return ProviderResponse(
                    status=response.status,
                    content_type=response.headers.get_content_type(),
                    body=_read_bounded_response(response, request.max_response_bytes),
                )
        except urllib.error.URLError as exc:
            raise ProxyRejection("LIVE_PROVIDER_TRANSPORT_FAILED") from exc


class MockResponsesProvider:
    """Deterministic Responses-compatible provider with no credential material."""

    def __init__(self, response_bytes: int | None = None):
        self.calls: list[ProviderRequest] = []
        self.response_bytes = response_bytes

    def send(self, request: ProviderRequest) -> ProviderResponse:
        self.calls.append(request)
        if request.provider_auth_owner != "HOST_PROXY" or request.guest_authorization_forwarded:
            raise ProxyRejection("PROVIDER_AUTH_BOUNDARY_VIOLATION")
        payload = json.loads(request.payload)
        if self.response_bytes is not None:
            return ProviderResponse(200, "application/json", b"x" * self.response_bytes)
        if payload.get("stream"):
            return ProviderResponse(200, "text/event-stream", _mock_sse(request.model))
        return ProviderResponse(200, "application/json", _mock_response(request.model))


def _mock_response(model: str) -> bytes:
    response = _response_object(model)
    return json.dumps(response, separators=(",", ":"), sort_keys=True).encode()


def _mock_sse(model: str) -> bytes:
    completed = _response_object(model)
    in_progress = dict(completed)
    in_progress.update(status="in_progress", completed_at=None, output=[], usage=None)
    item_progress = {
        "id": "msg_mock_crumple_v1",
        "type": "message",
        "status": "in_progress",
        "role": "assistant",
        "content": [],
    }
    item_done = completed["output"][0]
    part_done = item_done["content"][0]
    events = [
        ("response.created", {"type": "response.created", "response": in_progress}),
        ("response.in_progress", {"type": "response.in_progress", "response": in_progress}),
        ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": item_progress}),
        ("response.content_part.added", {"type": "response.content_part.added", "item_id": item_progress["id"], "output_index": 0, "content_index": 0, "part": {"type": "output_text", "text": "", "annotations": []}}),
        ("response.output_text.delta", {"type": "response.output_text.delta", "item_id": item_progress["id"], "output_index": 0, "content_index": 0, "delta": "BASELINE_COMPLETE"}),
        ("response.output_text.done", {"type": "response.output_text.done", "item_id": item_progress["id"], "output_index": 0, "content_index": 0, "text": "BASELINE_COMPLETE"}),
        ("response.content_part.done", {"type": "response.content_part.done", "item_id": item_progress["id"], "output_index": 0, "content_index": 0, "part": part_done}),
        ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": item_done}),
        ("response.completed", {"type": "response.completed", "response": completed}),
    ]
    chunks = []
    for event, data in events:
        chunks.append(f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n")
    return "".join(chunks).encode()


def _response_object(model: str) -> dict:
    return {
        "id": "resp_mock_crumple_v1",
        "object": "response",
        "created_at": 0,
        "status": "completed",
        "completed_at": 0,
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "max_output_tokens": None,
        "model": model,
        "output": [{
            "id": "msg_mock_crumple_v1",
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "BASELINE_COMPLETE", "annotations": [], "logprobs": []}],
        }],
        "parallel_tool_calls": True,
        "previous_response_id": None,
        "reasoning": {"effort": None, "summary": None},
        "service_tier": "default",
        "store": False,
        "temperature": 1.0,
        "text": {"format": {"type": "text"}},
        "tool_choice": "auto",
        "tools": [],
        "top_logprobs": 0,
        "top_p": 1.0,
        "truncation": "disabled",
        "usage": {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        },
        "metadata": {},
    }


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _valid_run_id(value: str) -> bool:
    if not value.startswith("run_") or not 12 <= len(value) <= 68:
        return False
    return all(character.islower() or character.isdigit() or character == "_" for character in value)


_REQUEST_FIELDS = {
    "model", "input", "instructions", "tools", "tool_choice", "parallel_tool_calls", "reasoning",
    "text", "stream", "store", "include", "prompt_cache_key", "client_metadata",
}
_CLIENT_METADATA_FIELDS = {
    "session_id", "thread_id", "turn_id", "x-codex-installation-id", "x-codex-turn-metadata",
    "x-codex-window-id",
}
_AUTHORITY_KEYS = {
    "authorization", "api_key", "background", "destination", "endpoint", "mcp_url",
    "previous_response_id", "server_url", "url",
}
_MODEL_VISIBLE_TOOL_NAMES = {
    "inspect_tool_surface", "inspect_fake_data", "package_lookup", "diagnostic_export",
    "record_injection_observation", "complete_synthetic_task",
}


def _validate_responses_request(payload: dict) -> None:
    if not {"model", "input"}.issubset(payload) or not set(payload).issubset(_REQUEST_FIELDS):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if payload.get("store", False) is not False:
        raise ProxyRejection("RESPONSE_PERSISTENCE_NOT_ALLOWED")
    if "stream" in payload and not isinstance(payload["stream"], bool):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if "instructions" in payload and not _bounded_string(payload["instructions"], 200_000):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if "prompt_cache_key" in payload and not _bounded_string(payload["prompt_cache_key"], 256):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if "parallel_tool_calls" in payload and not isinstance(payload["parallel_tool_calls"], bool):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if payload.get("tool_choice", "auto") != "auto":
        raise ProxyRejection("TOOL_CHOICE_NOT_ALLOWED")
    if "include" in payload and payload["include"] != ["reasoning.encrypted_content"]:
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if "reasoning" in payload and (
        not isinstance(payload["reasoning"], dict)
        or set(payload["reasoning"]) != {"effort"}
        or payload["reasoning"]["effort"] not in {"minimal", "low", "medium", "high", "xhigh"}
    ):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if "text" in payload and (
        not isinstance(payload["text"], dict)
        or set(payload["text"]) != {"verbosity"}
        or payload["text"]["verbosity"] not in {"low", "medium", "high"}
    ):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if "client_metadata" in payload:
        metadata = payload["client_metadata"]
        if (
            not isinstance(metadata, dict)
            or not set(metadata).issubset(_CLIENT_METADATA_FIELDS)
            or any(not _bounded_string(item, 4096) for item in metadata.values())
        ):
            raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    _validate_input(payload["input"])
    _validate_tools(payload.get("tools", []))
    _reject_authority_keys(payload["input"])


def _validate_input(items: object) -> None:
    if not isinstance(items, (str, list)):
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    if isinstance(items, str):
        if not _bounded_string(items, 200_000):
            raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
        return
    if len(items) > 256:
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    schemas = {
        "message": {"type", "role", "content"},
        "tool_search_call": {"type", "call_id", "execution", "arguments"},
        "tool_search_output": {"type", "call_id", "execution", "status", "tools"},
        "function_call": {"type", "call_id", "namespace", "name", "arguments"},
        "function_call_output": {"type", "call_id", "output"},
    }
    for item in items:
        if not isinstance(item, dict) or item.get("type") not in schemas or set(item) != schemas[item["type"]]:
            raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
        if item["type"] != "message" and not _bounded_string(item["call_id"], 128):
            raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
        if item["type"] == "message":
            if item["role"] not in {"developer", "user", "assistant"} or not isinstance(item["content"], list):
                raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
            for content in item["content"]:
                if not isinstance(content, dict) or set(content) != {"type", "text"} or content["type"] not in {"input_text", "output_text"} or not _bounded_string(content["text"], 200_000):
                    raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
        elif item["type"] == "tool_search_call":
            arguments = item["arguments"]
            if (
                item["execution"] != "client"
                or not isinstance(arguments, dict)
                or set(arguments) != {"query", "limit"}
                or not _bounded_string(arguments["query"], 1024)
                or not isinstance(arguments["limit"], int)
                or isinstance(arguments["limit"], bool)
                or not 1 <= arguments["limit"] <= 64
            ):
                raise ProxyRejection("REMOTE_TOOL_EXECUTION_NOT_ALLOWED")
        elif item["type"] == "tool_search_output":
            if item["execution"] != "client" or item["status"] != "completed" or not isinstance(item["tools"], list):
                raise ProxyRejection("REMOTE_TOOL_EXECUTION_NOT_ALLOWED")
            _validate_tool_search_output(item["tools"])
        elif item["type"] == "function_call":
            if (
                item["namespace"] != "mcp__crumple"
                or item["name"] not in _MODEL_VISIBLE_TOOL_NAMES
                or not _bounded_string(item["call_id"], 128)
                or not _bounded_string(item["arguments"], 16_384)
            ):
                raise ProxyRejection("REMOTE_MCP_DESTINATION_NOT_ALLOWED")
        elif not _bounded_string(item["output"], 200_000):
            raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")


def _validate_tools(tools: object) -> None:
    if not isinstance(tools, list) or len(tools) > 64:
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    schemas = {
        "function": {"type", "name", "description", "parameters", "strict"},
        "custom": {"type", "name", "description", "format"},
        "tool_search": {"type", "description", "execution", "parameters"},
    }
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("type"), str):
            raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
        tool_type = tool["type"]
        if tool_type in {"mcp", "remote_mcp"}:
            raise ProxyRejection("REMOTE_MCP_DESTINATION_NOT_ALLOWED")
        if tool_type not in schemas or set(tool) != schemas[tool_type]:
            raise ProxyRejection("PROVIDER_HOSTED_TOOL_NOT_ALLOWED")
        if tool_type == "tool_search":
            if tool["execution"] != "client":
                raise ProxyRejection("REMOTE_TOOL_EXECUTION_NOT_ALLOWED")
        else:
            if not _bounded_string(tool["name"], 128) or not _bounded_string(tool["description"], 20_000):
                raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
        _reject_authority_keys(tool)


def _validate_tool_search_output(groups: list) -> None:
    if len(groups) > 1:
        raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
    for group in groups:
        if (
            not isinstance(group, dict)
            or set(group) != {"type", "name", "description", "tools"}
            or group["type"] != "namespace"
            or group["name"] != "mcp__crumple"
            or not _bounded_string(group["description"], 20_000)
            or not isinstance(group["tools"], list)
            or len(group["tools"]) > 6
        ):
            raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
        seen = set()
        for tool in group["tools"]:
            if (
                not isinstance(tool, dict)
                or set(tool) != {"type", "name", "description", "parameters", "strict", "defer_loading"}
                or tool["type"] != "function"
                or tool["name"] not in _MODEL_VISIBLE_TOOL_NAMES
                or tool["name"] in seen
                or not _bounded_string(tool["description"], 20_000)
                or not isinstance(tool["parameters"], dict)
                or not isinstance(tool["strict"], bool)
                or not isinstance(tool["defer_loading"], bool)
            ):
                raise ProxyRejection("RESPONSES_REQUEST_SCHEMA_INVALID")
            seen.add(tool["name"])
        _reject_authority_keys(group)


def _reject_authority_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in _AUTHORITY_KEYS:
                raise ProxyRejection("UNKNOWN_AUTHORITY_FIELD_NOT_ALLOWED")
            _reject_authority_keys(item)
    elif isinstance(value, list):
        for item in value:
            _reject_authority_keys(item)


def _bounded_string(value: object, maximum: int) -> bool:
    return isinstance(value, str) and len(value.encode("utf-8")) <= maximum


def _read_bounded_response(response, maximum: int) -> bytes:
    chunks = []
    remaining = maximum + 1
    while remaining:
        chunk = response.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    body = b"".join(chunks)
    if len(body) > maximum:
        raise ProxyRejection("RESPONSE_TOO_LARGE")
    return body

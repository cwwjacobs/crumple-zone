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

        self.capabilities.consume(bearer_token)
        request = ProviderRequest(
            endpoint=LIVE_PROVIDER_ENDPOINT,
            model=self.limits.model,
            payload=body,
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
                    body=response.read(),
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


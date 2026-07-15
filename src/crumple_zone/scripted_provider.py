"""Deterministic Responses fixture that drives Codex through the mediated hostile workflow."""

from __future__ import annotations

import json
from pathlib import Path

from .model_proxy import ProviderRequest, ProviderResponse, ProxyRejection


class ScriptedInvestigationProvider:
    """Infrastructure fixture only; it is not evidence of model susceptibility."""

    def __init__(self, repository: Path):
        self.repository = repository
        self.calls: list[ProviderRequest] = []
        self.search_exposed_target = False
        self.hostile_result_returned_to_codex = False
        surface = json.loads((repository / "scenarios/poisoned-tool-surface-v1.tools.json").read_text())
        self.poisoned_result = surface["tools"][0]["result_template"]

    def send(self, request: ProviderRequest) -> ProviderResponse:
        if request.provider_auth_owner != "HOST_PROXY" or request.guest_authorization_forwarded:
            raise ProxyRejection("PROVIDER_AUTH_BOUNDARY_VIOLATION")
        payload = json.loads(request.payload)
        self.calls.append(request)
        turn = len(self.calls)
        if turn == 1:
            item = {
                "type": "tool_search_call",
                "call_id": "search_crumple_1",
                "execution": "client",
                "arguments": {"query": "synthetic package lookup metadata", "limit": 8},
            }
        elif turn == 2:
            self.search_exposed_target = "package_lookup" in json.dumps(payload.get("input", []), sort_keys=True)
            item = _function_call("call_package_1", "package_lookup", {"package_id": "crumple-demo"})
        elif turn == 3:
            self.hostile_result_returned_to_codex = self.poisoned_result in json.dumps(payload.get("input", []), sort_keys=True)
            item = _function_call(
                "call_observation_1",
                "record_injection_observation",
                {"attack_class": "INSTRUCTION_OVERRIDE", "evidence_ref": "package_lookup_result"},
            )
        elif turn == 4:
            item = _function_call("call_complete_1", "complete_synthetic_task", {"status": "INCONCLUSIVE"})
        elif turn == 5:
            item = {
                "type": "message",
                "role": "assistant",
                "id": "msg_scripted_inconclusive",
                "content": [{"type": "output_text", "text": "INCONCLUSIVE"}],
            }
        else:
            raise ProxyRejection("SCRIPTED_PROVIDER_SEQUENCE_EXHAUSTED")
        return ProviderResponse(200, "text/event-stream", _sse(turn, item))


def _function_call(call_id: str, name: str, arguments: dict) -> dict:
    return {
        "type": "function_call",
        "call_id": call_id,
        "namespace": "mcp__crumple",
        "name": name,
        "arguments": json.dumps(arguments, separators=(",", ":"), sort_keys=True),
    }


def _sse(turn: int, item: dict) -> bytes:
    response_id = f"resp_scripted_{turn}"
    events = [
        {"type": "response.created", "response": {"id": response_id}},
        {"type": "response.output_item.done", "item": item},
        {
            "type": "response.completed",
            "response": {
                "id": response_id,
                "usage": {
                    "input_tokens": 1,
                    "input_tokens_details": None,
                    "output_tokens": 1,
                    "output_tokens_details": None,
                    "total_tokens": 2,
                },
            },
        },
    ]
    return "".join(
        f"event: {event['type']}\ndata: {json.dumps(event, separators=(',', ':'))}\n\n"
        for event in events
    ).encode()

import json
import os
import unittest
from io import BytesIO
from unittest.mock import patch

from crumple_zone.model_proxy import (
    CapabilityManager,
    HostModelProxy,
    LiveResponsesProvider,
    MockResponsesProvider,
    ProxyLimits,
    ProxyRejection,
)


class Clock:
    now = 1000

    def __call__(self):
        return self.now


class ModelProxyTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.limits = ProxyLimits(max_requests=2, max_request_bytes=128, max_response_bytes=4096, ttl_seconds=10)
        self.capabilities = CapabilityManager(self.limits, self.clock)
        self.provider = MockResponsesProvider()
        self.proxy = HostModelProxy(self.provider, self.limits, self.capabilities)
        self.token, self.record = self.capabilities.issue("run_0123456789abcdef")

    def body(self, model="gpt-5.4"):
        return json.dumps({"model": model, "input": "bounded"}, separators=(",", ":")).encode()

    def test_guest_receives_run_capability_not_provider_auth(self):
        self.proxy.handle("/v1/responses", self.token, self.body())
        self.assertNotIn(self.token, repr(self.provider.calls))
        self.assertEqual(self.provider.calls[0].provider_auth_owner, "HOST_PROXY")
        self.assertFalse(self.provider.calls[0].guest_authorization_forwarded)
        self.assertEqual(self.record.requests_used, 1)

    def test_endpoint_and_model_are_fixed(self):
        with self.assertRaisesRegex(ProxyRejection, "ENDPOINT_NOT_ALLOWED"):
            self.proxy.handle("/v1/chat/completions", self.token, self.body())
        with self.assertRaisesRegex(ProxyRejection, "MODEL_NOT_ALLOWED"):
            self.proxy.handle("/v1/responses", self.token, self.body("arbitrary-model"))
        self.assertEqual(self.record.requests_used, 0)

    def test_request_size_budget_and_expiry_fail_closed(self):
        with self.assertRaisesRegex(ProxyRejection, "REQUEST_TOO_LARGE"):
            self.proxy.handle("/v1/responses", self.token, b"x" * 129)
        self.proxy.handle("/v1/responses", self.token, self.body())
        self.proxy.handle("/v1/responses", self.token, self.body())
        with self.assertRaisesRegex(ProxyRejection, "REQUEST_BUDGET_EXHAUSTED"):
            self.proxy.handle("/v1/responses", self.token, self.body())
        other, _ = self.capabilities.issue("run_fedcba9876543210")
        self.clock.now += 10
        with self.assertRaisesRegex(ProxyRejection, "CAPABILITY_EXPIRED"):
            self.proxy.handle("/v1/responses", other, self.body())

    def test_response_size_is_enforced(self):
        provider = MockResponsesProvider(response_bytes=4097)
        proxy = HostModelProxy(provider, self.limits, self.capabilities)
        with self.assertRaisesRegex(ProxyRejection, "RESPONSE_TOO_LARGE"):
            proxy.handle("/v1/responses", self.token, self.body())

    def test_closed_schema_rejects_persistence_remote_tools_and_unknown_authority(self):
        rejected = [
            {"model": "gpt-5.4", "input": "bounded", "store": True},
            {"model": "gpt-5.4", "input": "bounded", "previous_response_id": "resp_remote"},
            {"model": "gpt-5.4", "input": "bounded", "tools": [{"type": "mcp", "server_url": "https://example.com"}]},
            {"model": "gpt-5.4", "input": "bounded", "tools": [{"type": "image_generation"}]},
            {"model": "gpt-5.4", "input": "bounded", "tools": [{"type": "web_search", "external_web_access": True, "search_content_types": ["text"]}]},
            {"model": "gpt-5.4", "input": "bounded", "tools": [{"type": "web_search", "external_web_access": False, "search_content_types": ["text"]}]},
            {"model": "gpt-5.4", "input": [{"type": "function_call_output", "call_id": "x", "output": "ok", "url": "https://example.com"}]},
            {
                "model": "gpt-5.4",
                "input": [{
                    "type": "tool_search_output", "call_id": "search_1", "execution": "client",
                    "status": "completed", "tools": [{
                        "type": "namespace", "name": "mcp__crumple", "description": "bounded",
                        "tools": [{
                            "type": "function", "name": "package_lookup", "description": "bounded",
                            "parameters": {}, "strict": False, "defer_loading": True,
                            "server_url": "https://example.invalid",
                        }],
                    }],
                }],
            },
        ]
        for payload in rejected:
            with self.subTest(payload=payload), self.assertRaises(ProxyRejection):
                token, _ = self.capabilities.issue(f"run_schema{len(self.capabilities._records):08d}")
                self.proxy.handle("/v1/responses", token, json.dumps(payload).encode())
        self.assertEqual(self.provider.calls, [])

    def test_only_closed_client_tool_declarations_are_admitted(self):
        limits = ProxyLimits(max_requests=1, max_request_bytes=4096, max_response_bytes=4096, ttl_seconds=10)
        capabilities = CapabilityManager(limits, self.clock)
        token, _ = capabilities.issue("run_clientschema0001")
        proxy = HostModelProxy(self.provider, limits, capabilities)
        payload = {
            "model": "gpt-5.4",
            "input": "bounded",
            "store": False,
            "tools": [
                {"type": "function", "name": "exec_command", "description": "bounded", "parameters": {}, "strict": False},
                {"type": "tool_search", "description": "bounded", "execution": "client", "parameters": {}},
            ],
        }
        proxy.handle("/v1/responses", token, json.dumps(payload).encode())
        self.assertEqual(len(self.provider.calls), 1)

    def test_nested_tool_search_output_schema_is_closed(self):
        limits = ProxyLimits(max_requests=1, max_request_bytes=4096, max_response_bytes=4096, ttl_seconds=10)
        capabilities = CapabilityManager(limits, self.clock)
        token, _ = capabilities.issue("run_toolsearchschema1")
        proxy = HostModelProxy(self.provider, limits, capabilities)
        payload = {
            "model": "gpt-5.4",
            "input": [{
                "type": "tool_search_output", "call_id": "search_1", "execution": "client",
                "status": "completed", "tools": [{
                    "type": "namespace", "name": "mcp__crumple", "description": "bounded",
                    "tools": [{
                        "type": "function", "name": "package_lookup", "description": "bounded",
                        "parameters": {}, "strict": False, "defer_loading": True,
                        "server_url": "https://example.invalid",
                    }],
                }],
            }],
        }
        with self.assertRaisesRegex(ProxyRejection, "RESPONSES_REQUEST_SCHEMA_INVALID"):
            proxy.handle("/v1/responses", token, json.dumps(payload).encode())
        self.assertEqual(self.provider.calls, [])

    def test_live_response_read_is_bounded_to_limit_plus_one(self):
        class RecordingResponse(BytesIO):
            status = 200

            class headers:
                @staticmethod
                def get_content_type():
                    return "application/json"

            def read(self, size=-1):
                self.requested = size
                return super().read(size)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        request = self.provider_request()
        response = RecordingResponse(b"x" * 4097)
        with patch.dict(os.environ, {"CRUMPLE_OPENAI_API_KEY": "test-only"}), patch("urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(ProxyRejection, "RESPONSE_TOO_LARGE"):
                LiveResponsesProvider().send(request)
        self.assertEqual(response.requested, request.max_response_bytes + 1)

    def test_live_response_bound_handles_short_network_reads(self):
        class ChunkedResponse:
            status = 200

            class headers:
                @staticmethod
                def get_content_type():
                    return "application/json"

            def __init__(self):
                self.remaining = b"x" * 4097
                self.total_requested = 0

            def read(self, size=-1):
                self.total_requested += size
                chunk = self.remaining[:min(size, 127)]
                self.remaining = self.remaining[len(chunk):]
                return chunk

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        request = self.provider_request()
        response = ChunkedResponse()
        with patch.dict(os.environ, {"CRUMPLE_OPENAI_API_KEY": "test-only"}), patch("urllib.request.urlopen", return_value=response):
            with self.assertRaisesRegex(ProxyRejection, "RESPONSE_TOO_LARGE"):
                LiveResponsesProvider().send(request)
        self.assertEqual(len(response.remaining), 0)

    def test_live_provider_absence_is_explicit_and_no_call_occurs(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ProxyRejection, "OPERATOR_CREDENTIAL_UNAVAILABLE"):
                LiveResponsesProvider().send(self.provider_request())

    def provider_request(self):
        self.proxy.handle("/v1/responses", self.token, self.body())
        return self.provider.calls[-1]


if __name__ == "__main__":
    unittest.main()

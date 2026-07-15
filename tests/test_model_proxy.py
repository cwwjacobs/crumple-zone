import json
import os
import unittest
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

    def test_live_provider_absence_is_explicit_and_no_call_occurs(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ProxyRejection, "OPERATOR_CREDENTIAL_UNAVAILABLE"):
                LiveResponsesProvider().send(self.provider_request())

    def provider_request(self):
        self.proxy.handle("/v1/responses", self.token, self.body())
        return self.provider.calls[-1]


if __name__ == "__main__":
    unittest.main()

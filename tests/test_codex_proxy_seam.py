import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from crumple_zone.guest_codex import build_exec_command
from crumple_zone.model_proxy import CapabilityManager, HostModelProxy, MockResponsesProvider, ProxyLimits
from crumple_zone.model_proxy_http import running_proxy


class CodexProxySeamTests(unittest.TestCase):
    def test_installed_codex_exec_uses_only_run_capability(self):
        codex = shutil.which("codex")
        if codex is None:
            self.fail("CODEX_CLI_NOT_INSTALLED")
        limits = ProxyLimits(max_requests=4, ttl_seconds=60)
        capabilities = CapabilityManager(limits)
        provider = MockResponsesProvider()
        proxy = HostModelProxy(provider, limits, capabilities)
        token, record = capabilities.issue("run_codexseam00000001")

        with tempfile.TemporaryDirectory(prefix="crumple-codex-home-") as codex_home:
            with running_proxy(proxy) as server:
                port = server.server_address[1]
                env = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "CODEX_HOME": codex_home,
                    "CRUMPLE_RUN_CAPABILITY": token,
                    "HOME": codex_home,
                    "NO_COLOR": "1",
                }
                command = build_exec_command(
                    codex,
                    Path(codex_home),
                    f"http://127.0.0.1:{port}/v1",
                    "Return exactly BASELINE_COMPLETE and take no tool action.",
                )
                completed = subprocess.run(
                    command,
                    cwd=Path(codex_home),
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

            self.assertEqual(completed.returncode, 0, completed.stderr[-2000:])
            events = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
            self.assertTrue(events)
            self.assertIn("BASELINE_COMPLETE", completed.stdout)
            self.assertGreaterEqual(record.requests_used, 1)
            self.assertLessEqual(record.requests_used, limits.max_requests)
            self.assertTrue(provider.calls)
            self.assertNotIn(token, completed.stdout)
            self.assertNotIn(token, completed.stderr)
            self.assertNotIn(token, repr(provider.calls))
            self.assertNotIn("OPENAI_API_KEY", env)
            self.assertEqual(list(Path(codex_home).glob("auth.json")), [])

    def test_config_seam_rejects_arbitrary_proxy_destination(self):
        with self.assertRaisesRegex(ValueError, "MODEL_PROXY_BASE_URL_NOT_ALLOWED"):
            build_exec_command("/usr/bin/codex", Path("/tmp").resolve(), "https://example.com/v1", "bounded")


if __name__ == "__main__":
    unittest.main()

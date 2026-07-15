import copy
import hashlib
import json
import unittest
from pathlib import Path

from crumple_zone.contracts import CONTRACT_ROOT, ContractViolation, validate_contract


ROOT = Path(__file__).resolve().parents[1]


class ContractTests(unittest.TestCase):
    def test_all_schema_documents_are_json(self):
        for path in CONTRACT_ROOT.glob("*.schema.json"):
            with self.subTest(path=path.name):
                self.assertIsInstance(json.loads(path.read_text()), dict)

    def test_run_request_positive_and_unknown_field_negative(self):
        request = {
            "schema_version": "run-request.v1",
            "scenario_uri": "fixture://poisoned-tool-surface-v1",
            "policy": "observe",
            "limits": {"vcpu_count": 1, "memory_mib": 512, "wall_seconds": 120, "output_bytes": 1048576, "model_requests": 4},
        }
        validate_contract("run_request", request)
        request["host_path"] = "/etc"
        with self.assertRaisesRegex(ContractViolation, "UNKNOWN_PROPERTY"):
            validate_contract("run_request", request)

    def test_scenario_and_tool_surface_validate(self):
        scenario = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.json").read_text())
        surface = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.tools.json").read_text())
        validate_contract("scenario", scenario)
        validate_contract("tool_surface", surface)

    def test_authority_value_outside_enum_fails(self):
        finding = self._finding()
        finding["authority"] = "HOST_OMNISCIENT"
        with self.assertRaisesRegex(ContractViolation, "ENUM_MISMATCH"):
            validate_contract("finding", finding)

    def test_agent_interpretation_cannot_be_promoted_to_host_authority(self):
        finding = self._finding()
        finding["authority"] = "HOST_ENFORCED"
        with self.assertRaisesRegex(ContractViolation, "AUTHORITY_PROMOTION_INVALID"):
            validate_contract("finding", finding)

    def test_event_authority_is_code_bound(self):
        event = {
            "schema_version": "event.v1",
            "event_id": "evt_0123456789abcdef",
            "run_id": "run_0123456789abcdef",
            "sequence": 0,
            "monotonic_ns": 0,
            "code": "GUEST_EVENT_REPORTED",
            "authority": "HOST_MEDIATED",
            "component": "GUEST_CODEX",
            "scenario_id": "poisoned-tool-surface-v1",
            "policy_id": "observe-v1",
            "tool_id": "NONE",
            "decision": "NONE",
            "action_id": "NONE",
            "argument_projection": {"canary_present": False, "payload_bytes": 0, "argument_hash": "0" * 64},
            "result_projection": {"present": False, "payload_bytes": 0, "result_hash": hashlib.sha256(b"").hexdigest(), "is_error": False},
            "artifact_ref": "NONE",
        }
        with self.assertRaisesRegex(ContractViolation, "AUTHORITY_PROMOTION_INVALID"):
            validate_contract("event", event)

    def test_raw_hostile_strings_cannot_fit_trusted_projection(self):
        projection = self._projection()
        scenario = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.json").read_text())
        surface = json.loads((ROOT / "scenarios/poisoned-tool-surface-v1.tools.json").read_text())
        hostile = scenario["hostile_fixture_strings"] + [tool["description"] for tool in surface["tools"]] + [tool["result_template"] for tool in surface["tools"]]
        encoded = json.dumps(projection, sort_keys=True)
        for value in hostile:
            self.assertNotIn(value.encode(), encoded.encode())
            mutated = copy.deepcopy(projection)
            mutated["limitations"] = [value]
            with self.assertRaises(ContractViolation):
                validate_contract("trusted_projection", mutated)
        validate_contract("trusted_projection", projection)

    def test_event_cross_fields_are_exact(self):
        event = self._event()
        event["component"] = "MODEL_PROXY"
        with self.assertRaisesRegex(ContractViolation, "EVENT_CROSS_FIELD_PREDICATE_INVALID"):
            validate_contract("event", event)

        event = self._event()
        event["argument_projection"]["canary_present"] = True
        with self.assertRaisesRegex(ContractViolation, "EVENT_ARGUMENT_PREDICATE_INVALID"):
            validate_contract("event", event)

    def test_guest_semantics_field_is_rejected(self):
        projection = self._projection()
        projection["guest_summary"] = "untrusted"
        with self.assertRaisesRegex(ContractViolation, "UNKNOWN_PROPERTY"):
            validate_contract("trusted_projection", projection)

    @staticmethod
    def _finding():
        return {
            "schema_version": "finding.v1",
            "finding_id": "fnd_0123456789abcdef",
            "run_id": "run_0123456789abcdef",
            "code": "SUSPECTED_PROMPT_INJECTION",
            "status": "OBSERVED",
            "authority": "AGENT_INTERPRETED",
            "evidence_refs": ["evt_0123456789abcdef"],
            "tripwire_code": "NONE",
        }

    @staticmethod
    def _event():
        return {
            "schema_version": "event.v1",
            "event_id": "evt_0123456789abcdef",
            "run_id": "run_0123456789abcdef",
            "sequence": 0,
            "monotonic_ns": 0,
            "code": "RUN_ACCEPTED",
            "authority": "HOST_ENFORCED",
            "component": "CONTROLLER",
            "scenario_id": "poisoned-tool-surface-v1",
            "policy_id": "observe-v1",
            "tool_id": "NONE",
            "decision": "NONE",
            "action_id": "NONE",
            "argument_projection": {"canary_present": False, "payload_bytes": 0, "argument_hash": hashlib.sha256(b"").hexdigest()},
            "result_projection": {"present": False, "payload_bytes": 0, "result_hash": hashlib.sha256(b"").hexdigest(), "is_error": False},
            "artifact_ref": "NONE",
        }

    @staticmethod
    def _projection():
        digest = "0" * 64
        return {
            "schema_version": "trusted-projection.v1",
            "run_id": "run_0123456789abcdef",
            "run_status": "COMPLETED",
            "failure_code": "NONE",
            "scenario_id": "poisoned-tool-surface-v1",
            "scenario_hash": digest,
            "runtime_manifest_hash": digest,
            "policy_id": "observe-v1",
            "verdict": "INCONCLUSIVE",
            "findings": [],
            "checks_executed": ["REQUEST_SCHEMA_VALID"],
            "checks_not_executed": ["LIVE_PROVIDER_CALL"],
            "failed_checks": [],
            "evidence_refs": [],
            "authority_sources": ["HOST_ENFORCED"],
            "limitations": ["OPERATOR_CREDENTIAL_UNAVAILABLE", "NO_GLOBAL_SAFETY_CLAIM"],
            "envelope_hash": digest,
            "time_to_ready_ms": 1,
            "time_to_ready_limit_ms": 1000,
            "teardown_verified": False,
        }


if __name__ == "__main__":
    unittest.main()

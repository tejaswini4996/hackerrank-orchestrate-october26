"""Custom regression tests for deletion-audit policy helpers."""
import importlib.util
import unittest
from pathlib import Path

MAIN = Path(__file__).resolve().parents[1] / "main.py"
SPEC = importlib.util.spec_from_file_location("deletion_audit_main", MAIN)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class DeletionAuditCustomCases(unittest.TestCase):
    def test_non_deletion_phone_update(self):
        text = "The mobile number on my profile is out of date. Please replace it and leave the account active."
        self.assertTrue(MODULE.is_non_deletion_request(text))

    def test_erasure_request_with_generic_policy_boilerplate(self):
        text = "I would like the account to be erased. Please apply the correct treatment to records covered by the request."
        self.assertFalse(MODULE.is_non_deletion_request(text))

    def test_active_connector_requires_disable(self):
        state = MODULE.state_from_record("DATA_FLOW", {"enabled": True, "customer_email": "user@example.com"})
        self.assertEqual(state, "ACTIVE")

    def test_restore_access_must_be_blocked(self):
        state = MODULE.state_from_record("BACKUP_ARCHIVE", {"restore_allowed": True, "customer_reference": "user_10"})
        self.assertEqual(state, "ACTIVE")

    def test_tombstone_with_direct_identifiers_is_not_compliant(self):
        state = MODULE.state_from_record(
            "ACCOUNT_TOMBSTONE",
            {"subject_reference": "user_10", "email": "user@example.com", "phone": "+1 555 0100"},
        )
        self.assertEqual(state, "PRESENT")

    def test_tombstone_with_only_stable_user_reference_is_redacted(self):
        state = MODULE.state_from_record(
            "ACCOUNT_TOMBSTONE",
            {"subject_reference": "user_10", "email": None, "phone": None, "email_hash": None, "name": None},
        )
        self.assertEqual(state, "REDACTED")

    def test_sql_json_payload_is_expanded_before_classification(self):
        row = {
            "resource_id": "search_123",
            "payload": '{"email":"person@example.com","customer_reference":"user_10"}',
        }
        expanded = MODULE.expand_record_fields(row)
        self.assertEqual(expanded["email"], "person@example.com")
        self.assertEqual(expanded["customer_reference"], "user_10")
        self.assertEqual(MODULE.state_from_record("SEARCH_INDEX_ENTRY", expanded), "PRESENT")

    def test_resource_link_can_use_stable_user_id_without_old_email(self):
        cutoff = MODULE.parse_time("2026-09-10T00:00:00Z")
        observation = MODULE.make_observation(
            "evidence_1", cutoff, cutoff, "search_service", "search_123",
            "SEARCH_INDEX_ENTRY", "PRESENT", [("resource_id", "search_123")], "json"
        )
        activity = [{
            "event_time": "2026-09-09T00:00:00Z",
            "event_type": "LINK_RESOURCE_IDENTITY",
            "resource_id": "search_123",
            "details": "Catalog linked search_123 to stable subject user_10",
        }]
        selected = MODULE.relevant_obs_for_case(
            {"audit_at": "2026-09-10T00:00:00Z"}, "user_10", {"old@example.com"},
            [observation], cutoff, activity
        )
        self.assertEqual([o["resource_id"] for o in selected], ["search_123"])


if __name__ == "__main__":
    unittest.main()

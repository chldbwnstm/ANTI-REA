"""Pure parent-side evidence checks; no target/compiler execution."""
import copy
import unittest

from antirea.script_validation_evidence import compare_repeated_observations
from antirea.languages import language_catalog


def reply(rows=None):
    rows = rows if rows is not None else [
        {"kind": "return", "type": "int", "value": "7"},
        {"kind": "exception", "type": "ZeroDivisionError"},
    ]
    return {"outputs": {"f": copy.deepcopy(rows)},
            "outputs_second": {"f": copy.deepcopy(rows)},
            "deterministic": {"f": True}}


class ScriptRepeatEvidenceTests(unittest.TestCase):
    def compare(self, baseline=None, protected=None):
        return compare_repeated_observations(
            reply() if baseline is None else baseline,
            reply() if protected is None else protected, "f", 2)

    def test_equal_raw_repeats_pass(self):
        self.assertEqual(self.compare(), {
            "sampled_output_match": True, "deterministic": True,
            "raw_repeat_arrays_compared": True})

    def test_second_repeat_change_defeats_true_summary(self):
        protected = reply()
        protected["outputs_second"]["f"][0]["value"] = "9"
        result = self.compare(protected=protected)
        self.assertFalse(result["sampled_output_match"])
        self.assertFalse(result["deterministic"])

    def test_equal_cross_arm_nondeterminism_still_fails(self):
        first, second = reply(), reply()
        for arm in (first, second):
            arm["outputs_second"]["f"][0]["value"] = "9"
        result = self.compare(first, second)
        self.assertTrue(result["sampled_output_match"])
        self.assertFalse(result["deterministic"])

    def test_different_but_individually_deterministic_arms_fail(self):
        protected = reply()
        for field in ("outputs", "outputs_second"):
            protected[field]["f"][0]["value"] = "9"
        result = self.compare(protected=protected)
        self.assertFalse(result["sampled_output_match"])
        self.assertTrue(result["deterministic"])

    def test_false_child_summary_is_not_overridden(self):
        protected = reply()
        protected["deterministic"]["f"] = False
        self.assertFalse(self.compare(protected=protected)["deterministic"])

    def test_summary_cannot_replace_missing_raw_array(self):
        for arm_name in ("baseline", "protected"):
            for field in ("outputs", "outputs_second", "deterministic"):
                with self.subTest(arm=arm_name, field=field):
                    arms = {"baseline": reply(), "protected": reply()}
                    del arms[arm_name][field]
                    with self.assertRaises(ValueError):
                        self.compare(**arms)

    def test_missing_function_is_refused(self):
        for field in ("outputs", "outputs_second", "deterministic"):
            with self.subTest(field=field):
                protected = reply()
                del protected[field]["f"]
                with self.assertRaises(ValueError):
                    self.compare(protected=protected)

    def test_nonboolean_summary_refused(self):
        for value in (1, 0, "true", [], None):
            with self.subTest(value=value):
                protected = reply()
                protected["deterministic"]["f"] = value
                with self.assertRaises(ValueError):
                    self.compare(protected=protected)

    def test_wrong_length_in_any_raw_array_refused(self):
        for arm_name in ("baseline", "protected"):
            for field in ("outputs", "outputs_second"):
                with self.subTest(arm=arm_name, field=field):
                    arms = {"baseline": reply(), "protected": reply()}
                    arms[arm_name][field]["f"].pop()
                    with self.assertRaises(ValueError):
                        self.compare(**arms)

    def test_nonlist_array_refused(self):
        for value in ({}, (), "12", None):
            with self.subTest(value=value):
                protected = reply()
                protected["outputs_second"]["f"] = value
                with self.assertRaises(ValueError):
                    self.compare(protected=protected)

    def test_untagged_observation_refused(self):
        protected = reply()
        protected["outputs_second"]["f"][0] = 7
        with self.assertRaises(ValueError):
            self.compare(protected=protected)

    def test_reply_and_field_types_refused(self):
        for value in ([], "reply", 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.compare(protected=value)
        protected = reply()
        protected["outputs_second"] = []
        with self.assertRaises(ValueError):
            self.compare(protected=protected)

    def test_expected_count_must_be_positive_exact_int(self):
        for value in (0, -1, True, 2.0, "2"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compare_repeated_observations(reply(), reply(), "f", value)

    def test_function_name_must_be_nonempty_string(self):
        for value in ("", None, 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                compare_repeated_observations(reply(), reply(), value, 2)

    def test_type_tags_are_not_coerced(self):
        protected = reply()
        for field in ("outputs", "outputs_second"):
            protected[field]["f"][0] = {"kind": "return", "type": "bool", "value": "True"}
        self.assertFalse(self.compare(protected=protected)["sampled_output_match"])

    def test_number_negative_zero_tags_are_not_normalized(self):
        original = reply([{"kind": "return", "type": "number", "value": "0000000000000000"}] * 2)
        protected = reply([{"kind": "return", "type": "number", "value": "8000000000000000"}] * 2)
        self.assertFalse(self.compare(original, protected)["sampled_output_match"])

    def test_boolean_payload_does_not_compare_equal_to_integer_one(self):
        original = reply([{"kind": "return", "type": "boolean", "value": True}] * 2)
        protected = reply([{"kind": "return", "type": "boolean", "value": 1}] * 2)
        self.assertFalse(self.compare(original, protected)["sampled_output_match"])

    def test_nonfinite_json_payload_is_refused(self):
        malformed = reply([{"kind": "return", "type": "number", "value": float("nan")}] * 2)
        with self.assertRaises(ValueError):
            self.compare(protected=malformed)

    def test_inputs_are_not_mutated(self):
        original, protected = reply(), reply()
        snapshots = copy.deepcopy((original, protected))
        self.compare(original, protected)
        self.assertEqual((original, protected), snapshots)


class ScriptHardeningCatalogTests(unittest.TestCase):
    def test_script_catalog_exposes_scoped_profile_without_native_or_resistance_claim(self):
        for language in ("python", "javascript", "typescript"):
            with self.subTest(language=language):
                protection = language_catalog(language)["languages"][0]["source_protection"]
                hardening = protection["runtime_hardening"]
                self.assertEqual(hardening["profile"], "per_function_flattened_dispatch_v1")
                self.assertEqual(hardening["qualification"], "per_artifact_required")
                self.assertIs(hardening["kagura_passes_applied"], False)
                self.assertEqual(hardening["external_attack_evaluation"], "not_evaluated")
                self.assertIs(protection["whole_language_verified"], False)

    def test_script_profile_is_not_claimed_for_native_routes(self):
        for language in ("c", "cpp", "rust", "go", "swift", "csharp", "java", "kotlin"):
            with self.subTest(language=language):
                protection = language_catalog(language)["languages"][0]["source_protection"]
                self.assertNotIn("runtime_hardening", protection)


if __name__ == "__main__":
    unittest.main()

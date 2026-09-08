from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from rule_validation import load_rule, matches_rule, validate_rule  # noqa: E402


RULE_DIR = ROOT / "rules" / "sigma"
KQL_DIR = ROOT / "queries" / "kql"
SPL_DIR = ROOT / "queries" / "spl"
CASE_PATH = ROOT / "tests" / "cases" / "process_events.json"
HUNT_CATALOG_PATH = ROOT / "hunts" / "catalog.yml"


def _rules() -> dict[str, dict]:
    return {path.stem: load_rule(path) for path in sorted(RULE_DIR.glob("*.yml"))}


def _case_id(case: dict) -> str:
    outcome = "match" if case["expected"] else "no-match"
    return f"{case['rule']}-{outcome}"


with CASE_PATH.open("r", encoding="utf-8") as handle:
    CASES = json.load(handle)

with HUNT_CATALOG_PATH.open("r", encoding="utf-8") as handle:
    HUNT_CATALOG = yaml.safe_load(handle)["entries"]


class RepositoryTests(unittest.TestCase):
    def test_rule_set_is_valid(self) -> None:
        rules = _rules()
        self.assertEqual(len(rules), 6)

        errors: list[str] = []
        for stem, rule in rules.items():
            errors.extend(validate_rule(rule, Path(f"rules/sigma/{stem}.yml")))

        self.assertEqual(errors, [])
        self.assertEqual(len({str(rule["id"]) for rule in rules.values()}), len(rules))
        self.assertEqual(len({rule["title"] for rule in rules.values()}), len(rules))

    def test_query_sets_match_sigma_rule_names(self) -> None:
        sigma_stems = set(_rules())
        kql_stems = {path.stem for path in KQL_DIR.glob("*.kql")}
        spl_stems = {path.stem for path in SPL_DIR.glob("*.spl")}

        self.assertEqual(kql_stems, sigma_stems)
        self.assertEqual(spl_stems, sigma_stems)

    def test_kql_query_shape(self) -> None:
        for path in sorted(KQL_DIR.glob("*.kql")):
            with self.subTest(query=path.stem):
                query = path.read_text(encoding="utf-8")
                self.assertTrue(query.startswith("DeviceProcessEvents\n"))
                self.assertIn("| where ", query)
                self.assertIn("| project Timestamp, DeviceName", query)
                self.assertIn("ReportId", query)

    def test_spl_query_shape(self) -> None:
        for path in sorted(SPL_DIR.glob("*.spl")):
            with self.subTest(query=path.stem):
                query = path.read_text(encoding="utf-8")
                self.assertIn("FROM datamodel=Endpoint.Processes", query)
                self.assertIn("Processes.process_name", query)
                self.assertIn("| rename Processes.* AS *", query)
                self.assertIn("| table ", query)

    def test_synthetic_process_events(self) -> None:
        rules = _rules()
        for case in CASES:
            with self.subTest(case=_case_id(case)):
                self.assertIn(case["rule"], rules)
                self.assertIs(
                    matches_rule(rules[case["rule"]], case["event"]),
                    case["expected"],
                )

    def test_hunt_catalog_is_valid(self) -> None:
        self.assertEqual(len(HUNT_CATALOG), 8)
        self.assertEqual(len({entry["id"] for entry in HUNT_CATALOG}), 8)
        self.assertEqual(len({entry["query"] for entry in HUNT_CATALOG}), 8)

        discovered_queries = {
            path.relative_to(ROOT).as_posix()
            for base in (ROOT / "hunts", ROOT / "analytics")
            for path in base.rglob("*")
            if path.suffix in {".kql", ".cql", ".spl"}
        }
        catalog_queries = {entry["query"] for entry in HUNT_CATALOG}
        self.assertEqual(catalog_queries, discovered_queries)

        for entry in HUNT_CATALOG:
            with self.subTest(hunt=entry["id"]):
                self.assertIn(entry["kind"], {"hunt", "analysis"})
                self.assertIn(entry["status"], {"test", "experimental"})
                self.assertIn(
                    entry["platform"],
                    {"microsoft-defender-xdr", "crowdstrike-logscale", "splunk"},
                )
                self.assertTrue(entry["data_sources"])
                self.assertTrue(entry["expected_signals"])
                self.assertTrue((ROOT / entry["query"]).is_file())

    def test_hunt_queries_contain_expected_signals(self) -> None:
        for entry in HUNT_CATALOG:
            with self.subTest(hunt=entry["id"]):
                query = (ROOT / entry["query"]).read_text(encoding="utf-8")
                self.assertGreater(len(query.splitlines()), 5)
                for signal in entry["expected_signals"]:
                    self.assertIn(signal, query)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Tests for openrouter_zdr_audit.py — stdlib unittest only, no network.

Run: python3 tests/run_tests.py  (exit 0 on success)
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import openrouter_zdr_audit as oza


def run_cli(*argv, **kw):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "openrouter_zdr_audit.py"), *argv],
        capture_output=True, text=True, timeout=30, cwd=ROOT, **kw)


def req(model, provider, date, rid="r1"):
    return {"id": rid, "model": model, "provider": provider, "date": date}


class TestDateParsing(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(oza.parse_day("2026-10-05").isoformat(), "2026-10-05")

    def test_malformed_returns_none(self):
        for bad in ("", "2026/10/05", "2026-13-01", "2026-02-30", "Oct 5",
                    "2026-10", None, 20261005, "  "):
            self.assertIsNone(oza.parse_day(bad), bad)


class TestIncidentWindows(unittest.TestCase):
    def test_novita_window_inclusive(self):
        for d in ("2026-05-28", "2026-10-05", "2026-11-11"):
            v, _ = oza.audit_request(req("minimax/minimax-m2", "novita", d))
            self.assertEqual(v, "EXPOSED", d)

    def test_novita_window_boundaries_excluded(self):
        # Day before start / day after end: same provider, so AT_RISK not EXPOSED.
        for d in ("2026-05-27", "2026-11-12"):
            v, _ = oza.audit_request(req("minimax/minimax-m2", "novita", d))
            self.assertEqual(v, "AT_RISK", d)

    def test_phala_window(self):
        v, _ = oza.audit_request(
            req("deepseek/deepseek-v4-flash-0731", "phala", "2026-10-21"))
        self.assertEqual(v, "EXPOSED")
        v, _ = oza.audit_request(
            req("deepseek/deepseek-v4-flash-0731", "phala", "2026-11-09"))
        self.assertEqual(v, "AT_RISK")

    def test_together_models(self):
        for model in ("z-ai/glm-5.2", "moonshotai/kimi-k2.6",
                      "minimax/minimax-m2"):
            v, _ = oza.audit_request(req(model, "together", "2026-07-04"))
            self.assertEqual(v, "EXPOSED", model)

    def test_together_window_end(self):
        v, _ = oza.audit_request(req("z-ai/glm-5.2", "together", "2026-08-01"))
        self.assertEqual(v, "AT_RISK")

    def test_provider_mismatch_not_exposed(self):
        # Same model + date, different provider: not in any incident window.
        v, _ = oza.audit_request(req("minimax/minimax-m2", "fireworks",
                                     "2026-10-05"))
        self.assertEqual(v, "CLEAR")

    def test_model_match_case_insensitive(self):
        v, _ = oza.audit_request(req("MiniMax/MiniMax-M2", "Novita", "2026-10-05"))
        self.assertEqual(v, "EXPOSED")

    def test_clear_before_zdr_removal(self):
        v, _ = oza.audit_request(req("openai/gpt-6.2-sol", "openai", "2026-11-20"))
        self.assertEqual(v, "CLEAR")

    def test_unknown_zdr_on_removal_day(self):
        v, _ = oza.audit_request(
            req("google/gemini-4-neon", "google", "2026-11-22"))
        self.assertEqual(v, "UNKNOWN_ZDR")

    def test_zdr_removal_does_not_override_incident(self):
        # Novita request after 2026-11-22 is AT_RISK (notice provider),
        # not UNKNOWN_ZDR — the provider rule takes precedence.
        v, _ = oza.audit_request(req("minimax/minimax-m2", "novita", "2026-11-25"))
        self.assertEqual(v, "AT_RISK")


class TestMalformedInput(unittest.TestCase):
    def test_missing_fields_skipped(self):
        for bad in ({}, {"model": "x"}, {"provider": "novita"},
                    {"model": "x", "provider": "novita"},
                    {"model": "x", "provider": "novita", "date": "junk"},
                    "not a dict", None):
            v, _ = oza.audit_request(bad)
            self.assertEqual(v, "SKIPPED", bad)

    def test_audit_lines_skips_bad_json(self):
        results = oza.audit_lines([
            '{"id": "a", "model": "x", "provider": "y", "date": "2026-11-01"}',
            '{broken json',
            '',
            '{"id": "b", "model": "minimax/minimax-m2", "provider": "novita", '
            '"date": "2026-10-05"}',
        ])
        self.assertEqual([r["verdict"] for r in results],
                         ["CLEAR", "SKIPPED", "EXPOSED"])

    def test_empty_log(self):
        self.assertEqual(oza.audit_lines([]), [])
        self.assertEqual(oza.audit_lines(["", "  "]), [])


class TestCli(unittest.TestCase):
    def test_demo_deterministic(self):
        r1 = run_cli("--demo", "--fail-on", "never")
        r2 = run_cli("--demo", "--fail-on", "never")
        self.assertEqual(r1.returncode, 0)
        self.assertEqual(r1.stdout, r2.stdout)
        self.assertEqual(len(hashlib.sha256(r1.stdout.encode()).hexdigest()), 64)

    def test_demo_exit_1_by_design(self):
        # 4 EXPOSED requests in the sample log, so plain --demo exits 1.
        r = run_cli("--demo")
        self.assertEqual(r.returncode, 1)
        self.assertIn("EXPOSED: 4", r.stdout)

    def test_demo_summary_counts(self):
        r = run_cli("--demo", "--fail-on", "never")
        self.assertIn(
            "Summary (10 requests): EXPOSED: 4, AT_RISK: 2, UNKNOWN_ZDR: 1, "
            "CLEAR: 2, SKIPPED: 1", r.stdout)
        self.assertIn("Rotate secrets from these requests:", r.stdout)
        self.assertIn("req-2: deepseek/deepseek-v4-flash-0731 via phala",
                      r.stdout)

    def test_json_output_parses(self):
        r = run_cli("--demo", "--json", "--fail-on", "never")
        self.assertEqual(r.returncode, 0)
        data = json.loads(r.stdout)
        self.assertEqual(len(data["results"]), 10)
        verdicts = [x["verdict"] for x in data["results"]]
        self.assertEqual(verdicts.count("EXPOSED"), 4)

    def test_stdin_log(self):
        r = run_cli("--fail-on", "never", input='{"id": "s1", "model": '
                    '"openai/gpt-6.2-sol", "provider": "openai", '
                    '"date": "2026-11-20"}\n')
        self.assertEqual(r.returncode, 0)
        self.assertIn("CLEAR", r.stdout)

    def test_custom_log_file(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                        delete=False) as fh:
            fh.write('{"id": "c1", "model": "minimax/minimax-m2", '
                     '"provider": "novita", "date": "2026-06-01"}\n')
            path = fh.name
        try:
            r = run_cli("--log", path, "--fail-on", "never")
            self.assertEqual(r.returncode, 0)
            self.assertIn("EXPOSED", r.stdout)
        finally:
            os.unlink(path)

    def test_missing_log_file_errors(self):
        r = run_cli("--log", "/nonexistent/log.jsonl")
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

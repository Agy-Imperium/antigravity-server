#!/usr/bin/env python3
"""
Antigravity Zero-Privilege Bypass System - Unified E2E Test Runner
Executes 4-Tier Opaque-Box Test Suites:
  - Tier 1: Isolated Feature Coverage (F1-F16, >=5 each)
  - Tier 2: Boundary Value Analysis & Corner Cases (F1-F16, >=5 each)
  - Tier 3: Cross-Feature Combinations (Pairwise Integrations)
  - Tier 4: Real-World Workload Scenarios & Live Prompt Verification

Supports CLI filtering (--tier 1..4), structured JSON output (--json),
colored summary tables, and strict exit code contracts (0=pass, 1=fail).
"""

import argparse
import json
import os
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Tuple

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR))

# Tier to module mapping
TIER_MODULES = {
    1: {
        "name": "Tier 1: Feature Coverage (Category-Partition)",
        "module": "test_tier1_features",
        "file": TESTS_DIR / "test_tier1_features.py",
    },
    2: {
        "name": "Tier 2: Boundary & Corner Cases (BVA)",
        "module": "test_tier2_boundaries",
        "file": TESTS_DIR / "test_tier2_boundaries.py",
    },
    3: {
        "name": "Tier 3: Cross-Feature Combinations (Pairwise)",
        "module": "test_tier3_combinations",
        "file": TESTS_DIR / "test_tier3_combinations.py",
    },
    4: {
        "name": "Tier 4: Real-World Workloads (Scenarios)",
        "module": "test_tier4_workloads",
        "file": TESTS_DIR / "test_tier4_workloads.py",
    },
}


class DetailedTestResult(unittest.TestResult):
    """Custom TestResult that captures timing, status, and error details per test."""

    def __init__(self, stream=None, descriptions=None, verbosity=1):
        super().__init__(stream, descriptions, verbosity)
        self.verbosity = verbosity
        self.records: List[Dict] = []
        self._test_start_time = 0.0

    def startTest(self, test):
        super().startTest(test)
        self._test_start_time = time.perf_counter()
        if self.verbosity > 1:
            sys.stdout.write(f"  RUN: {test.id()} ... ")
            sys.stdout.flush()

    def addSuccess(self, test):
        super().addSuccess(test)
        elapsed = time.perf_counter() - self._test_start_time
        self.records.append({
            "id": test.id(),
            "name": getattr(test, "_testMethodName", str(test)),
            "doc": getattr(test, "_testMethodDoc", "") or "",
            "status": "PASSED",
            "duration": elapsed,
            "error": None,
        })
        if self.verbosity > 1:
            sys.stdout.write(f"\033[32mPASS\033[0m ({elapsed:.3f}s)\n")
            sys.stdout.flush()

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        elapsed = time.perf_counter() - self._test_start_time
        self.records.append({
            "id": test.id(),
            "name": getattr(test, "_testMethodName", str(test)),
            "doc": getattr(test, "_testMethodDoc", "") or "",
            "status": "SKIPPED",
            "duration": elapsed,
            "skip_reason": reason,
            "error": None,
        })
        if self.verbosity > 1:
            sys.stdout.write(f"\033[33mSKIP\033[0m ({reason})\n")
            sys.stdout.flush()

    def addFailure(self, test, err):
        super().addFailure(test, err)
        elapsed = time.perf_counter() - self._test_start_time
        err_msg = self._exc_info_to_string(err, test)
        self.records.append({
            "id": test.id(),
            "name": getattr(test, "_testMethodName", str(test)),
            "doc": getattr(test, "_testMethodDoc", "") or "",
            "status": "FAILED",
            "duration": elapsed,
            "error": err_msg,
        })
        if self.verbosity > 1:
            sys.stdout.write(f"\033[31mFAIL\033[0m ({elapsed:.3f}s)\n")
            sys.stdout.flush()

    def addError(self, test, err):
        super().addError(test, err)
        elapsed = time.perf_counter() - self._test_start_time
        err_msg = self._exc_info_to_string(err, test)
        self.records.append({
            "id": test.id(),
            "name": getattr(test, "_testMethodName", str(test)),
            "doc": getattr(test, "_testMethodDoc", "") or "",
            "status": "ERROR",
            "duration": elapsed,
            "error": err_msg,
        })
        if self.verbosity > 1:
            sys.stdout.write(f"\033[31mERROR\033[0m ({elapsed:.3f}s)\n")
            sys.stdout.flush()


def run_tier(tier_num: int, verbosity: int = 1) -> Tuple[Dict, DetailedTestResult]:
    """Execute all tests in specified tier and return summary statistics."""
    tier_info = TIER_MODULES[tier_num]
    module_name = tier_info["module"]

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(module_name)

    result = DetailedTestResult(verbosity=verbosity)
    start_t = time.perf_counter()
    suite.run(result)
    duration = time.perf_counter() - start_t

    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    passed = total_tests - failures - errors - skipped

    tier_summary = {
        "tier": tier_num,
        "name": tier_info["name"],
        "total": total_tests,
        "passed": passed,
        "skipped": skipped,
        "failed": failures,
        "errors": errors,
        "duration": duration,
        "tests": result.records,
    }

    return tier_summary, result


def print_colored_summary_table(tier_summaries: List[Dict], total_duration: float):
    """Render a clean, formatted terminal summary table."""
    print("\n" + "=" * 80)
    print(" ANTIGRAVITY ZERO-PRIVILEGE BYPASS — E2E TEST EXECUTION SUMMARY")
    print("=" * 80)
    print(f"{'Tier':<6} {'Name':<42} {'Total':<6} {'Pass':<6} {'Skip':<6} {'Fail':<6} {'Time':<8}")
    print("-" * 80)

    total_all = 0
    total_pass = 0
    total_skip = 0
    total_fail = 0

    for s in tier_summaries:
        t_id = f"T{s['tier']}"
        name = s['name'][:40]
        tot = s['total']
        p = s['passed']
        sk = s['skipped']
        f = s['failed'] + s['errors']
        tm = f"{s['duration']:.2f}s"

        total_all += tot
        total_pass += p
        total_skip += sk
        total_fail += f

        pass_col = f"\033[32m{p:<6}\033[0m" if p > 0 else f"{p:<6}"
        fail_col = f"\033[31m{f:<6}\033[0m" if f > 0 else f"{f:<6}"
        skip_col = f"\033[33m{sk:<6}\033[0m" if sk > 0 else f"{sk:<6}"

        print(f"{t_id:<6} {name:<42} {tot:<6} {pass_col} {skip_col} {fail_col} {tm:<8}")

    print("-" * 80)
    tot_pass_col = f"\033[32m{total_pass:<6}\033[0m" if total_pass > 0 else f"{total_pass:<6}"
    tot_fail_col = f"\033[31m{total_fail:<6}\033[0m" if total_fail > 0 else f"{total_fail:<6}"
    tot_skip_col = f"\033[33m{total_skip:<6}\033[0m" if total_skip > 0 else f"{total_skip:<6}"
    print(f"{'TOTAL':<6} {'All Executed Test Suites':<42} {total_all:<6} {tot_pass_col} {tot_skip_col} {tot_fail_col} {total_duration:.2f}s")
    print("=" * 80)

    # Print failures if any
    all_failures = []
    for s in tier_summaries:
        for t in s["tests"]:
            if t["status"] in ["FAILED", "ERROR"]:
                all_failures.append((s["tier"], t))

    if all_failures:
        print("\n\033[31m[FAILED TESTS DETAILS]\033[0m")
        for tier_num, t in all_failures:
            print(f"\n--- Tier {tier_num}: {t['id']} ---")
            print(t["error"])
        print("\n\033[31mFAILED: One or more test suites encountered failures.\033[0m")
    else:
        print(f"\n\033[32mSUCCESS: All {total_all} test cases passed or safely skipped pending milestones.\033[0m")


def main():
    parser = argparse.ArgumentParser(
        description="Antigravity Zero-Privilege Bypass - Opaque-Box E2E Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 e2e_runner.py                # Run all test tiers (Tiers 1..4)
  python3 e2e_runner.py --tier 1       # Run only Tier 1 Feature Coverage
  python3 e2e_runner.py --tier 2       # Run only Tier 2 Boundary Tests
  python3 e2e_runner.py --json         # Output structured JSON report
  python3 e2e_runner.py -v             # Verbose live test logging
        """
    )
    parser.add_argument(
        "--tier",
        type=int,
        choices=[1, 2, 3, 4],
        help="Run a specific tier (1: Features, 2: Boundaries, 3: Combinations, 4: Workloads)"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        default=True,
        help="Run all tiers (default)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output structured JSON results to stdout"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose test output"
    )

    args = parser.parse_args()

    selected_tiers = [args.tier] if args.tier is not None else [1, 2, 3, 4]
    verbosity = 2 if args.verbose else 1

    overall_start = time.perf_counter()
    tier_summaries = []
    has_failure = False

    for tier_num in selected_tiers:
        if not args.json and verbosity > 1:
            print(f"\n>>> Running {TIER_MODULES[tier_num]['name']}...")
        summary, result = run_tier(tier_num, verbosity=verbosity)
        tier_summaries.append(summary)
        if summary["failed"] > 0 or summary["errors"] > 0:
            has_failure = True

    overall_duration = time.perf_counter() - overall_start

    if args.json:
        report = {
            "status": "FAILED" if has_failure else "PASSED",
            "total_duration": overall_duration,
            "selected_tiers": selected_tiers,
            "summaries": tier_summaries,
        }
        print(json.dumps(report, indent=2))
    else:
        print_colored_summary_table(tier_summaries, overall_duration)

    sys.exit(1 if has_failure else 0)


if __name__ == "__main__":
    main()

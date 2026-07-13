#!/usr/bin/python3
"""run_tests.py — RUN tinycss2's ENTIRE upstream pytest suite and print a parseable summary.

Invoked via the `/mayhem/tinycss2-tests` ELF launcher (NOT directly), so the verify-repo
sabotage oracle can neuter the launcher and prove the test oracle is behavioral.

This runs upstream's own suite (tests/test_tinycss2.py — the CSS parsing known-answer tests
driven by the tests/css-parsing-tests JSON corpus), unmodified, with the project's normal
pytest configuration from pyproject.toml. It prints one line:

    RUNTESTS tests=<n> passed=<p> failed=<f> skipped=<s>

Exit 0 iff failed == 0. mayhem/test.sh parses that line into a CTRF report.
"""
from __future__ import annotations

import sys


class _Counter:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            if report.passed:
                self.passed += 1
            elif report.failed:
                self.failed += 1
            elif report.skipped:
                self.skipped += 1
        elif report.when in ("setup", "teardown"):
            if report.failed:
                self.failed += 1
            elif report.skipped and report.when == "setup":
                self.skipped += 1


def main() -> int:
    import pytest

    counter = _Counter()
    rc = pytest.main(["-q", "/mayhem/tests", "-p", "no:cacheprovider"], plugins=[counter])
    tests = counter.passed + counter.failed + counter.skipped
    print(f"RUNTESTS tests={tests} passed={counter.passed} "
          f"failed={counter.failed} skipped={counter.skipped}")
    if tests == 0:
        print("RUNTESTS-ERROR no tests collected", file=sys.stderr)
        return 1
    if rc != 0 and counter.failed == 0:
        # pytest failed for a non-test-failure reason (usage error, internal error)
        print(f"RUNTESTS-ERROR pytest exited {rc} with no recorded failures", file=sys.stderr)
        return 1
    return 0 if counter.failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # import/setup failure is a hard failure, not a vacuous pass
        import traceback

        traceback.print_exc()
        print(f"RUNTESTS tests=1 passed=0 failed=1 skipped=0 (harness error: {exc})")
        sys.exit(1)

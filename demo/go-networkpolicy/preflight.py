#!/usr/bin/env python3
"""Bounded, fully logged dataplane stabilization BEFORE any scored kind episode.

This is a separate admin-only probe Pod; the before/during/after Oracle still
requires the original three exact HTTP results and no favorable sample picks.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

MAX_SAMPLES = 8
REQUIRED_CONSECUTIVE = 2

def is_stable(probe, expected_service_ip):
    if not isinstance(probe, dict):
        return False
    return (
        probe.get("dns_ok") is True
        and probe.get("dns_error") == ""
        and isinstance(probe.get("dns_addresses"), list)
        and expected_service_ip in probe["dns_addresses"]
        and probe.get("name_http_status") == 200
        and probe.get("direct_http_status") == 200
        and probe.get("direct_http_attempts") == [200, 200, 200]
    )

def wait_until_stable(collect, expected_ip, emit, sleep=time.sleep):
    streak = 0
    for attempt in range(1, MAX_SAMPLES + 1):
        try:
            sample = collect()
        except Exception as exc:
            # Record exceptions rather than dropping failed samples.
            sample = {"error": str(exc)[:256]}
        stable = is_stable(sample, expected_ip)
        emit({"attempt": attempt, "stable": stable, "probe": sample})
        streak = streak + 1 if stable else 0
        if streak >= REQUIRED_CONSECUTIVE:
            return True
        if attempt < MAX_SAMPLES:
            sleep(1)
    return False

def run_probe():
    try:
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("probe.py"))],
            text=True, capture_output=True, timeout=16, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": f"probe unavailable: {type(exc).__name__}"}
    if result.returncode != 0 or len(result.stdout) > 16384:
        return {"error": "probe exited unsuccessfully or output exceeded 16KiB",
                "exit_code": result.returncode}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": "probe response was not a single JSON document"}

def main():
    expected_ip = os.environ.get("SERVICE_IP", "")
    if not expected_ip:
        print("UNKNOWN: no explicit Service IP", file=sys.stderr)
        return 3
    good = wait_until_stable(
        run_probe, expected_ip,
        lambda entry: print(json.dumps(entry, sort_keys=True), flush=True),
    )
    if not good:
        print("UNKNOWN: bounded dataplane startup preflight did not stabilize",
              file=sys.stderr)
        return 3
    print("PASS: two consecutive independently logged stable preflight snapshots",
          flush=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())

"""G2i: startup readiness is separate from the frozen before/during/after oracle."""
import importlib.util
from pathlib import Path

PREFLIGHT = Path(__file__).resolve().parents[1] / "demo" / "go-networkpolicy" / "preflight.py"
spec = importlib.util.spec_from_file_location("g2i_preflight", PREFLIGHT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def sample(name=200, direct=(200, 200, 200), resolved=("10.96.0.55",)):
    return {
        "dns_ok": True, "dns_error": "", "dns_addresses": list(resolved),
        "name_http_status": name, "direct_http_status": direct[-1],
        "direct_http_attempts": list(direct),
    }

def test_reject_transient_success_and_wrong_service_ip():
    assert not module.is_stable(sample(name=0), "10.96.0.55")
    assert not module.is_stable(sample(direct=(0, 200, 200)), "10.96.0.55")
    assert not module.is_stable(sample(resolved=("203.0.113.7",)), "10.96.0.55")
    assert module.is_stable(sample(), "10.96.0.55")

def test_stable_preflight_preserves_every_cold_and_successful_sample():
    samples = iter([
        sample(name=0, direct=(0, 200, 200)),
        sample(),
        sample(direct=(200, 0, 200)),
        sample(),
        sample(),
    ])
    events = []
    ok = module.wait_until_stable(
        lambda: next(samples), "10.96.0.55", events.append,
        sleep=lambda _: None,
    )
    assert ok is True
    assert len(events) == 5
    assert [event["stable"] for event in events] == [
        False, True, False, True, True
    ]
    assert events[0]["probe"]["direct_http_attempts"] == [0, 200, 200]

def test_flaky_baseline_exhausts_a_bounded_attempt_budget():
    samples = iter([sample() if i % 2 else sample(name=0) for i in range(8)])
    events = []
    ok = module.wait_until_stable(
        lambda: next(samples), "10.96.0.55", events.append,
        sleep=lambda _: None,
    )
    assert ok is False
    assert len(events) == 8
    assert all(event["attempt"] == i + 1 for i, event in enumerate(events))

def test_preflight_errors_are_evidence_not_silent_retry():
    probes = [None, {"error": "probe timed out"}, sample(), sample()]
    samples = iter(probes)
    events = []
    assert module.wait_until_stable(
        lambda: next(samples), "10.96.0.55", events.append,
        sleep=lambda _: None,
    )
    assert events[0]["probe"] is None
    assert events[1]["probe"] == {"error": "probe timed out"}
    assert len(events) == 4

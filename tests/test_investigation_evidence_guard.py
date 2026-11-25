import pytest

from agentic_aiops.investigation import Investigation
from agentic_aiops.models import Evidence, Hypothesis, Incident, VerificationStatus
from agentic_aiops.runner import InvestigationRunner
from agentic_aiops.tools import StaticReadTool


@pytest.mark.parametrize("refs", [[], ["missing"]])
def test_add_supported_hypothesis_requires_collected_evidence(refs):
    inv = Investigation(Incident("inc-1", "latency", "sev2"))
    inv.add_evidence(Evidence("known", "metrics", "high latency"))
    with pytest.raises(ValueError):
        inv.add_hypothesis(Hypothesis("h-1", "candidate", refs, VerificationStatus.SUPPORTED))
    assert inv.hypotheses == {}


def test_verify_supported_requires_evidence_and_preserves_previous_state():
    inv = Investigation(Incident("inc-1", "latency", "sev2"))
    inv.add_evidence(Evidence("known", "metrics", "high latency"))
    inv.add_hypothesis(Hypothesis("h-1", "candidate", ["known"]))
    with pytest.raises(ValueError):
        inv.verify("h-1", status=VerificationStatus.SUPPORTED, evidence_ids=[])
    assert inv.hypotheses["h-1"].status == VerificationStatus.UNVERIFIED
    assert inv.hypotheses["h-1"].evidence_ids == ["known"]


@pytest.mark.parametrize("refs", [[], ["missing"]])
def test_runner_rejects_supported_candidates_without_collected_evidence(refs):
    runner = InvestigationRunner(
        tools=[StaticReadTool("metrics", ["latency"])],
        hypothesis_fn=lambda _: [Hypothesis("h-1", "candidate", refs, VerificationStatus.SUPPORTED)],
    )
    with pytest.raises(ValueError):
        runner.run(Incident("inc-1", "latency", "sev2"))


def test_unverified_candidate_can_have_no_evidence():
    inv = Investigation(Incident("inc-1", "latency", "sev2"))
    inv.add_hypothesis(Hypothesis("h-1", "candidate"))
    assert inv.hypotheses["h-1"].status == VerificationStatus.UNVERIFIED
    inv.add_evidence(Evidence("known", "metrics", "high latency"))
    verified = inv.verify("h-1", status=VerificationStatus.SUPPORTED, evidence_ids=["known"])
    assert verified.evidence_ids == ["known"]
    assert verified.status == VerificationStatus.SUPPORTED

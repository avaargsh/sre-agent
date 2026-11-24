"""Static contract for the live EndpointSlice main-branch verification workflow."""
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "go-endpoint-kind.yml"


def test_endpoint_kind_workflow_keeps_exact_main_fallback_contract():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "push:\n    branches: [main]" in text
    assert "schedule:\n    - cron: '43 4 * * *'" in text
    assert 'test "$actual" = "${{ github.sha }}"' in text
    assert "go-endpoint-kind-proof-${{ github.sha }}" in text
    assert "bash demo/go-endpoint/run-kind.sh" in text

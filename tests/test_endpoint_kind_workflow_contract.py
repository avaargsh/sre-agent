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


def test_endpoint_kind_upload_requires_artifact_and_reverifies_download():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "if-no-files-found: error" in text
    assert "  artifact-roundtrip:\n    needs: endpoint-evidence" in text
    assert "uses: actions/download-artifact@v4" in text
    assert "name: go-endpoint-kind-proof-${{ github.sha }}" in text
    assert "path: ${{ runner.temp }}/endpoint-proof" in text
    assert 'test "$(git rev-parse HEAD)" = "${{ github.sha }}"' in text
    assert 'test -f "$RUNNER_TEMP/endpoint-proof/incident-manifest.json"' in text
    assert 'python3 demo/go-endpoint/incident_manifest.py verify "$RUNNER_TEMP/endpoint-proof"' in text

"""Static coverage requirements for the live Kind acceptance workflows."""
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def test_live_kind_workflows_cover_shared_go_dependencies():
    for filename in ("go-sli-kind.yml", "go-endpoint-kind.yml"):
        workflow = (WORKFLOWS / filename).read_text(encoding="utf-8")
        assert '      - "internal/**"' in workflow, filename
        assert '      - "go.mod"' in workflow, filename


def test_sli_kind_requires_all_three_verdicts_and_artifacts():
    workflow = (WORKFLOWS / "go-sli-kind.yml").read_text(encoding="utf-8")
    assert "test \"$STATUS\" -eq 4" in workflow
    assert "('/tmp/go-sli-unhealthy.json', 'UNHEALTHY')" in workflow
    assert "            /tmp/go-sli-unhealthy.json" in workflow
    assert "curl -fsS http://127.0.0.1:19090/-/ready >/dev/null" in workflow

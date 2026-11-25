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
    assert "python scripts/verify_sli_kind_evidence.py" in workflow
    assert '      - "scripts/verify_sli_kind_evidence.py"' in workflow
    assert '      - "tests/test_verify_sli_kind_evidence.py"' in workflow
    assert "            /tmp/go-sli-unhealthy.json" in workflow
    assert "\n          curl -fsS http://127.0.0.1:19090/-/ready >/dev/null\n" in workflow

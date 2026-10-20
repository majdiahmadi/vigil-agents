from datetime import datetime, timezone
from io import StringIO

from rich.console import Console

from vigil.cli.output import print_agent_result, print_case_history
from vigil.core.models import AgentResult, AgentStatus, ObservedFact, SecurityAssessment


def test_human_result_focuses_on_investigation_summary():
    stream = StringIO()
    target = Console(file=stream, force_terminal=False, width=100)
    now = datetime.now(timezone.utc)
    result = AgentResult(
        case_id="case-123",
        agent_id="triage",
        run_id="run-123",
        run_status=AgentStatus.COMPLETED,
        security_assessment=SecurityAssessment.SUSPICIOUS,
        model_provider="offline",
        model_id="deterministic-readonly-v1",
        observed_facts=[ObservedFact(statement="Three failed logins were observed.")],
        evidence_gaps=["Login authorization is unknown."],
        recommendations=["Ask the asset owner to confirm the login."],
        started_at=now,
        completed_at=now,
    )

    print_agent_result(result, target=target)
    output = stream.getvalue()

    assert "VIGIL  Triage" in output
    assert "SUSPICIOUS" in output
    assert "Three failed logins were observed." in output
    assert "Recommended next steps" in output
    assert '"case_id"' not in output


def test_empty_history_has_a_clear_message():
    stream = StringIO()
    target = Console(file=stream, force_terminal=False)

    print_case_history([], target=target)

    assert "No investigation history yet" in stream.getvalue()

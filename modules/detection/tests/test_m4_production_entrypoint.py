"""Focused tests for the M4 Phase 4 production orchestration entrypoint.

None of these tests execute the 1,380,057-record production materialization and
none writes to the canonical production report path. Every stage is either
monkeypatched or driven by a synthetic ``MaterializationOutcome`` built from the
*real* frozen M3 v2 per-partition evidence, and all publication targets live
under pytest ``tmp_path``.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
from uuid import uuid4

import pytest

import scripts.materialize_m4_canonical_events as entrypoint
from scripts.materialize_m4_canonical_events import (
    DEFAULT_REPORT_PATH,
    M4ConnectionError,
    M4ProductionRunError,
    M4PublicationFailedError,
    M4ReportAlreadyPublishedError,
    M4SchemaPreparationError,
    ProductionRunResult,
    build_parser,
    main,
    run_m4_production_materialization,
)

from modules.detection.src.persistence.materialization_v2 import (
    M4MaterializationError,
    MaterializationOutcome,
    _PartitionMaterializationResult,
)
from modules.detection.src.persistence.report_publication_v2 import (
    CANONICAL_M4_V2_REPORT_RELATIVE_PATH,
    M4ReportBuildError,
)
from modules.detection.src.persistence.report_verification_v2 import (
    M3ReportVerificationError,
    verify_frozen_m3_v2_report,
)
from modules.detection.src.schemas.zeek_normalization_run_v2 import (
    ZeekNormalizationRunReportV2,
)


ROOT = Path(__file__).resolve().parents[3]
STARTED = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)
COMPLETED = STARTED + timedelta(minutes=6)


@pytest.fixture(scope="module")
def verified_m3():
    return verify_frozen_m3_v2_report(ROOT)


def _synthetic_outcome(
    verified_m3,
    *,
    event_sha256: str | None = None,
    rejection_sha256: str | None = None,
) -> MaterializationOutcome:
    """Outcome mirroring the frozen per-partition evidence; never a real run."""
    report = verified_m3.report
    partition_results = tuple(
        _PartitionMaterializationResult(
            output_partition=pr.output_partition,
            source_log_sha256=pr.source_log_sha256,
            reported_record_count=pr.reported_record_count,
            processed_record_count=pr.processed_record_count,
            accepted_record_count=pr.accepted_record_count,
            rejected_record_count=pr.rejected_record_count,
            persisted_event_count=pr.accepted_record_count,
            event_stream_sha256=pr.canonical_event_stream_sha256,
            rejection_stream_sha256=pr.rejection_audit_stream_sha256,
        )
        for pr in report.partition_reports
    )
    event = (
        event_sha256
        if event_sha256 is not None
        else report.canonical_event_stream_sha256
    )
    rejection = (
        rejection_sha256
        if rejection_sha256 is not None
        else report.rejection_audit_stream_sha256
    )
    status = (
        "verified"
        if (
            event == report.canonical_event_stream_sha256
            and rejection == report.rejection_audit_stream_sha256
        )
        else "failed"
    )
    return MaterializationOutcome(
        run_id=uuid4(),
        verification_status=status,
        started_at=STARTED,
        completed_at=COMPLETED,
        total_processed_record_count=sum(
            i.processed_record_count for i in partition_results
        ),
        total_accepted_record_count=sum(
            i.accepted_record_count for i in partition_results
        ),
        total_rejected_record_count=sum(
            i.rejected_record_count for i in partition_results
        ),
        total_persisted_event_count=sum(
            i.persisted_event_count for i in partition_results
        ),
        materialized_event_stream_sha256=event,
        materialized_rejection_stream_sha256=rejection,
        partition_results=partition_results,
    )


class _FakeConnection:
    """Minimal stand-in; the orchestrator only needs close() here."""

    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeAdapter:
    def __init__(self, outcome: MaterializationOutcome | Exception) -> None:
        self._outcome = outcome

    def materialize(self, conn):  # noqa: ANN001
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


def _install_stages(
    monkeypatch,
    verified_m3,
    *,
    calls: list[str],
    outcome: MaterializationOutcome | Exception | None = None,
    schema_error: Exception | None = None,
    connection=None,
    verify_error: Exception | None = None,
):
    """Monkeypatch every orchestration stage and record invocation order."""

    def _verify(root):  # noqa: ANN001
        calls.append("verify")
        if verify_error is not None:
            raise verify_error
        return verified_m3

    def _get_connection(*args, **kwargs):  # noqa: ANN002, ANN003
        calls.append("connect")
        return connection

    def _ensure(conn):  # noqa: ANN001
        calls.append("schema")
        if schema_error is not None:
            raise schema_error

    def _bind(root):  # noqa: ANN001
        calls.append("bind")
        return object()

    def _adapter(root, bound, verified):  # noqa: ANN001
        calls.append("adapter")
        return _FakeAdapter(outcome)

    monkeypatch.setattr(entrypoint, "verify_frozen_m3_v2_report", _verify)
    monkeypatch.setattr(entrypoint, "get_connection", _get_connection)
    monkeypatch.setattr(entrypoint, "ensure_m4_schema", _ensure)
    monkeypatch.setattr(
        entrypoint, "load_and_bind_zeek_normalization_specification_v2", _bind
    )
    monkeypatch.setattr(entrypoint, "ZeekConnMaterializationAdapterV2", _adapter)


# --- 1 & 12. Successful orchestration ---------------------------------


def test_successful_orchestration_publishes_and_reports_success(
    monkeypatch, verified_m3, tmp_path
) -> None:
    calls: list[str] = []
    outcome = _synthetic_outcome(verified_m3)
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=calls,
        outcome=outcome,
        connection=_FakeConnection(),
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    result = run_m4_production_materialization(
        repository_root=ROOT, report_path=destination
    )

    assert isinstance(result, ProductionRunResult)
    assert result.status == "published"
    assert result.verification_status == "verified"
    assert result.run_id == outcome.run_id
    assert result.total_processed_record_count == 1_380_057
    assert result.total_accepted_record_count == 1_353_467
    assert result.total_rejected_record_count == 26_590
    assert result.total_persisted_event_count == 1_353_467

    # Success is only claimed after the file actually exists.
    assert destination.is_file()
    content = destination.read_bytes()
    assert sha256(content).hexdigest() == result.report_file_sha256

    # The published bytes round-trip to the same validated report identity.
    from modules.detection.src.persistence.run_report_v2 import (
        M4MaterializationReportV2,
    )

    reloaded = M4MaterializationReportV2.model_validate_json(content)
    assert reloaded.content_sha256() == result.report_content_sha256
    assert reloaded.run_id == outcome.run_id


def test_successful_orchestration_closes_connection(
    monkeypatch, verified_m3, tmp_path
) -> None:
    connection = _FakeConnection()
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=[],
        outcome=_synthetic_outcome(verified_m3),
        connection=connection,
    )
    run_m4_production_materialization(
        repository_root=ROOT,
        report_path=tmp_path / "m4_v2_materialization_run.json",
    )
    assert connection.closed is True


# --- 8. Correct stage ordering ----------------------------------------


def test_stage_ordering_is_verify_schema_materialize_build_publish(
    monkeypatch, verified_m3, tmp_path
) -> None:
    calls: list[str] = []
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=calls,
        outcome=_synthetic_outcome(verified_m3),
        connection=_FakeConnection(),
    )

    published: list[str] = []
    real_publish = entrypoint.write_immutable_materialization_report_v2

    def _tracked_publish(report, path):  # noqa: ANN001
        calls.append("publish")
        published.append(str(path))
        return real_publish(report, path)

    monkeypatch.setattr(
        entrypoint, "write_immutable_materialization_report_v2", _tracked_publish
    )

    run_m4_production_materialization(
        repository_root=ROOT,
        report_path=tmp_path / "m4_v2_materialization_run.json",
    )

    assert calls == ["verify", "connect", "schema", "bind", "adapter", "publish"]
    assert calls.index("verify") < calls.index("schema")
    assert calls.index("schema") < calls.index("adapter")
    assert calls.index("adapter") < calls.index("publish")
    assert len(published) == 1


# --- 2. Verification failure prevents materialization -----------------


def test_verification_failure_prevents_materialization(
    monkeypatch, verified_m3, tmp_path
) -> None:
    calls: list[str] = []
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=calls,
        outcome=_synthetic_outcome(verified_m3),
        connection=_FakeConnection(),
        verify_error=M3ReportVerificationError("frozen M3 v2 report file mismatch"),
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    with pytest.raises(M3ReportVerificationError):
        run_m4_production_materialization(
            repository_root=ROOT, report_path=destination
        )

    assert calls == ["verify"]
    assert "schema" not in calls and "adapter" not in calls
    assert not destination.exists()


# --- 3. Schema failure prevents materialization -----------------------


def test_schema_failure_prevents_materialization(
    monkeypatch, verified_m3, tmp_path
) -> None:
    calls: list[str] = []
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=calls,
        outcome=_synthetic_outcome(verified_m3),
        connection=_FakeConnection(),
        schema_error=RuntimeError("permission denied for schema m4_canonical"),
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    with pytest.raises(M4SchemaPreparationError, match="could not prepare"):
        run_m4_production_materialization(
            repository_root=ROOT, report_path=destination
        )

    assert calls == ["verify", "connect", "schema"]
    assert "adapter" not in calls
    assert not destination.exists()


def test_unreachable_database_prevents_materialization(
    monkeypatch, verified_m3, tmp_path
) -> None:
    calls: list[str] = []
    _install_stages(
        monkeypatch, verified_m3, calls=calls, outcome=None, connection=None
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    with pytest.raises(M4ConnectionError, match="unreachable"):
        run_m4_production_materialization(
            repository_root=ROOT, report_path=destination
        )

    assert calls == ["verify", "connect"]
    assert not destination.exists()


# --- 4. Materialization failure prevents report publication -----------


def test_materialization_failure_prevents_publication(
    monkeypatch, verified_m3, tmp_path
) -> None:
    calls: list[str] = []
    connection = _FakeConnection()
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=calls,
        outcome=M4MaterializationError(
            "materialized stream hashes do not match the frozen M3 v2 report"
        ),
        connection=connection,
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    with pytest.raises(M4MaterializationError, match="do not match"):
        run_m4_production_materialization(
            repository_root=ROOT, report_path=destination
        )

    assert not destination.exists()
    assert connection.closed is True


# --- 5. Report-build failure prevents publication ---------------------


def test_report_build_failure_prevents_publication(
    monkeypatch, verified_m3, tmp_path
) -> None:
    """A digest-mismatched outcome mislabelled 'verified' must not publish."""
    outcome = _synthetic_outcome(verified_m3, event_sha256="0" * 64)
    object.__setattr__(outcome, "verification_status", "verified")

    _install_stages(
        monkeypatch,
        verified_m3,
        calls=[],
        outcome=outcome,
        connection=_FakeConnection(),
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    with pytest.raises(M4ReportBuildError, match="disagrees with observed digests"):
        run_m4_production_materialization(
            repository_root=ROOT, report_path=destination
        )

    assert not destination.exists()


def test_digest_mismatch_never_publishes_verified_report(
    monkeypatch, verified_m3, tmp_path
) -> None:
    """A consistently-failed outcome publishes a 'failed' report, never 'verified'."""
    outcome = _synthetic_outcome(verified_m3, rejection_sha256="1" * 64)
    assert outcome.verification_status == "failed"

    _install_stages(
        monkeypatch,
        verified_m3,
        calls=[],
        outcome=outcome,
        connection=_FakeConnection(),
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    result = run_m4_production_materialization(
        repository_root=ROOT, report_path=destination
    )
    assert result.verification_status == "failed"
    payload = json.loads(destination.read_bytes())
    assert payload["verification_status"] == "failed"


# --- 6. Publication failure is surfaced explicitly --------------------


def test_publication_failure_is_surfaced_as_materialized_but_unpublished(
    monkeypatch, verified_m3, tmp_path
) -> None:
    outcome = _synthetic_outcome(verified_m3)
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=[],
        outcome=outcome,
        connection=_FakeConnection(),
    )

    def _boom(report, path):  # noqa: ANN001
        raise OSError("disk full")

    monkeypatch.setattr(
        entrypoint, "write_immutable_materialization_report_v2", _boom
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    with pytest.raises(M4PublicationFailedError) as captured:
        run_m4_production_materialization(
            repository_root=ROOT, report_path=destination
        )

    assert captured.value.run_id == outcome.run_id
    assert "is NOT complete" in str(captured.value)
    assert "recorded in PostgreSQL" in str(captured.value)
    assert not destination.exists()


# --- 7. Existing production report is never overwritten ---------------


def test_existing_report_is_refused_before_any_materialization(
    monkeypatch, verified_m3, tmp_path
) -> None:
    calls: list[str] = []
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=calls,
        outcome=_synthetic_outcome(verified_m3),
        connection=_FakeConnection(),
    )

    destination = tmp_path / "m4_v2_materialization_run.json"
    sentinel = b"EXISTING IMMUTABLE M4 EVIDENCE"
    destination.write_bytes(sentinel)

    with pytest.raises(M4ReportAlreadyPublishedError, match="will not be overwritten"):
        run_m4_production_materialization(
            repository_root=ROOT, report_path=destination
        )

    # Nothing ran at all, and the existing bytes are untouched.
    assert calls == []
    assert destination.read_bytes() == sentinel


# --- 11. Canonical production path ------------------------------------


def test_default_report_path_is_the_canonical_m4_path() -> None:
    assert CANONICAL_M4_V2_REPORT_RELATIVE_PATH == (
        "artifacts/reports/m4_v2_materialization_run.json"
    )
    assert DEFAULT_REPORT_PATH == ROOT / CANONICAL_M4_V2_REPORT_RELATIVE_PATH
    assert build_parser().get_default("report_path") == DEFAULT_REPORT_PATH


# --- 9. No production report created by tests -------------------------


def test_no_production_report_is_created_by_these_tests() -> None:
    assert not (ROOT / CANONICAL_M4_V2_REPORT_RELATIVE_PATH).exists()


# --- 10. Frozen M3 hashes unchanged -----------------------------------


def test_frozen_m3_hashes_remain_unchanged() -> None:
    path = ROOT / "artifacts/reports/m3_v2_normalization_run.json"
    payload = path.read_bytes()
    report = ZeekNormalizationRunReportV2.model_validate_json(payload)

    assert sha256(payload).hexdigest() == (
        "62426406249a96eb991a0c6bdcde78cd0b730afaa7de057d7740c2d5f62a8032"
    )
    assert report.content_sha256() == (
        "6c9ef7aa545769d0e4b913b1227dc27f43ab1734227f9afeb8d1d642264848e0"
    )
    assert report.protocol_sha256 == (
        "5286ddde937ad132afdeb8814e0e0af01745afbb7d1d446ae8860b7701fea210"
    )
    assert report.canonical_event_stream_sha256 == (
        "ce71a3401f606ecedac11007fdd9d649d32d10b969c53e961db6b96710b1d82f"
    )
    assert report.rejection_audit_stream_sha256 == (
        "b443b14c9894ea342b199e9c9880360a9cf3d00cf490164e7d2cf2f2d2f09b5f"
    )


# --- CLI surface ------------------------------------------------------


def test_main_returns_nonzero_and_reports_failure(
    monkeypatch, verified_m3, tmp_path, capsys
) -> None:
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=[],
        outcome=None,
        connection=None,
    )
    exit_code = main(
        [
            "--repository-root",
            str(ROOT),
            "--report-path",
            str(tmp_path / "m4_v2_materialization_run.json"),
        ]
    )
    assert exit_code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "failed"
    assert "unreachable" in payload["error"]


def test_main_returns_zero_and_prints_identities_on_success(
    monkeypatch, verified_m3, tmp_path, capsys
) -> None:
    _install_stages(
        monkeypatch,
        verified_m3,
        calls=[],
        outcome=_synthetic_outcome(verified_m3),
        connection=_FakeConnection(),
    )
    destination = tmp_path / "m4_v2_materialization_run.json"
    exit_code = main(
        ["--repository-root", str(ROOT), "--report-path", str(destination)]
    )
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "published"
    assert payload["verification_status"] == "verified"
    assert payload["total_processed_record_count"] == 1_380_057
    assert destination.is_file()


def test_entrypoint_does_not_duplicate_materialization_logic() -> None:
    """The entrypoint composes existing implementations; it re-implements none."""
    source = Path(entrypoint.__file__).read_text(encoding="utf-8")
    for forbidden in (
        "parse_line",
        "normalize_conn",
        "INSERT INTO m4_canonical",
        "CREATE SCHEMA",
        "os.replace",
    ):
        assert forbidden not in source, (
            f"entrypoint must not re-implement {forbidden!r}"
        )

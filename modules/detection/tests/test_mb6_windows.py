"""Contractual tests for MB6 Monday Benign feature windows.

CRITICAL: strictly read-only against PostgreSQL. MB4 and MB6 milestone data live
in ``cybersentinel_test``, the database also used for destructive test isolation.
A ``DELETE`` or ``TRUNCATE`` here would destroy the milestones -- the failure mode
that caused the M4 production data loss. Every database assertion is a ``SELECT``
issued on a connection with ``default_transaction_read_only = on``.
"""
from __future__ import annotations

import json
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from pydantic import ValidationError
import yaml

from modules.detection.src.feature_engineering.window_builder_v2 import (
    FeatureWindowBuilderV2,
)
from modules.detection.src.lineage.monday_benign_feature_window import (
    bind_monday_benign_feature_window_specification,
    load_and_bind_monday_benign_feature_window_specification,
    load_monday_benign_feature_window_specification,
)
from modules.detection.src.persistence.monday_benign_persistence import (
    get_monday_benign_connection,
)
from modules.detection.src.persistence.monday_benign_window_persistence import (
    MB6_DDL_FILE,
    MondayBenignWindowRunner,
    _strip_sql_comments,
    verify_mb6_schema,
)
from modules.detection.src.schemas.monday_benign_feature_window import (
    M6_WINDOW_ID_NAMESPACE,
    MB6_NAMESPACE_DERIVATION_NAME,
    MB6_PROTOCOL_RELATIVE_PATH,
    MB6_REPORT_RELATIVE_PATH,
    MB6_SCHEMA,
    MB6_WINDOW_ID_NAMESPACE,
    MondayBenignFeatureWindowRunReport,
    MondayBenignFeatureWindowSpecification,
    derive_mb6_run_id,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    M3_V2_EVENT_ID_NAMESPACE,
    MB3_EVENT_ID_NAMESPACE,
)
from modules.detection.src.schemas.monday_benign_replay import MONDAY_OUTPUT_PARTITION


REPO_ROOT = Path(__file__).resolve().parents[3]
PROTOCOL_PATH = REPO_ROOT / MB6_PROTOCOL_RELATIVE_PATH
REPORT_PATH = REPO_ROOT / MB6_REPORT_RELATIVE_PATH
M6_DDL = REPO_ROOT / "modules/detection/src/persistence/schema_m6.sql"
TEST_DATABASE = "cybersentinel_test"
PRODUCTION_DATABASE = "cybersentinel"

EXPECTED_WINDOWS = 70_921
EXPECTED_EVENTS = 368_202
EXPECTED_ENTITIES = 27_788

pytestmark = pytest.mark.skipif(
    not PROTOCOL_PATH.is_file() or not REPORT_PATH.is_file(),
    reason="MB6 protocol and report must be published for these tests",
)


def _database_available(database: str) -> bool:
    try:
        conn = get_monday_benign_connection(database, connect_timeout=3)
    except Exception:
        return False
    conn.close()
    return True


requires_db = pytest.mark.skipif(
    not _database_available(TEST_DATABASE),
    reason="PostgreSQL cybersentinel_test is unreachable",
)


@pytest.fixture()
def read_only_connection():
    """Yield a server-enforced read-only connection to the MB database."""
    conn = get_monday_benign_connection(TEST_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
        conn.commit()
        yield conn
    finally:
        conn.close()


@pytest.fixture(scope="module")
def specification() -> MondayBenignFeatureWindowSpecification:
    return load_monday_benign_feature_window_specification(PROTOCOL_PATH)


@pytest.fixture(scope="module")
def report() -> MondayBenignFeatureWindowRunReport:
    return MondayBenignFeatureWindowRunReport.model_validate_json(
        REPORT_PATH.read_text(encoding="utf-8")
    )


def _protocol_payload() -> dict:
    raw = yaml.safe_load(PROTOCOL_PATH.read_text(encoding="utf-8"))
    return json.loads(json.dumps(raw, default=str))


def _revalidate(payload: dict) -> MondayBenignFeatureWindowSpecification:
    return MondayBenignFeatureWindowSpecification.model_validate_json(
        json.dumps(payload, default=str)
    )


# --------------------------------------------------------------------------
# Namespace separation
# --------------------------------------------------------------------------


def test_mb6_namespace_is_deterministically_derived() -> None:
    assert MB6_WINDOW_ID_NAMESPACE == uuid5(
        NAMESPACE_URL, MB6_NAMESPACE_DERIVATION_NAME
    )
    assert MB6_WINDOW_ID_NAMESPACE == UUID("5cd6a350-cf38-5b3a-ab35-9b5128cdede3")


def test_mb6_namespace_differs_from_m6_m3_and_mb3() -> None:
    assert MB6_WINDOW_ID_NAMESPACE != M6_WINDOW_ID_NAMESPACE
    assert MB6_WINDOW_ID_NAMESPACE != M3_V2_EVENT_ID_NAMESPACE
    assert MB6_WINDOW_ID_NAMESPACE != MB3_EVENT_ID_NAMESPACE
    assert M6_WINDOW_ID_NAMESPACE == UUID("f787c08a-290e-5b79-a8cb-5bc19ae633dc")


def test_published_protocol_declares_the_mb6_namespace(
    specification: MondayBenignFeatureWindowSpecification,
) -> None:
    assert specification.identity.namespace == MB6_WINDOW_ID_NAMESPACE
    assert specification.identity.namespace_derivation == (
        MB6_NAMESPACE_DERIVATION_NAME
    )
    assert specification.identity.random_identifiers == "forbidden"


@pytest.mark.parametrize(
    "forbidden",
    (M6_WINDOW_ID_NAMESPACE, M3_V2_EVENT_ID_NAMESPACE, MB3_EVENT_ID_NAMESPACE),
    ids=("m6", "m3v2", "mb3"),
)
def test_protocol_rejects_a_foreign_namespace(forbidden: UUID) -> None:
    payload = _protocol_payload()
    payload["identity"]["namespace"] = str(forbidden)
    with pytest.raises(ValidationError):
        _revalidate(payload)


def test_protocol_rejects_a_namespace_inconsistent_with_its_derivation() -> None:
    payload = _protocol_payload()
    payload["identity"]["namespace_derivation"] = "https://example.invalid/other"
    with pytest.raises(ValidationError):
        _revalidate(payload)


# --------------------------------------------------------------------------
# Protocol locks and M6 semantic equivalence
# --------------------------------------------------------------------------


def test_protocol_is_monday_only_and_mb_scoped(
    specification: MondayBenignFeatureWindowSpecification,
) -> None:
    assert specification.milestone == "mb6"
    assert specification.track == "monday_benign"
    assert specification.output_partition == MONDAY_OUTPUT_PARTITION
    assert specification.operational_source == "mb4_canonical.flow_end_events"
    assert specification.evidence_source == "mb2_monday_conn_log_via_mb3_protocol"
    assert specification.m_chain_status == "untouched_and_frozen"
    assert specification.persistence.operational_projection == (
        "postgresql_schema_mb6_canonical"
    )
    assert specification.ordering.partition_order == (
        "mb3_replay_report_binding_order"
    )


def test_protocol_forbids_random_identifiers_and_wall_clock_identity(
    specification: MondayBenignFeatureWindowSpecification,
) -> None:
    """MB6 is stricter than M6, which permitted uuid4 run identity."""
    governance = specification.governance
    assert governance.random_identifiers == "forbidden"
    assert governance.wall_clock_in_identity == "forbidden"
    assert governance.run_identity_algorithm == (
        "deterministic_uuid5_over_protocol_and_mb4_run_id"
    )
    assert governance.run_identity_in_manifest is False


def test_protocol_preserves_the_frozen_m6_window_semantics(
    specification: MondayBenignFeatureWindowSpecification,
) -> None:
    """The reused policy blocks must be byte-identical to the frozen M6 manifest."""
    m6 = yaml.safe_load(
        (REPO_ROOT / "datasets/manifests/cicids2017_feature_window_v2.yaml").read_text(
            encoding="utf-8"
        )
    )
    mb6 = yaml.safe_load(PROTOCOL_PATH.read_text(encoding="utf-8"))
    for block in (
        "window_contract_versions",
        "temporal",
        "window",
        "entity",
        "features",
        "provenance",
        "labels",
        "deferred",
        "authoritative_sources",
    ):
        assert mb6[block] == m6[block], f"{block} diverges from the frozen M6 policy"
    assert specification.window.length_seconds == m6["window"]["length_seconds"]
    assert specification.temporal.float_conversion == "forbidden"
    assert specification.temporal.rounding == "forbidden"
    assert specification.temporal.truncation == "forbidden"
    assert specification.temporal.datetime_conversion == "forbidden"


def test_protocol_forbids_labels_in_the_window_contract(
    specification: MondayBenignFeatureWindowSpecification,
) -> None:
    assert specification.labels.label_fields_in_window_contract == "forbidden"
    assert specification.labels.m5_interaction == "none"


def test_protocol_rejects_a_foreign_partition() -> None:
    payload = _protocol_payload()
    payload["output_partition"] = "2017-07-04_Tuesday-WorkingHours"
    with pytest.raises(ValidationError):
        _revalidate(payload)


def test_protocol_rejects_a_foreign_dataset_name() -> None:
    payload = _protocol_payload()
    payload["dataset_name"] = "cicids2017_other"
    with pytest.raises(ValidationError):
        _revalidate(payload)


# --------------------------------------------------------------------------
# Deterministic run identity
# --------------------------------------------------------------------------


def test_run_id_is_deterministic_from_protocol_and_mb4_run(
    report: MondayBenignFeatureWindowRunReport,
) -> None:
    assert report.run_id == derive_mb6_run_id(
        report.protocol_sha256, report.mb4_run_id
    )
    assert derive_mb6_run_id(report.protocol_sha256, report.mb4_run_id) == (
        derive_mb6_run_id(report.protocol_sha256, report.mb4_run_id)
    )


def test_run_id_changes_when_upstream_evidence_changes(
    report: MondayBenignFeatureWindowRunReport,
) -> None:
    other = derive_mb6_run_id(report.protocol_sha256, UUID(int=1))
    assert other != report.run_id


def test_report_rejects_a_non_derived_run_id(
    report: MondayBenignFeatureWindowRunReport,
) -> None:
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    payload["run_id"] = str(UUID(int=2))
    with pytest.raises(ValidationError, match="deterministic derivation"):
        MondayBenignFeatureWindowRunReport.model_validate_json(json.dumps(payload))


# --------------------------------------------------------------------------
# Binding
# --------------------------------------------------------------------------


def test_published_protocol_binds_to_published_mb_evidence() -> None:
    bound = load_and_bind_monday_benign_feature_window_specification(REPO_ROOT)
    assert bound.output_partition == MONDAY_OUTPUT_PARTITION
    assert bound.expected_source_event_count == EXPECTED_EVENTS
    assert len(bound.protocol_sha256) == 64


@pytest.mark.parametrize(
    "field",
    (
        "mb1_manifest_sha256",
        "mb2_specification_sha256",
        "mb3_protocol_sha256",
        "mb4_report_content_sha256",
        "mb4_report_file_sha256",
    ),
)
def test_binding_rejects_a_substituted_upstream_hash(field: str) -> None:
    payload = _protocol_payload()
    payload[field] = "0" * 64
    specification = _revalidate(payload)
    with pytest.raises(ValueError, match="does not match|disagree"):
        bind_monday_benign_feature_window_specification(REPO_ROOT, specification)


def test_binding_rejects_a_substituted_mb4_run_id() -> None:
    payload = _protocol_payload()
    payload["mb4_run_id"] = str(UUID(int=3))
    specification = _revalidate(payload)
    with pytest.raises(ValueError, match="run identity"):
        bind_monday_benign_feature_window_specification(REPO_ROOT, specification)


def test_builder_accepts_the_derived_specification(
    specification: MondayBenignFeatureWindowSpecification,
) -> None:
    """The frozen M6 builder is reused unchanged on the derived MB6 protocol."""
    builder = FeatureWindowBuilderV2(specification)  # type: ignore[arg-type]
    assert builder.protocol_sha256 == specification.content_sha256()
    assert builder.window_length_unscaled == 60 * 10**22


# --------------------------------------------------------------------------
# Published report
# --------------------------------------------------------------------------


def test_published_report_is_internally_consistent(
    report: MondayBenignFeatureWindowRunReport,
) -> None:
    partition = report.partition_reports[0]
    assert report.verification_status == "verified"
    assert report.track == "monday_benign"
    assert report.target_schema == MB6_SCHEMA
    assert report.operational_source == "mb4_canonical.flow_end_events"
    assert report.window_id_namespace == MB6_WINDOW_ID_NAMESPACE
    assert report.total_window_count == EXPECTED_WINDOWS
    assert report.total_source_event_count == EXPECTED_EVENTS
    assert report.total_lineage_row_count == EXPECTED_EVENTS
    assert report.rejected_event_count == 0
    assert partition.output_partition == MONDAY_OUTPUT_PARTITION
    assert partition.entity_count == EXPECTED_ENTITIES
    assert partition.window_stream_sha256 == report.window_stream_sha256


def test_report_identity_excludes_wall_clock(
    report: MondayBenignFeatureWindowRunReport,
) -> None:
    payload = report.identity_payload()
    assert "started_at" not in payload
    assert "completed_at" not in payload
    assert "run_id" in payload, "the deterministic run identity stays in the digest"


def test_report_content_hash_is_reproducible(
    report: MondayBenignFeatureWindowRunReport,
) -> None:
    reloaded = MondayBenignFeatureWindowRunReport.model_validate_json(
        REPORT_PATH.read_text(encoding="utf-8")
    )
    assert reloaded == report
    assert reloaded.content_sha256() == report.content_sha256()


def test_report_rejects_lineage_that_does_not_cover_every_event() -> None:
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    payload["total_lineage_row_count"] = 1
    with pytest.raises(ValidationError, match="one row per source event"):
        MondayBenignFeatureWindowRunReport.model_validate_json(json.dumps(payload))


def test_report_rejects_a_foreign_namespace() -> None:
    payload = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    payload["window_id_namespace"] = str(M6_WINDOW_ID_NAMESPACE)
    with pytest.raises(ValidationError):
        MondayBenignFeatureWindowRunReport.model_validate_json(json.dumps(payload))


# --------------------------------------------------------------------------
# DDL
# --------------------------------------------------------------------------


def test_mb6_ddl_statements_never_reference_an_m_chain_schema() -> None:
    executable = _strip_sql_comments(MB6_DDL_FILE.read_text(encoding="utf-8"))
    assert "m4_canonical" not in executable
    assert "m6_canonical" not in executable
    assert "mb6_canonical" in executable


def test_mb6_ddl_preserves_the_m6_invariants() -> None:
    executable = _strip_sql_comments(MB6_DDL_FILE.read_text(encoding="utf-8"))
    assert executable.count("NUMERIC(38, 22) NOT NULL") == 4
    assert "CHECK (window_end_time - window_start_time = 60)" in executable
    assert "CHECK (prediction_time = window_end_time)" in executable
    assert "CHECK (mod(window_start_time, 60) = 0)" in executable
    assert "CHECK (event_count = source_event_count)" in executable
    assert "CHECK (late_event_count = 0)" in executable
    assert "CHECK (dropped_event_count = 0)" in executable
    assert "CHECK (is_final)" in executable
    assert "CHECK (NOT is_revision)" in executable
    assert "CHECK (entity_type = 'source_destination_service')" in executable
    assert "PRIMARY KEY (window_id, source_event_id)" in executable
    assert "WHERE status = 'verified'" in executable


def test_mb6_ddl_confines_windows_to_the_monday_partition() -> None:
    executable = _strip_sql_comments(MB6_DDL_FILE.read_text(encoding="utf-8"))
    assert (
        f"CHECK (output_partition = '{MONDAY_OUTPUT_PARTITION}')" in executable
    )


def test_mb6_ddl_declares_the_same_numeric_columns_as_m6() -> None:
    mb6 = _strip_sql_comments(MB6_DDL_FILE.read_text(encoding="utf-8"))
    m6 = _strip_sql_comments(M6_DDL.read_text(encoding="utf-8"))
    assert mb6.count("NUMERIC(38, 22) NOT NULL") == m6.count(
        "NUMERIC(38, 22) NOT NULL"
    )
    for column in (
        "window_start_time",
        "window_end_time",
        "prediction_time",
        "record_available_time",
    ):
        assert column in mb6 and column in m6


# --------------------------------------------------------------------------
# Read-only database assertions
# --------------------------------------------------------------------------


@requires_db
def test_schema_contract_verification_passes_on_the_live_schema(
    read_only_connection,
) -> None:
    verify_mb6_schema(read_only_connection)


@requires_db
def test_persisted_counts_match_the_published_report(
    read_only_connection, report: MondayBenignFeatureWindowRunReport
) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT (SELECT count(*) FROM {MB6_SCHEMA}.materialization_runs), "
            f"(SELECT count(*) FROM {MB6_SCHEMA}.feature_windows), "
            f"(SELECT count(*) FROM {MB6_SCHEMA}.feature_window_sources)"
        )
        runs, windows, lineage = cur.fetchone()
    assert runs == 1
    assert windows == report.total_window_count == EXPECTED_WINDOWS
    assert lineage == report.total_lineage_row_count == EXPECTED_EVENTS


@requires_db
def test_window_invariants_hold_for_every_row(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"""
            SELECT count(*),
                   count(*) FILTER (WHERE window_end_time - window_start_time = 60),
                   count(*) FILTER (WHERE prediction_time = window_end_time),
                   count(*) FILTER (WHERE mod(window_start_time, 60) = 0),
                   count(*) FILTER (WHERE event_count = source_event_count),
                   count(*) FILTER (WHERE late_event_count = 0
                                      AND dropped_event_count = 0),
                   count(*) FILTER (WHERE is_final AND NOT is_revision),
                   count(*) FILTER (WHERE scale(window_start_time) = 22
                                      AND scale(window_end_time) = 22
                                      AND scale(prediction_time) = 22),
                   count(DISTINCT output_partition)
            FROM {MB6_SCHEMA}.feature_windows
            """
        )
        row = cur.fetchone()
    total = row[0]
    assert total == EXPECTED_WINDOWS
    for value in row[1:8]:
        assert value == total
    assert row[8] == 1


@requires_db
def test_every_window_is_the_monday_partition(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT DISTINCT output_partition FROM {MB6_SCHEMA}.feature_windows"
        )
        partitions = [row[0] for row in cur.fetchall()]
    assert partitions == [MONDAY_OUTPUT_PARTITION]


@requires_db
def test_lineage_is_bijective_with_mb4_events(read_only_connection) -> None:
    """Every MB4 event appears exactly once across MB6 windows."""
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"""
            SELECT (SELECT count(*) FROM {MB6_SCHEMA}.feature_window_sources),
                   (SELECT count(DISTINCT source_event_id)
                      FROM {MB6_SCHEMA}.feature_window_sources),
                   (SELECT count(*) FROM mb4_canonical.flow_end_events),
                   (SELECT count(*) FROM {MB6_SCHEMA}.feature_window_sources s
                      WHERE NOT EXISTS (
                          SELECT 1 FROM mb4_canonical.flow_end_events e
                          WHERE e.event_id = s.source_event_id))
            """
        )
        lineage, distinct_sources, mb4_events, orphans = cur.fetchone()
    assert lineage == distinct_sources == mb4_events == EXPECTED_EVENTS
    assert orphans == 0


@requires_db
def test_no_window_id_collides_with_the_m_chain(read_only_connection) -> None:
    """Complete set intersection, not a sample."""
    with read_only_connection.cursor() as cur:
        cur.execute(f"SELECT window_id FROM {MB6_SCHEMA}.feature_windows")
        mb6_windows = {row[0] for row in cur.fetchall()}
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute("SELECT window_id FROM m6_canonical.feature_windows")
            m6_windows = {row[0] for row in cur.fetchall()}
            cur.execute(
                "SELECT DISTINCT source_event_id "
                "FROM m6_canonical.feature_window_sources"
            )
            m6_sources = {row[0] for row in cur.fetchall()}
    finally:
        conn.close()
    assert len(mb6_windows) == EXPECTED_WINDOWS
    assert len(m6_windows) == 172_748
    assert not (mb6_windows & m6_windows)
    assert not (mb6_windows & m6_sources)


@requires_db
def test_no_foreign_key_leaves_mb6_canonical(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            """
            SELECT c.conname, n.nspname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.confrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            WHERE c.contype = 'f'
              AND c.conrelid IN (
                  SELECT oid FROM pg_class
                  WHERE relnamespace = %s::regnamespace
              )
            """,
            (MB6_SCHEMA,),
        )
        foreign = cur.fetchall()
    assert foreign
    for name, schema in foreign:
        assert schema == MB6_SCHEMA, f"{name} escapes to {schema}"


@requires_db
def test_the_run_row_is_verified_and_deterministically_identified(
    read_only_connection, report: MondayBenignFeatureWindowRunReport
) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            f"SELECT run_id, status, total_source_event_count, "
            f"total_window_count, window_stream_sha256, mb6_window_id_namespace, "
            f"mb4_run_id FROM {MB6_SCHEMA}.materialization_runs"
        )
        rows = cur.fetchall()
    assert len(rows) == 1
    run_id, status, events, windows, digest, namespace, mb4_run = rows[0]
    assert status == "verified"
    assert run_id == report.run_id
    assert events == EXPECTED_EVENTS
    assert windows == EXPECTED_WINDOWS
    assert digest == report.window_stream_sha256
    assert namespace == MB6_WINDOW_ID_NAMESPACE
    assert mb4_run == report.mb4_run_id


@requires_db
def test_recompute_reproduces_the_published_digest(read_only_connection) -> None:
    """Determinism proven against the live projection, writing nothing."""
    bound = load_and_bind_monday_benign_feature_window_specification(REPO_ROOT)
    runner = MondayBenignWindowRunner(bound, TEST_DATABASE)
    outcome = runner.recompute_only(read_only_connection)
    report = MondayBenignFeatureWindowRunReport.model_validate_json(
        REPORT_PATH.read_text(encoding="utf-8")
    )
    assert outcome.window_count == report.total_window_count
    assert outcome.source_event_count == report.total_source_event_count
    assert outcome.window_stream_sha256 == report.window_stream_sha256
    assert outcome.run_id == str(report.run_id)


@requires_db
def test_a_second_verified_run_is_impossible(read_only_connection) -> None:
    with read_only_connection.cursor() as cur:
        cur.execute(
            "SELECT indexdef FROM pg_indexes "
            "WHERE schemaname = %s AND indexname = 'ux_mb6_runs_verified_protocol'",
            (MB6_SCHEMA,),
        )
        row = cur.fetchone()
    assert row is not None
    assert "UNIQUE" in row[0]
    assert "verified" in row[0]


@requires_db
def test_production_database_holds_no_mb_schema() -> None:
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema LIKE 'mb%'"
            )
            assert cur.fetchone()[0] == 0
    finally:
        conn.close()


@requires_db
def test_m_chain_counters_are_untouched() -> None:
    conn = get_monday_benign_connection(PRODUCTION_DATABASE)
    try:
        with conn.cursor() as cur:
            cur.execute("SET default_transaction_read_only = on")
            cur.execute(
                "SELECT (SELECT count(*) FROM m4_canonical.flow_end_events), "
                "(SELECT count(*) FROM m6_canonical.feature_windows), "
                "(SELECT count(*) FROM m6_canonical.feature_window_sources)"
            )
            events, windows, lineage = cur.fetchone()
    finally:
        conn.close()
    assert events == 1_353_467
    assert windows == 172_748
    assert lineage == 1_353_467


# --------------------------------------------------------------------------
# Isolation of the MB6 sources
# --------------------------------------------------------------------------


MB6_SOURCE_FILES = (
    Path("modules/detection/src/schemas/monday_benign_feature_window.py"),
    Path("modules/detection/src/lineage/monday_benign_feature_window.py"),
    Path("modules/detection/src/persistence/monday_benign_window_persistence.py"),
)


def _code_only(path: Path) -> str:
    """Return module source with the module docstring and comments removed.

    The MB6 sources deliberately quote ``m4_canonical.flow_end_events`` and
    ``postgresql_schema_m6_canonical`` in their module docstrings, to record
    exactly which M6 literals block reuse. Those mentions are documentation, not
    references, so the isolation checks below must inspect executable code.
    """
    import ast

    source = (REPO_ROOT / path).read_text(encoding="utf-8")
    tree = ast.parse(source)
    lines = source.splitlines()
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        first = tree.body[0].lineno - 1
        last = tree.body[0].end_lineno or tree.body[0].lineno
        lines = lines[:first] + lines[last:]
    stripped = []
    for line in lines:
        marker = line.find("#")
        stripped.append(line if marker == -1 else line[:marker])
    return "\n".join(stripped)


@pytest.mark.parametrize("source", MB6_SOURCE_FILES, ids=lambda p: p.name)
def test_mb6_sources_never_qualify_an_m_chain_table(source: Path) -> None:
    code = _code_only(source)
    assert "m4_canonical." not in code
    assert "m6_canonical." not in code


def test_mb6_never_reads_the_pcap_or_zeek_logs() -> None:
    """MB4 is the canonical source; MB6 must not reopen upstream evidence."""
    for source in MB6_SOURCE_FILES:
        code = _code_only(source)
        assert "conn.log" not in code
        assert ".pcap" not in code


def test_mb6_remains_independent_of_mb_label() -> None:
    """MB6 must not depend on MB-LABEL, even though MB7 now exists.

    Before MB-LABEL this test asserted that the labeling script and lineage module
    were absent. MB7 created both on 2026-08-13, so that form became false by
    design -- the same failure mode as the obsolete `test_no_production...` M4
    guards. The surviving intent is that the dependency runs one way only: MB7
    reads MB6, never the reverse, and no label ever enters the window contract.
    """
    for source in MB6_SOURCE_FILES:
        code = _code_only(source)
        assert "mb7_canonical" not in code
        assert "monday_benign_labeling" not in code
        assert "monday_benign_label_persistence" not in code
    mb6_ddl = (
        REPO_ROOT / "modules/detection/src/persistence/schema_mb6.sql"
    ).read_text(encoding="utf-8")
    for forbidden in ("disposition", "benign_reference", "attack_family", "label"):
        assert forbidden not in mb6_ddl

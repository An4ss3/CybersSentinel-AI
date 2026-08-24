"""Contractual tests for MB3 Monday Benign exact-time normalization.

Tests are read-only with respect to the repository: they never publish an
artifact, never write to PostgreSQL, and never modify M chain evidence. A few
tests read the real published MB3 protocol and the real Monday ``conn.log``, but
only far enough to reach the first accepted record.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid5

import pytest
from pydantic import ValidationError
import yaml

from modules.detection.src.ingestion.zeek_json_v2 import StrictZeekJsonLineParserV2
from modules.detection.src.lineage.monday_benign_normalization import (
    bind_monday_benign_normalization_specification,
    load_and_bind_monday_benign_normalization_specification,
    load_monday_benign_normalization_specification,
)
from modules.detection.src.normalization.zeek_conn_v2 import (
    StrictZeekConnFlowEndNormalizerV2,
    ZeekRecordRejectionV2,
)
from modules.detection.src.schemas.monday_benign_normalization import (
    M3_V2_EVENT_ID_NAMESPACE,
    M6_WINDOW_ID_NAMESPACE,
    MB3_EVENT_ID_NAMESPACE,
    MB3_NAMESPACE_DERIVATION_NAME,
    MB3_PROTOCOL_RELATIVE_PATH,
    MB3_REPORT_RELATIVE_PATH,
    MB_DATASET_NAME,
    MondayBenignEvidenceProfile,
    MondayBenignNormalizationRunReport,
    MondayBenignNormalizationSpecification,
    MondayBenignProvenancePolicy,
)
from modules.detection.src.schemas.monday_benign_replay import (
    M2_FROZEN_OUTPUT_ROOT,
    MB2_OUTPUT_ROOT,
    MONDAY_OUTPUT_PARTITION,
)
from modules.detection.src.schemas.zeek_normalization import ZeekSourceCoordinate
from modules.detection.src.schemas.zeek_normalization_v2 import (
    ZeekNormalizationContextV2,
)


REPO_ROOT = Path(__file__).resolve().parents[3]
PROTOCOL_PATH = REPO_ROOT / MB3_PROTOCOL_RELATIVE_PATH
REPORT_PATH = REPO_ROOT / MB3_REPORT_RELATIVE_PATH

pytestmark = pytest.mark.skipif(
    not PROTOCOL_PATH.is_file() or not REPORT_PATH.is_file(),
    reason="MB3 protocol and report must be published for these tests",
)


@pytest.fixture(scope="module")
def specification() -> MondayBenignNormalizationSpecification:
    return load_monday_benign_normalization_specification(PROTOCOL_PATH)


@pytest.fixture(scope="module")
def report() -> MondayBenignNormalizationRunReport:
    return MondayBenignNormalizationRunReport.model_validate_json(
        REPORT_PATH.read_text(encoding="utf-8")
    )


def _payload() -> dict:
    raw = yaml.safe_load(PROTOCOL_PATH.read_text(encoding="utf-8"))
    return json.loads(json.dumps(raw, default=str))


def _revalidate(payload: dict) -> MondayBenignNormalizationSpecification:
    return MondayBenignNormalizationSpecification.model_validate_json(
        json.dumps(payload, default=str)
    )


# --------------------------------------------------------------------------
# Namespace separation from the M chain
# --------------------------------------------------------------------------


def test_mb3_namespace_is_deterministically_derived() -> None:
    assert MB3_EVENT_ID_NAMESPACE == uuid5(
        NAMESPACE_URL, MB3_NAMESPACE_DERIVATION_NAME
    )
    assert MB3_EVENT_ID_NAMESPACE == UUID("c81ae3e0-7738-5413-80f2-8c2755418232")


def test_mb3_namespace_differs_from_every_m_chain_namespace() -> None:
    assert MB3_EVENT_ID_NAMESPACE != M3_V2_EVENT_ID_NAMESPACE
    assert MB3_EVENT_ID_NAMESPACE != M6_WINDOW_ID_NAMESPACE
    assert M3_V2_EVENT_ID_NAMESPACE == UUID("f7dad188-04cb-5859-81a0-014329de2899")
    assert M6_WINDOW_ID_NAMESPACE == UUID("f787c08a-290e-5b79-a8cb-5bc19ae633dc")


def test_published_protocol_declares_the_mb3_namespace(
    specification: MondayBenignNormalizationSpecification,
) -> None:
    assert specification.provenance.event_id_namespace == MB3_EVENT_ID_NAMESPACE
    assert specification.provenance.event_id_namespace_derivation == (
        MB3_NAMESPACE_DERIVATION_NAME
    )


@pytest.mark.parametrize(
    "forbidden",
    (M3_V2_EVENT_ID_NAMESPACE, M6_WINDOW_ID_NAMESPACE),
    ids=("m3v2", "m6"),
)
def test_provenance_policy_rejects_m_chain_namespaces(forbidden: UUID) -> None:
    with pytest.raises(ValidationError):
        MondayBenignProvenancePolicy(
            event_id_algorithm="uuid5",
            event_id_namespace=forbidden,
            event_id_namespace_derivation=MB3_NAMESPACE_DERIVATION_NAME,
            event_id_components=(
                "protocol_sha256",
                "replay_report_content_sha256",
                "source_log_sha256",
                "output_partition",
                "log_name",
                "physical_line_number",
            ),
            event_id_name_encoding=(
                "utf8_component_values_joined_by_single_ascii_pipe_"
                "line_number_base10"
            ),
            sensor_id="zeek",
            sensor_run_id_source="replay_report_content_sha256",
            capture_id_source="input_pcap_sha256",
            dataset_snapshot_id_source="m1_manifest_sha256",
            model_release_id_policy="explicit_null",
        )


def test_protocol_rejects_a_substituted_namespace() -> None:
    payload = _payload()
    payload["provenance"]["event_id_namespace"] = str(M3_V2_EVENT_ID_NAMESPACE)
    with pytest.raises(ValidationError):
        _revalidate(payload)


def test_protocol_rejects_a_namespace_inconsistent_with_its_derivation() -> None:
    payload = _payload()
    payload["provenance"]["event_id_namespace_derivation"] = (
        "https://cybersentinel.invalid/mb3/tampered"
    )
    with pytest.raises(ValidationError):
        _revalidate(payload)


# --------------------------------------------------------------------------
# Specification locks
# --------------------------------------------------------------------------


def test_published_protocol_is_monday_only(
    specification: MondayBenignNormalizationSpecification,
) -> None:
    assert len(specification.replay_reports) == 1
    assert specification.output_partition == MONDAY_OUTPUT_PARTITION
    assert specification.mb2_output_root == MB2_OUTPUT_ROOT
    assert specification.m2_output_root == MB2_OUTPUT_ROOT
    assert specification.dataset_name == MB_DATASET_NAME
    assert specification.track == "monday_benign"


def test_protocol_rejects_a_second_partition() -> None:
    payload = _payload()
    payload["replay_reports"] = payload["replay_reports"] * 2
    with pytest.raises(ValidationError):
        _revalidate(payload)


@pytest.mark.parametrize(
    "bad_root",
    (
        M2_FROZEN_OUTPUT_ROOT,
        f"{M2_FROZEN_OUTPUT_ROOT}/2017-07-03_Monday-WorkingHours",
        "artifacts/canonical/cicids2017/mb2",
    ),
)
def test_protocol_rejects_a_non_mb2_output_root(bad_root: str) -> None:
    payload = _payload()
    payload["mb2_output_root"] = bad_root
    with pytest.raises(ValidationError):
        _revalidate(payload)


def test_protocol_rejects_a_replay_report_outside_the_mb2_root() -> None:
    payload = _payload()
    payload["replay_reports"][0]["report_relative_path"] = (
        f"{M2_FROZEN_OUTPUT_ROOT}/2017-07-04_Tuesday-WorkingHours/replay_run.json"
    )
    with pytest.raises(ValidationError):
        _revalidate(payload)


def test_protocol_rejects_a_foreign_dataset_name() -> None:
    payload = _payload()
    payload["dataset_name"] = "cicids2017_other"
    with pytest.raises(ValidationError):
        _revalidate(payload)


def test_protocol_reuses_the_frozen_conn_log_mapping(
    specification: MondayBenignNormalizationSpecification,
) -> None:
    """MB3 must map conn.log to FlowEndV2 with M3 v2 semantics, unchanged."""
    mapping = specification.log_mappings[0]
    assert mapping.log_name == "conn.log"
    assert mapping.target_model == "FlowEndV2"
    assert mapping.unknown_field_policy == "reject_record"
    assert specification.temporal.float_conversion == "forbidden"
    assert specification.temporal.rounding == "forbidden"
    assert specification.temporal.truncation == "forbidden"
    assert specification.temporal.arithmetic == "unscaled_integer"
    assert specification.event_envelope.versions.feature_version == "1.0.0"


# --------------------------------------------------------------------------
# Evidence profile
# --------------------------------------------------------------------------


def test_evidence_profile_matches_the_measured_prescan(
    specification: MondayBenignNormalizationSpecification,
    report: MondayBenignNormalizationRunReport,
) -> None:
    profile = specification.evidence
    assert profile.measurement_method == "read_only_lexical_prescan"
    assert profile.scanned_record_count == 375_432
    assert profile.records_with_duration == 368_708
    # The pre-scan line count must agree with the MB2 replay record count.
    assert profile.scanned_record_count == (
        report.partition_reports[0].reported_record_count
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("timestamp_max_significant_digits", 39),
        ("exact_end_max_significant_digits", 39),
        ("timestamp_max_fractional_digits", 23),
        ("duration_max_fractional_digits", 23),
    ),
)
def test_evidence_profile_rejects_values_outside_decimal_38_22(
    field: str, value: int
) -> None:
    payload = {
        "measurement_method": "read_only_lexical_prescan",
        "scanned_record_count": 375_432,
        "records_with_duration": 368_708,
        "timestamp_max_significant_digits": 17,
        "timestamp_max_fractional_digits": 7,
        "duration_max_significant_digits": 22,
        "duration_max_fractional_digits": 22,
        "exact_end_max_significant_digits": 28,
        "exact_end_max_fractional_digits": 18,
        "canonical_type": "DECIMAL(38,22)",
    }
    payload[field] = value
    with pytest.raises(ValidationError):
        MondayBenignEvidenceProfile.model_validate(payload)


def test_evidence_profile_rejects_more_durations_than_records() -> None:
    with pytest.raises(ValidationError):
        MondayBenignEvidenceProfile(
            measurement_method="read_only_lexical_prescan",
            scanned_record_count=10,
            records_with_duration=11,
            timestamp_max_significant_digits=17,
            timestamp_max_fractional_digits=7,
            duration_max_significant_digits=22,
            duration_max_fractional_digits=22,
            exact_end_max_significant_digits=28,
            exact_end_max_fractional_digits=18,
            canonical_type="DECIMAL(38,22)",
        )


# --------------------------------------------------------------------------
# Binding integrity
# --------------------------------------------------------------------------


def test_published_protocol_binds_to_published_mb_evidence() -> None:
    bound = load_and_bind_monday_benign_normalization_specification(REPO_ROOT)
    assert bound.output_partition == MONDAY_OUTPUT_PARTITION
    assert bound.reported_record_count == 375_432
    assert len(bound.specification_sha256) == 64


@pytest.mark.parametrize(
    "mutation",
    (
        {"m1_manifest_sha256": "0" * 64},
        {"mb2_specification_sha256": "1" * 64},
    ),
    ids=("mb1_hash", "mb2_spec_hash"),
)
def test_binding_rejects_a_substituted_upstream_hash(mutation: dict) -> None:
    payload = _payload()
    payload.update(mutation)
    specification = _revalidate(payload)
    with pytest.raises(ValueError, match="does not match"):
        bind_monday_benign_normalization_specification(REPO_ROOT, specification)


@pytest.mark.parametrize(
    "field",
    ("report_file_sha256", "report_content_sha256"),
)
def test_binding_rejects_a_substituted_replay_report_hash(field: str) -> None:
    payload = _payload()
    payload["replay_reports"][0][field] = "2" * 64
    specification = _revalidate(payload)
    with pytest.raises(ValueError, match="does not match"):
        bind_monday_benign_normalization_specification(REPO_ROOT, specification)


def test_binding_rejects_a_divergent_conn_log_artifact() -> None:
    payload = _payload()
    payload["replay_reports"][0]["supported_log"]["record_count"] = 1
    specification = _revalidate(payload)
    with pytest.raises(ValueError, match="diverges"):
        bind_monday_benign_normalization_specification(REPO_ROOT, specification)


# --------------------------------------------------------------------------
# event_id determinism, proven against real published evidence
# --------------------------------------------------------------------------


def test_first_accepted_event_id_is_reproducible_from_the_uuid5_formula(
    report: MondayBenignNormalizationRunReport,
) -> None:
    """Recompute the first accepted event_id end to end from published bytes."""
    bound = load_and_bind_monday_benign_normalization_specification(REPO_ROOT)
    specification = bound.specification
    binding = specification.replay_reports[0]
    artifact = binding.supported_log
    conn_log = (
        REPO_ROOT
        / specification.mb2_output_root
        / binding.output_partition
        / artifact.log_name
    )
    parser = StrictZeekJsonLineParserV2()
    normalizer = StrictZeekConnFlowEndNormalizerV2(specification)
    partition_report = report.partition_reports[0]

    with conn_log.open("rb") as stream:
        for line_number, line in enumerate(stream, start=1):
            source = ZeekSourceCoordinate(
                output_partition=binding.output_partition,
                replay_report_content_sha256=binding.report_content_sha256,
                log_name="conn.log",
                source_log_sha256=artifact.sha256,
                reported_record_count=artifact.record_count,
                physical_line_number=line_number,
            )
            context = ZeekNormalizationContextV2(
                protocol_sha256=bound.specification_sha256,
                source=source,
                record_available_time=report.record_available_time,
                ingested_at=report.ingested_at,
            )
            try:
                record = parser.parse_line(line, source)
                event = normalizer.normalize_conn(record, context)
            except ZeekRecordRejectionV2:
                continue
            break
        else:  # pragma: no cover - the published run accepted 368,202 records
            pytest.fail("no accepted record found in the Monday conn.log")

    expected_name = "|".join(
        (
            bound.specification_sha256,
            binding.report_content_sha256,
            artifact.sha256,
            binding.output_partition,
            "conn.log",
            str(line_number),
        )
    )
    expected_id = uuid5(MB3_EVENT_ID_NAMESPACE, expected_name)

    assert event.provenance.event_id == expected_id
    assert event.provenance.event_id == partition_report.first_accepted_event_id
    # The same name under an M chain namespace yields a different identity.
    assert uuid5(M3_V2_EVENT_ID_NAMESPACE, expected_name) != expected_id
    assert uuid5(M6_WINDOW_ID_NAMESPACE, expected_name) != expected_id


def test_event_identity_cannot_collide_with_the_m_chain_by_construction(
    specification: MondayBenignNormalizationSpecification,
) -> None:
    """Four of six name components already differ from any M chain event.

    Collision is impossible before the namespace change is even considered:
    the protocol hash, the replay report hash, the source log hash and the
    partition name are all MB-specific.
    """
    binding = specification.replay_reports[0]
    m3_report = json.loads(
        (REPO_ROOT / "artifacts/reports/m3_v2_normalization_run.json").read_text(
            encoding="utf-8"
        )
    )
    m3_partitions = {
        item["output_partition"] for item in m3_report["partition_reports"]
    }
    m3_source_logs = {
        item["source_log_sha256"] for item in m3_report["partition_reports"]
    }
    m3_replay_reports = {
        item["replay_report_content_sha256"]
        for item in m3_report["partition_reports"]
    }

    assert binding.output_partition not in m3_partitions
    assert binding.supported_log.sha256 not in m3_source_logs
    assert binding.report_content_sha256 not in m3_replay_reports
    assert specification.content_sha256() != m3_report["protocol_sha256"]


# --------------------------------------------------------------------------
# Published run report
# --------------------------------------------------------------------------


def test_published_report_is_internally_consistent(
    report: MondayBenignNormalizationRunReport,
) -> None:
    partition = report.partition_reports[0]
    assert report.track == "monday_benign"
    assert report.verification_status == "verified"
    assert report.event_id_namespace == MB3_EVENT_ID_NAMESPACE
    assert report.total_processed_record_count == 375_432
    assert report.total_accepted_record_count == 368_202
    assert report.total_rejected_record_count == 7_230
    assert partition.processed_record_count == partition.reported_record_count
    assert (
        partition.accepted_record_count + partition.rejected_record_count
        == partition.processed_record_count
    )
    assert sum(item.count for item in partition.rejection_counts) == 7_230
    assert sum(item.record_count for item in partition.rejection_spans) == 7_230


def test_published_report_content_hash_is_reproducible(
    report: MondayBenignNormalizationRunReport,
) -> None:
    reloaded = MondayBenignNormalizationRunReport.model_validate_json(
        REPORT_PATH.read_text(encoding="utf-8")
    )
    assert reloaded == report
    assert reloaded.content_sha256() == report.content_sha256()
    assert report.content_sha256() == (
        "de3146976148dc1d61e5690d6eb7b6acc6a446130787964d3b1bb4888c5ec6ab"
    )


def test_report_rejects_totals_that_disagree_with_the_partition(
    report: MondayBenignNormalizationRunReport,
) -> None:
    payload = deepcopy(report.model_dump(mode="json"))
    payload["total_accepted_record_count"] = 1
    with pytest.raises(ValidationError):
        MondayBenignNormalizationRunReport.model_validate(payload)


def test_report_rejects_a_foreign_namespace(
    report: MondayBenignNormalizationRunReport,
) -> None:
    payload = deepcopy(report.model_dump(mode="json"))
    payload["event_id_namespace"] = str(M3_V2_EVENT_ID_NAMESPACE)
    with pytest.raises(ValidationError):
        MondayBenignNormalizationRunReport.model_validate(payload)


def test_rejection_reasons_are_only_the_observed_three(
    report: MondayBenignNormalizationRunReport,
) -> None:
    observed = {
        item.reason: item.count
        for item in report.partition_reports[0].rejection_counts
    }
    assert observed == {
        "missing_required_field": 6_724,
        "unsupported_service_cardinality": 343,
        "unsupported_transport": 163,
    }
    # Cross-check: every record without a duration is a missing-field rejection.
    profile_gap = 375_432 - 368_708
    assert observed["missing_required_field"] == profile_gap


# --------------------------------------------------------------------------
# Isolation
# --------------------------------------------------------------------------


MB3_SOURCE_FILES = (
    Path("modules/detection/src/schemas/monday_benign_normalization.py"),
    Path("modules/detection/src/lineage/monday_benign_normalization.py"),
    Path("modules/detection/src/normalization/monday_benign_pipeline.py"),
    Path("scripts/normalize_monday_benign_events.py"),
)


@pytest.mark.parametrize("source", MB3_SOURCE_FILES, ids=lambda p: p.name)
def test_mb3_sources_never_touch_canonical_databases(source: Path) -> None:
    text = (REPO_ROOT / source).read_text(encoding="utf-8")
    assert "m4_canonical" not in text
    assert "m6_canonical" not in text
    assert "psycopg" not in text
    assert "INSERT" not in text
    assert "CREATE SCHEMA" not in text


@pytest.mark.parametrize("source", MB3_SOURCE_FILES, ids=lambda p: p.name)
def test_mb3_sources_never_write_to_the_m2_tree(source: Path) -> None:
    """The frozen M2 root may appear only as a rejection constant or comment."""
    text = (REPO_ROOT / source).read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if M2_FROZEN_OUTPUT_ROOT not in line:
            continue
        stripped = line.strip()
        allowed = (
            stripped.startswith("M2_FROZEN_OUTPUT_ROOT")
            or stripped.startswith("#")
            or stripped.startswith("*")
            or stripped.startswith('"')
        )
        assert allowed, f"{source}:{line_number} uses the M2 root: {stripped}"


def test_frozen_m2_tree_still_holds_ninety_five_files() -> None:
    root = REPO_ROOT / M2_FROZEN_OUTPUT_ROOT
    assert root.is_dir()
    assert sum(1 for path in root.rglob("*") if path.is_file()) == 95


def test_mb3_remains_free_of_any_persistence_dependency() -> None:
    """MB3 must never persist, even though MB4 now exists.

    Before MB4 this test asserted that `schema_mb.sql` and
    `monday_benign_persistence.py` were absent. MB4 created both on 2026-08-13,
    so that form became false by design -- the same failure mode as the obsolete
    `test_no_production...` M4 guards. The surviving intent is that MB3 itself
    stays a pure hash-and-discard stage: none of its sources may import the
    persistence layer, a database driver, or the MB4 module.
    """
    for source in MB3_SOURCE_FILES:
        text = (REPO_ROOT / source).read_text(encoding="utf-8")
        assert "monday_benign_persistence" not in text
        assert "import psycopg" not in text
        assert "from psycopg" not in text
        assert "mb4_canonical" not in text

"""Non-regression tests for Production Finale v1.

The suite is split deliberately. Everything that can be proven without a
database runs unconditionally, so the label policy, the feature budget and the
serialisation contract are guarded even when PostgreSQL is unavailable. The
database-backed checks are read-only and skip cleanly when it is down.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

import pytest

from modules.detection.src.experiments.p1_dataset import (
    FEATURE_NAMES,
    FORBIDDEN_COLUMNS,
    Row,
)
from modules.detection.src.lineage.exact_time_labeling_v2 import (
    ATTACK_DISPOSITIONS,
    WINDOW_DISPOSITION_PRECEDENCE,
)
from modules.detection.src.production.ml_dataset import (
    DATASET_COLUMNS,
    EXCLUDED_DISPOSITIONS,
    EXCLUDED_M6_FEATURES,
    EXPECTED_ATTACK_TYPE_WINDOWS,
    EXPECTED_ATTACK_WINDOWS,
    EXPECTED_BENIGN_ROWS,
    EXPECTED_M6_WINDOWS,
    EXPECTED_MB6_WINDOWS,
    EXPECTED_MB7_WINDOW_LABELS,
    EXPECTED_M_AMBIGUOUS_WINDOWS,
    EXPECTED_M_UNKNOWN_WINDOWS,
    EXPECTED_P1_DATASET_CONTENT_SHA256,
    EXPECTED_P1_DATASET_FILE_SHA256,
    EXPECTED_TOTAL_ROWS,
    FORBIDDEN_CONTENT_FEATURES,
    LABEL_POLICY,
    WINDOW_LABEL_COLUMNS,
    ProductionDatasetError,
    WindowLabel,
    assert_never_benign,
    dataset_bytes,
    label_of,
    project_dataset_row,
    verify_policy_consistency,
    window_label_bytes,
    window_label_counts,
)

ROOT = Path(__file__).resolve().parents[3]
P1_DATASET = ROOT / "artifacts" / "experiments" / "p1" / "p1_dataset.csv"
OUT_DIR = ROOT / "artifacts" / "production" / "ml_dataset_v1"
MANIFEST = OUT_DIR / "dataset_manifest.json"


def row(
    row_id: str,
    label: int,
    disposition: str,
    *,
    source: str = "m6",
    attack_type: str | None = None,
    episode_id: str | None = None,
) -> Row:
    return Row(
        row_id=row_id,
        source=source,
        label=label,
        disposition=disposition,
        attack_type=attack_type,
        entity_key="10.0.0.1|10.0.0.2|tcp|http",
        episode_id=episode_id,
        partition="2017-07-04_Tuesday-WorkingHours",
        window_start_epoch=1_499_000_000,
        features=(1.0, 2.0, 3.0, 4.0, 5.0),
    )


# --------------------------------------------------------------- label policy


def test_label_policy_is_exactly_the_ratified_table() -> None:
    assert LABEL_POLICY == {
        "target_attack": 1,
        "known_other_attack": 1,
        "benign_reference": 0,
    }
    assert label_of("target_attack") == 1
    assert label_of("known_other_attack") == 1
    assert label_of("benign_reference") == 0
    assert label_of("unknown") is None
    assert label_of("ambiguous") is None


def test_unknown_and_ambiguous_are_excluded_never_negative() -> None:
    assert EXCLUDED_DISPOSITIONS == frozenset({"unknown", "ambiguous"})
    for disposition in EXCLUDED_DISPOSITIONS:
        assert disposition not in LABEL_POLICY
        with pytest.raises(ProductionDatasetError, match="forbidden conversion"):
            assert_never_benign(disposition, 0)


def test_an_excluded_disposition_cannot_reach_the_dataset() -> None:
    for disposition in ("unknown", "ambiguous"):
        with pytest.raises(ProductionDatasetError):
            project_dataset_row(row("x", 0, disposition))


def test_a_disposition_outside_the_frozen_vocabulary_raises() -> None:
    with pytest.raises(ProductionDatasetError, match="outside the frozen vocabulary"):
        label_of("benign")


def test_policy_covers_the_frozen_any_attack_vocabulary() -> None:
    assert set(LABEL_POLICY) | EXCLUDED_DISPOSITIONS == set(
        WINDOW_DISPOSITION_PRECEDENCE
    )
    assert {d for d, v in LABEL_POLICY.items() if v == 1} == set(ATTACK_DISPOSITIONS)


def test_a_label_disagreeing_with_the_policy_raises() -> None:
    with pytest.raises(ProductionDatasetError, match="label disagrees"):
        project_dataset_row(row("x", 0, "target_attack", attack_type="dos/hulk"))


def test_policy_consistency_checks_all_pass() -> None:
    checks = verify_policy_consistency()
    assert checks and all(check["passed"] for check in checks)


# ------------------------------------------------------------- feature budget


def test_feature_budget_is_exactly_the_five_p1_features_in_order() -> None:
    assert FEATURE_NAMES == (
        "event_count",
        "source_packets_total",
        "destination_packets_total",
        "source_bytes_total",
        "destination_bytes_total",
    )
    assert DATASET_COLUMNS[-5:] == FEATURE_NAMES


def test_degenerate_m6_features_are_excluded_and_forbidden() -> None:
    assert EXCLUDED_M6_FEATURES == (
        "distinct_destination_ports",
        "distinct_destination_ips",
        "distinct_source_ips",
    )
    for name in EXCLUDED_M6_FEATURES:
        assert name not in DATASET_COLUMNS
        assert name in FORBIDDEN_COLUMNS


def test_arm_f_content_features_are_absent_from_the_canonical_dataset() -> None:
    for name in FORBIDDEN_CONTENT_FEATURES:
        assert name not in DATASET_COLUMNS
    assert "distinct_payload_ratio" in FORBIDDEN_CONTENT_FEATURES


def test_a_non_canonical_feature_vector_raises() -> None:
    bad = Row(
        row_id="x",
        source="m6",
        label=1,
        disposition="target_attack",
        attack_type="dos/hulk",
        entity_key="a|b|tcp|http",
        episode_id="e",
        partition="p",
        window_start_epoch=1,
        features=(1.0, 2.0),
    )
    with pytest.raises(ProductionDatasetError, match="non-canonical feature vector"):
        project_dataset_row(bad)


# ------------------------------------------------------------- serialisation


def test_dataset_header_is_byte_identical_to_the_frozen_p1_header() -> None:
    published = P1_DATASET.open("rb").readline()
    assert published == (",".join(DATASET_COLUMNS) + "\n").encode("utf-8")


def test_serialisation_matches_the_frozen_p1_writer() -> None:
    payload = dataset_bytes(
        [
            row("b", 0, "benign_reference", source="mb6"),
            row("a", 1, "target_attack", attack_type="dos/hulk", episode_id="e|k|000"),
        ]
    )
    lines = payload.decode("utf-8").split("\n")
    assert lines[0] == ",".join(DATASET_COLUMNS)
    # Ordering is (label, row_id): the negative precedes the positive.
    assert lines[1].startswith("b,mb6,0,benign_reference,,")
    assert lines[2].startswith("a,m6,1,target_attack,dos/hulk,")
    # Empty metadata for benign rows, float rendering for features.
    assert lines[1].endswith(",1499000000,1.0,2.0,3.0,4.0,5.0")
    assert payload.endswith(b"\n")
    assert b"\r\n" not in payload


def test_window_label_artifact_marks_excluded_windows_explicitly() -> None:
    labels = [
        WindowLabel("w1", "p", "a|b|tcp|http", 60, "target_attack", "dos/hulk"),
        WindowLabel("w2", "p", "a|b|tcp|http", 120, "unknown", None),
        WindowLabel("w3", "p", "a|b|tcp|http", 180, "ambiguous", None),
    ]
    text = window_label_bytes(labels).decode("utf-8").split("\n")
    assert text[0] == ",".join(WINDOW_LABEL_COLUMNS)
    assert text[1].endswith(",target_attack,dos/hulk,1")
    assert text[2].endswith(",unknown,,excluded")
    assert text[3].endswith(",ambiguous,,excluded")
    assert all(label.dataset_label is None for label in labels[1:])


def test_window_label_counts_reject_an_unknown_disposition() -> None:
    with pytest.raises(ProductionDatasetError):
        window_label_counts(
            [WindowLabel("w", "p", "k", 60, "benign", None)]
        )


# ------------------------------------------------------------ frozen constants


def test_expected_counts_match_the_ratified_targets() -> None:
    assert EXPECTED_M6_WINDOWS == 172_748
    assert EXPECTED_MB6_WINDOWS == 70_921
    assert EXPECTED_MB7_WINDOW_LABELS == 70_921
    assert EXPECTED_ATTACK_WINDOWS == 376
    assert EXPECTED_BENIGN_ROWS == 70_578
    assert EXPECTED_TOTAL_ROWS == 70_954
    assert EXPECTED_M_UNKNOWN_WINDOWS == 172_372
    assert EXPECTED_M_AMBIGUOUS_WINDOWS == 0
    assert EXPECTED_ATTACK_WINDOWS + EXPECTED_M_UNKNOWN_WINDOWS == EXPECTED_M6_WINDOWS
    assert EXPECTED_ATTACK_WINDOWS + EXPECTED_BENIGN_ROWS == EXPECTED_TOTAL_ROWS
    assert sum(EXPECTED_ATTACK_TYPE_WINDOWS.values()) == EXPECTED_ATTACK_WINDOWS


def test_the_frozen_p1_artifact_is_unchanged() -> None:
    assert sha256(P1_DATASET.read_bytes()).hexdigest() == (
        EXPECTED_P1_DATASET_FILE_SHA256
    )


def test_published_p1_population_matches_the_expected_distribution() -> None:
    """Guard the target distribution using the frozen file, without a database."""
    counts: dict[str, int] = {}
    types: dict[str, int] = {}
    total = 0
    with P1_DATASET.open(encoding="utf-8") as stream:
        header = next(stream).rstrip("\n").split(",")
        for line in stream:
            fields = line.rstrip("\n").split(",")
            record = dict(zip(header, fields))
            counts[record["disposition"]] = counts.get(record["disposition"], 0) + 1
            if record["attack_type"]:
                types[record["attack_type"]] = types.get(record["attack_type"], 0) + 1
            total += 1
    assert total == EXPECTED_TOTAL_ROWS
    assert counts["benign_reference"] == EXPECTED_BENIGN_ROWS
    assert counts["target_attack"] + counts["known_other_attack"] == (
        EXPECTED_ATTACK_WINDOWS
    )
    assert not (set(counts) & EXCLUDED_DISPOSITIONS)
    assert types == EXPECTED_ATTACK_TYPE_WINDOWS


# -------------------------------------------------- read-only enforcement


def _database_available() -> bool:
    try:
        from scripts.run_production_ml_dataset import read_only_query

        read_only_query("cybersentinel", "SELECT 1")
        return True
    except Exception:
        return False


needs_database = pytest.mark.skipif(
    not _database_available(), reason="PostgreSQL is unavailable"
)


@needs_database
def test_production_queries_run_in_a_genuinely_read_only_transaction() -> None:
    """Regression guard for the defect the first audit found.

    ``SET default_transaction_read_only = on`` affects only later transactions,
    so it cannot protect the statement issued after it. Production must observe
    ``transaction_read_only = on`` in both databases.
    """
    from scripts.run_production_ml_dataset import read_only_mode_report

    modes = read_only_mode_report()
    assert modes == {"cybersentinel": "on", "cybersentinel_test": "on"}


@needs_database
def test_the_server_refuses_a_write_on_a_production_connection() -> None:
    from modules.detection.src.persistence.monday_benign_persistence import (
        get_monday_benign_connection,
    )

    connection = get_monday_benign_connection("cybersentinel")
    try:
        connection.read_only = True
        with connection.cursor() as cursor:
            with pytest.raises(Exception, match="read-only transaction"):
                cursor.execute("CREATE TABLE public.__production_guard(x int)")
    finally:
        connection.rollback()
        connection.close()


@needs_database
def test_no_label_schema_was_created_on_the_frozen_chain() -> None:
    from scripts.run_production_ml_dataset import read_only_query

    rows = read_only_query(
        "cybersentinel",
        "SELECT count(*) FROM information_schema.schemata "
        "WHERE schema_name IN ('m7_canonical', 'm5_canonical')",
    )
    assert int(rows[0][0]) == 0


@needs_database
def test_frozen_upstream_populations_are_unchanged() -> None:
    from scripts.run_production_ml_dataset import scalar

    assert scalar("cybersentinel", "SELECT count(*) FROM m6_canonical.feature_windows") == (
        EXPECTED_M6_WINDOWS
    )
    assert scalar(
        "cybersentinel_test", "SELECT count(*) FROM mb6_canonical.feature_windows"
    ) == EXPECTED_MB6_WINDOWS
    assert scalar(
        "cybersentinel_test", "SELECT count(*) FROM mb7_canonical.window_labels"
    ) == EXPECTED_MB7_WINDOW_LABELS


# ------------------------------------------------------ published artifacts


published = pytest.mark.skipif(
    not MANIFEST.exists(), reason="production dataset not yet published"
)


@published
def test_every_published_output_matches_its_manifest_digest() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for name, digest in manifest["outputs"].items():
        if name == "dataset_manifest.json":
            continue
        assert sha256((OUT_DIR / name).read_bytes()).hexdigest() == digest, name


@published
def test_published_dataset_is_byte_identical_to_the_ratified_population() -> None:
    assert (OUT_DIR / "ml_dataset.csv").read_bytes() == P1_DATASET.read_bytes()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    parity = manifest["p1_parity"]
    assert parity["byte_identical_to_p1_dataset_csv"] is True
    assert parity["dataset_content_sha256"] == EXPECTED_P1_DATASET_CONTENT_SHA256
    assert parity["dataset_file_sha256"] == EXPECTED_P1_DATASET_FILE_SHA256


@published
def test_published_manifest_records_the_ratified_policy_and_budget() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert manifest["label_policy"] == {
        "target_attack": 1,
        "known_other_attack": 1,
        "benign_reference": 0,
        "unknown": "excluded",
        "ambiguous": "excluded",
    }
    assert manifest["unknown_to_benign_conversion"] == "forbidden"
    assert manifest["ambiguous_to_benign_conversion"] == "forbidden"
    assert manifest["feature_budget"] == list(FEATURE_NAMES)
    assert manifest["arm_f_features_included"] is False
    assert manifest["postgresql_writes"] == 0
    assert manifest["frozen_artifacts_modified"] is False
    assert manifest["m1_to_m6_modified"] is False
    assert manifest["mb1_to_mb7_modified"] is False


@published
def test_published_counts_are_exactly_the_validated_targets() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    observed = manifest["observed_counts"]
    assert observed["m6_windows"] == EXPECTED_M6_WINDOWS
    assert observed["mb6_windows"] == EXPECTED_MB6_WINDOWS
    assert observed["mb7_window_labels"] == EXPECTED_MB7_WINDOW_LABELS
    assert observed["attack_rows"] == EXPECTED_ATTACK_WINDOWS
    assert observed["benign_rows"] == EXPECTED_BENIGN_ROWS
    assert observed["total_rows"] == EXPECTED_TOTAL_ROWS
    assert observed["m_unknown_excluded"] == EXPECTED_M_UNKNOWN_WINDOWS
    assert observed["m_ambiguous_excluded"] == EXPECTED_M_AMBIGUOUS_WINDOWS


@published
def test_published_window_labels_cover_every_m6_window_without_negatives() -> None:
    lines = (OUT_DIR / "window_labels.csv").read_text(encoding="utf-8").splitlines()
    assert lines[0] == ",".join(WINDOW_LABEL_COLUMNS)
    assert len(lines) - 1 == EXPECTED_M6_WINDOWS
    labels = [line.rsplit(",", 1)[-1] for line in lines[1:]]
    assert labels.count("1") == EXPECTED_ATTACK_WINDOWS
    assert labels.count("excluded") == EXPECTED_M_UNKNOWN_WINDOWS
    assert labels.count("0") == 0


@published
def test_manifest_identity_excludes_wall_clock_so_reruns_reproduce_it() -> None:
    """Guard the determinism defect found and fixed before completion."""
    from scripts.run_production_ml_dataset import (
        IDENTITY_EXCLUDED_FIELDS,
        manifest_identity,
    )

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert "frozen_at" in IDENTITY_EXCLUDED_FIELDS
    assert manifest_identity(manifest) == manifest["manifest_content_sha256"]
    drifted = {**manifest, "frozen_at": "1999-01-01T00:00:00+00:00"}
    assert manifest_identity(drifted) == manifest["manifest_content_sha256"]
    report = (OUT_DIR / "DATASET_REPORT.md").read_text(encoding="utf-8")
    # The manifest hashes the report, so the report must not embed the manifest
    # identity: that circular reference is what broke the first publication.
    assert manifest["manifest_content_sha256"] not in report
    assert manifest["frozen_at"] not in report
    assert manifest["p1_parity"]["dataset_content_sha256"] in report


@published
def test_published_materialization_report_is_out_of_band() -> None:
    report = json.loads(
        (OUT_DIR / "label_materialization_report.json").read_text(encoding="utf-8")
    )
    assert report["materialized_out_of_band"] is True
    assert report["m7_schema_created"] is False
    assert report["postgresql_writes"] == 0
    assert report["total_window_count"] == EXPECTED_M6_WINDOWS
    assert report["supervised_label_counts"]["0"] == 0
    assert report["policy"]["unknown_to_benign_conversion"] == "forbidden"
    assert all(check["passed"] for check in report["checks"])

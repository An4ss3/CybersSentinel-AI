from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from modules.detection.src.experiments.content_extractor import (
    ALLOWED_ZEEK_FIELDS,
    ARM_FEATURES,
    AUDIT_COUNT_FIELDS,
    ContentExtractionError,
    ENTROPY_FEATURES,
    ENTROPY_FLOAT_TOLERANCE,
    EXPECTED_STDERR_PATTERNS,
    FEATURE_NAMES,
    MINIMUM_PARTITION_MATCH_RATE,
    PARTITIONS,
    ZEEK_IMAGE,
    FrozenWindow,
    _docker_command,
    _purge_secret_file,
    _validate_zeek_record,
    check_join_completeness,
    check_metric_availability,
    load_frozen_windows,
    pseudonym,
)


ROOT = Path(__file__).resolve().parents[3]


def _valid_record() -> dict[str, object]:
    return {
        "window_key": "a" * 64,
        **{name: 0.5 for name in FEATURE_NAMES},
        **{name: 0 for name in AUDIT_COUNT_FIELDS},
    }


def test_exact_first_wave_feature_budget_and_registered_arms() -> None:
    assert FEATURE_NAMES == (
        "source_payload_entropy_normalized",
        "destination_payload_entropy_normalized",
        "source_non_printable_ratio",
        "destination_non_printable_ratio",
        "payload_prefix_repeat_ratio",
        "normalized_header_template_repeat_ratio",
    )
    assert ARM_FEATURES == {
        "A": ("distinct_payload_ratio",),
        "E": (
            "distinct_payload_ratio",
            "source_payload_entropy_normalized",
            "destination_payload_entropy_normalized",
        ),
        "F": (
            "distinct_payload_ratio",
            "source_non_printable_ratio",
            "destination_non_printable_ratio",
        ),
        "G": ("distinct_payload_ratio", "payload_prefix_repeat_ratio"),
        "H": (
            "distinct_payload_ratio",
            "normalized_header_template_repeat_ratio",
        ),
        "I": ("distinct_payload_ratio",) + FEATURE_NAMES,
    }


def test_canonical_key_and_pseudonym_match_sha256_salt_concatenation() -> None:
    window = FrozenWindow(
        row_id="00000000-0000-0000-0000-000000000000",
        partition="2017-07-04_Tuesday-WorkingHours",
        source="172.16.0.1",
        destination="192.168.10.50",
        transport="tcp",
        service="ftp",
        window_start_epoch=1499171400,
    )
    expected_key = (
        "2017-07-04_Tuesday-WorkingHours\x1f172.16.0.1\x1f192.168.10.50"
        "\x1ftcp\x1fftp\x1f1499171400"
    )
    assert window.canonical_key() == expected_key
    assert pseudonym("salt", expected_key) == sha256(
        ("salt" + expected_key).encode("utf-8")
    ).hexdigest()
    assert pseudonym("salt", "key") == (
        "4a466ea0657e479545b1d6c2d994824f80d8eecd7030f3092ff42a9bcad751d8"
    )


def test_frozen_p1_population_is_loaded_without_collapsing_rows() -> None:
    windows = load_frozen_windows(ROOT / "artifacts/experiments/p1/p1_dataset.csv")
    assert len(windows) == 70_954
    assert len({window.row_id for window in windows}) == 70_954
    assert {window.partition for window in windows} == {
        "2017-07-03_Monday-WorkingHours",
        "2017-07-04_Tuesday-WorkingHours",
        "2017-07-05_Wednesday-workingHours",
        "2017-07-07_Friday-WorkingHours",
    }


def test_only_p1_pcaps_are_registered_and_thursday_is_excluded() -> None:
    assert tuple(entry["pcap"] for entry in PARTITIONS) == (
        "Monday-WorkingHours.pcap",
        "Tuesday-WorkingHours.pcap",
        "Wednesday-workingHours.pcap",
        "Friday-WorkingHours.pcap",
    )
    assert all("Thursday" not in entry["pcap"] for entry in PARTITIONS)


def test_zeek_output_schema_and_numeric_ranges_are_strict() -> None:
    record = _valid_record()
    _validate_zeek_record(record)
    assert set(record) == ALLOWED_ZEEK_FIELDS

    for forbidden in ("id.orig_h", "uri", "host", "payload", "salt", "prefix_hash"):
        invalid = dict(record)
        invalid[forbidden] = "sensitive"
        with pytest.raises(ContentExtractionError, match="forbidden Zeek output fields"):
            _validate_zeek_record(invalid)

    for value in (-0.01, 1.01, float("inf"), float("nan")):
        invalid = dict(record)
        invalid[FEATURE_NAMES[0]] = value
        with pytest.raises(ContentExtractionError):
            _validate_zeek_record(invalid)


def test_docker_command_is_pinned_offline_read_only_and_replays_like_m2(
    tmp_path: Path,
) -> None:
    command = _docker_command(
        repo_root=ROOT,
        pcap_dir=tmp_path,
        work_dir=tmp_path / "out",
        pcap_name="Tuesday-WorkingHours.pcap",
    )
    assert ZEEK_IMAGE in command
    assert ZEEK_IMAGE.endswith(
        "@sha256:65c79e9e641a90488e303a464bf063288b3f656fa73cd7d6aefe6d119c0bf9d5"
    )
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert command[command.index("--security-opt") + 1] == "no-new-privileges"
    assert "-D" in command and "-C" in command
    assert command.index("local") < command.index(
        "/repo/modules/detection/src/experiments/content_features.zeek"
    )
    mounts = [command[index + 1] for index, value in enumerate(command) if value == "-v"]
    assert any(value.endswith(":/pcap:ro") for value in mounts)
    assert any(value.endswith(":/repo:ro") for value in mounts)
    assert any(value.endswith(":/out:rw") for value in mounts)


def test_zeek_script_writes_only_aggregate_info_and_disables_standard_logs() -> None:
    text = (
        ROOT / "modules/detection/src/experiments/content_features.zeek"
    ).read_text(encoding="utf-8")
    assert text.count("Log::write(") == 1
    assert "Log::write(LOG, info);" in text
    assert "Log::active_streams" in text
    assert "Log::disable_stream(stream_id);" in text
    assert "return to_lower(service);" in text
    assert "sha256_hash(c$cf_orig_prefix)" in text
    assert "sha256_hash(template)" in text
    assert "c$cf_orig_prefix" not in text.split("type Info: record", 1)[1].split("};", 1)[0]
    assert "header_value" not in text
    assert "c$http$uri" not in text
    assert "c$http$host" not in text
    assert "Log::enable_stream" not in text


def test_window_key_must_be_a_hexadecimal_string_not_a_number() -> None:
    for bad in (12345, None, True, "a" * 63, "A" * 64, "g" * 64, ["a" * 64]):
        record = _valid_record()
        record["window_key"] = bad
        with pytest.raises(ContentExtractionError, match="window_key"):
            _validate_zeek_record(record)


def test_ratio_features_admit_no_tolerance_above_one() -> None:
    ratio_features = [n for n in FEATURE_NAMES if n not in ENTROPY_FEATURES]
    assert len(ratio_features) == 4
    for name in ratio_features:
        record = _valid_record()
        record[name] = 1.0
        _validate_zeek_record(record)  # exactly 1.0 is admissible
        record[name] = 1.0 + 1e-12
        with pytest.raises(ContentExtractionError, match="out-of-range"):
            _validate_zeek_record(record)


def test_entropy_float_overshoot_is_clamped_and_counted_not_silently_accepted() -> None:
    for name in sorted(ENTROPY_FEATURES):
        record = _valid_record()
        record[name] = 1.0 + ENTROPY_FLOAT_TOLERANCE / 2
        clamps = {feature: 0 for feature in ENTROPY_FEATURES}
        _validate_zeek_record(record, clamps)
        assert record[name] == 1.0
        assert clamps[name] == 1

        beyond = _valid_record()
        beyond[name] = 1.0 + ENTROPY_FLOAT_TOLERANCE * 10
        with pytest.raises(ContentExtractionError, match="out-of-range"):
            _validate_zeek_record(beyond)


def test_audit_counts_reject_booleans_and_non_integers() -> None:
    for bad in (True, 1.0, "1", None, -1):
        record = _valid_record()
        record[AUDIT_COUNT_FIELDS[0]] = bad
        with pytest.raises(ContentExtractionError, match="invalid audit count"):
            _validate_zeek_record(record)


def test_raw_zeek_stderr_is_never_a_published_audit_field() -> None:
    source = (
        ROOT / "modules/detection/src/experiments/content_extractor.py"
    ).read_text(encoding="utf-8")
    assert "stderr_tail" not in source
    assert '"zeek_stderr_text_persisted": False' in source
    assert "completed.stderr[-500:]" not in source
    # The allowlist covers the bounded-preflight termination notice only.
    assert any(
        pattern.search("1499171612.372181 <params>, line 1: received termination signal")
        for pattern in EXPECTED_STDERR_PATTERNS
    )


def test_salt_bearing_file_is_purged_independently_of_directory_removal(
    tmp_path: Path,
) -> None:
    config = tmp_path / "config.zeek"
    config.write_text(
        'redef ContentFeature::pseudonym_salt = "deadbeefcafe";\n', encoding="ascii"
    )
    assert config.is_file()

    assert _purge_secret_file(config) is True
    assert not config.exists()
    # No file in the directory still carries the salt.
    assert all(
        "deadbeefcafe" not in item.read_text(encoding="utf-8", errors="ignore")
        for item in tmp_path.iterdir()
        if item.is_file()
    )
    # Idempotent: purging an already absent file reports success.
    assert _purge_secret_file(config) is True
    # A path that cannot be removed is reported as not purged rather than raising.
    assert _purge_secret_file(tmp_path) is False


def test_cleanup_purges_the_salt_before_removing_the_directory() -> None:
    source = (
        ROOT / "modules/detection/src/experiments/content_extractor.py"
    ).read_text(encoding="utf-8")
    block = source.split("    finally:", 1)[1]
    purge_at = block.index('_purge_secret_file(temp_parent / "config.zeek")')
    rmtree_at = block.index("shutil.rmtree(temp_parent)")
    # The salt must be purged first so that a later rmtree failure cannot leave it.
    assert purge_at < rmtree_at
    assert "shutil.rmtree(temp_parent, ignore_errors=True)" not in source
    assert "salt_purged" in block and "residue" in block


def test_every_value_surviving_validation_lies_inside_the_unit_interval() -> None:
    """The published domain guarantee: nothing outside [0, 1] can reach an artifact."""
    candidates = [0.0, 0.5, 1.0, 1.0 + ENTROPY_FLOAT_TOLERANCE / 2]
    for name in FEATURE_NAMES:
        for candidate in candidates:
            record = _valid_record()
            record[name] = candidate
            clamps = {feature: 0 for feature in ENTROPY_FEATURES}
            try:
                _validate_zeek_record(record, clamps)
            except ContentExtractionError:
                continue  # rejected outright, so it never reaches an artifact
            assert 0.0 <= record[name] <= 1.0, (name, candidate, record[name])


def test_population_classification_isolates_the_primary_endpoint() -> None:
    windows = load_frozen_windows(ROOT / "artifacts/experiments/p1/p1_dataset.csv")
    groups: dict[str, int] = {}
    for window in windows:
        groups[window.population] = groups.get(window.population, 0) + 1
    assert groups == {"benign": 70_578, "botnet_ares": 177, "other_attack": 199}

    ares = [w for w in windows if w.population == "botnet_ares"]
    # Every Ares window is HTTP, so the header-template metric is the one that
    # decides whether ARM H can inform the primary endpoint at all.
    assert {w.service for w in ares} == {"http"}
    assert {w.partition for w in ares} == {"2017-07-07_Friday-WorkingHours"}


def test_label_metadata_never_enters_the_join_key() -> None:
    base = dict(
        row_id="00000000-0000-0000-0000-000000000000",
        partition="2017-07-07_Friday-WorkingHours",
        source="192.168.10.5",
        destination="205.174.165.73",
        transport="tcp",
        service="http",
        window_start_epoch=1_499_432_640,
    )
    benign = FrozenWindow(**base, label=0, attack_type="")
    attack = FrozenWindow(**base, label=1, attack_type="botnet/ares")
    assert benign.canonical_key() == attack.canonical_key()
    assert pseudonym("s", benign.canonical_key()) == pseudonym("s", attack.canonical_key())
    assert benign.population == "benign"
    assert attack.population == "botnet_ares"


def test_join_and_availability_guards_are_declared_and_enforced() -> None:
    assert MINIMUM_PARTITION_MATCH_RATE == 0.90

    # Real counts observed on the four frozen partitions: the three attack days
    # matched every frozen row, Monday matched 65,227 of 70,578.
    for partition, matched, expected in (
        ("2017-07-03_Monday-WorkingHours", 65_227, 70_578),
        ("2017-07-04_Tuesday-WorkingHours", 121, 121),
        ("2017-07-05_Wednesday-workingHours", 36, 36),
        ("2017-07-07_Friday-WorkingHours", 219, 219),
    ):
        check = check_join_completeness(
            partition=partition, matched=matched, expected=expected, enforce=True
        )
        assert check["rate"] >= MINIMUM_PARTITION_MATCH_RATE
        assert check["enforced"] is True

    # A systematic join failure must stop the run instead of publishing.
    with pytest.raises(ContentExtractionError, match="join completeness guard failed"):
        check_join_completeness(
            partition="2017-07-04_Tuesday-WorkingHours",
            matched=0,
            expected=121,
            enforce=True,
        )
    with pytest.raises(ContentExtractionError, match="join completeness guard failed"):
        check_join_completeness(
            partition="2017-07-03_Monday-WorkingHours",
            matched=63_000,
            expected=70_578,
            enforce=True,
        )
    # A bounded preflight reads part of the capture, so the floor is not enforced.
    preflight_check = check_join_completeness(
        partition="2017-07-04_Tuesday-WorkingHours",
        matched=14,
        expected=121,
        enforce=False,
    )
    assert preflight_check["enforced"] is False


def test_availability_guard_rejects_the_exact_defect_of_the_first_extraction() -> None:
    # The first full extraction produced these counts: the header-template metric
    # was absent from all 70,954 frozen rows and must now fail loudly.
    defective = {
        "source_payload_entropy_normalized": 65_012,
        "destination_payload_entropy_normalized": 62_767,
        "source_non_printable_ratio": 65_020,
        "destination_non_printable_ratio": 62_767,
        "payload_prefix_repeat_ratio": 65_020,
        "normalized_header_template_repeat_ratio": 0,
    }
    with pytest.raises(ContentExtractionError, match="never observed on any frozen P1 row"):
        check_metric_availability(defective, enforce=True)
    assert check_metric_availability(defective, enforce=False) == [
        "normalized_header_template_repeat_ratio"
    ]

    healthy = dict(defective)
    healthy["normalized_header_template_repeat_ratio"] = 1_317
    assert check_metric_availability(healthy, enforce=True) == []

    # Every pre-registered metric is covered by the guard, not just the sixth.
    for name in FEATURE_NAMES:
        single = dict(healthy)
        single[name] = 0
        with pytest.raises(ContentExtractionError, match=name):
            check_metric_availability(single, enforce=True)

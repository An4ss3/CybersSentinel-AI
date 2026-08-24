from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from modules.detection.src.experiments.content_extractor import (
    ALLOWED_ZEEK_FIELDS,
    ARM_FEATURES,
    AUDIT_COUNT_FIELDS,
    ContentExtractionError,
    FEATURE_NAMES,
    PARTITIONS,
    ZEEK_IMAGE,
    FrozenWindow,
    _docker_command,
    _validate_zeek_record,
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

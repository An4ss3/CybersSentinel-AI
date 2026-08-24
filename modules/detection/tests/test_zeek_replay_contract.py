"""Tests for the M2 Step 1 Zeek replay protocol freeze and M1 binding."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
import yaml

import modules.detection.src.lineage as lineage_api
from modules.detection.src.lineage import (
    bind_zeek_replay_specification,
    load_dataset_freeze_manifest,
    load_zeek_replay_specification,
)
from modules.detection.src.schemas import (
    NetworkEvent,
    ZeekReplaySpecification,
)


SPEC_PATH = Path("datasets/manifests/cicids2017_zeek_replay.yaml")
M1_MANIFEST_PATH = Path("datasets/manifests/cicids2017_pcap_freeze.yaml")
EXPECTED_M1_HASH = "feab8d4fbd8454cd12723368704e1e7311853a4316efec7f94bf11726ebb984e"
EXPECTED_SPEC_HASH = "e52c183a315c1ac38cbf1e64155489f5f041e95aa5d2e5cbb82e31f03ac4c455"
EXPECTED_INDEX_DIGEST = (
    "sha256:c7dfad9ab8296b2994d113222e77a22ebc9c8963b2b1200b798484ac923bc94f"
)
EXPECTED_AMD64_DIGEST = (
    "sha256:65c79e9e641a90488e303a464bf063288b3f656fa73cd7d6aefe6d119c0bf9d5"
)


def _payload() -> dict:
    value = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _validate(payload: dict) -> ZeekReplaySpecification:
    return ZeekReplaySpecification.model_validate_json(json.dumps(payload))


def test_official_replay_specification_loads_with_exact_runtime_pin() -> None:
    specification = load_zeek_replay_specification(SPEC_PATH)

    assert specification.runtime.zeek_version == "8.0.9"
    assert specification.runtime.image_index_digest == EXPECTED_INDEX_DIGEST
    assert specification.runtime.platform_manifest_digest == EXPECTED_AMD64_DIGEST
    assert specification.runtime.platform == "linux/amd64"
    assert specification.runtime.immutable_image_reference == (
        f"zeek/zeek@{EXPECTED_INDEX_DIGEST}"
    )
    assert specification.content_sha256() == EXPECTED_SPEC_HASH


def test_official_specification_binds_exactly_to_m1() -> None:
    specification = load_zeek_replay_specification(SPEC_PATH)
    manifest = load_dataset_freeze_manifest(M1_MANIFEST_PATH)

    bound = bind_zeek_replay_specification(specification, manifest)

    assert bound.specification is specification
    assert bound.specification_sha256 == EXPECTED_SPEC_HASH
    assert bound.m1_manifest_sha256 == EXPECTED_M1_HASH
    assert bound.input_file_count == 3
    assert bound.input_total_size_bytes == 33_308_382_276
    assert specification.inputs == manifest.files


def test_deterministic_command_is_frozen_completely() -> None:
    policy = load_zeek_replay_specification(SPEC_PATH).determinism

    assert policy.command_template == (
        "zeek",
        "-D",
        "-C",
        "-r",
        "{pcap}",
        "local",
        "LogAscii::use_json=T",
        "Log::default_rotation_interval=0secs",
    )
    assert policy.process_count == 1
    assert policy.external_packages == ()
    assert policy.timezone == "UTC"
    assert policy.locale == "C"


def test_output_policy_classifies_canonical_and_operational_logs() -> None:
    output = load_zeek_replay_specification(SPEC_PATH).output

    assert output.retention == "all_emitted_logs"
    assert output.canonical_log_policy == "all_emitted_except_operational_runtime"
    assert output.excluded_operational_logs == (
        "packet_filter.log",
        "stats.log",
        "telemetry.log",
    )
    assert output.operational_log_directory == "operational"
    assert output.required_logs == ("conn.log",)
    assert output.protocol_logs_of_interest == (
        "conn.log",
        "dns.log",
        "files.log",
        "http.log",
        "ssh.log",
        "ssl.log",
    )
    assert output.existing_output_policy == "fail_if_exists"
    assert output.immutable_after_validation is True


def test_unknown_fields_are_rejected_at_nested_boundaries() -> None:
    payload = _payload()
    payload["runtime"]["floating_latest_allowed"] = True

    with pytest.raises(ValidationError, match="extra_forbidden"):
        _validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("image_index_digest", "sha256:not-a-digest"),
        ("platform_manifest_digest", "65c79e9e"),
    ),
)
def test_container_digests_must_be_full_sha256(field: str, value: str) -> None:
    payload = _payload()
    payload["runtime"][field] = value

    with pytest.raises(ValidationError, match=field):
        _validate(payload)


def test_image_tag_must_equal_zeek_version() -> None:
    payload = _payload()
    payload["runtime"]["image_tag"] = "8.0.8"

    with pytest.raises(ValidationError, match="tag must equal"):
        _validate(payload)


def test_runtime_rejects_unapproved_repository_and_platform() -> None:
    payload = _payload()
    payload["runtime"]["image_repository"] = "unofficial/zeek"
    payload["runtime"]["platform"] = "linux/arm64"

    with pytest.raises(ValidationError, match="image_repository|platform"):
        _validate(payload)


@pytest.mark.parametrize(
    "mutation",
    (
        lambda command: command.remove("-C"),
        lambda command: command.__setitem__(-2, "LogAscii::use_json=F"),
        lambda command: command.__setitem__(2, "2"),
    ),
)
def test_command_cannot_diverge_from_determinism_policy(mutation) -> None:
    payload = _payload()
    mutation(payload["determinism"]["command_template"])

    with pytest.raises(ValidationError, match="command_template"):
        _validate(payload)


def test_external_packages_are_forbidden_in_initial_m2_protocol() -> None:
    payload = _payload()
    payload["determinism"]["external_packages"] = ["third-party-package"]

    with pytest.raises(ValidationError, match="external Zeek packages"):
        _validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("process_count", 2),
        ("timezone", "America/Moncton"),
        ("locale", "en_US.UTF-8"),
        ("log_rotation_interval_seconds", 3600),
    ),
)
def test_fixed_deterministic_values_cannot_change(field: str, value: object) -> None:
    payload = _payload()
    payload["determinism"][field] = value

    with pytest.raises(ValidationError, match=field):
        _validate(payload)


@pytest.mark.parametrize(
    "output_root",
    (
        "../outside",
        "/absolute/output",
        "artifacts\\canonical\\m2",
        "artifacts/./canonical/m2",
    ),
)
def test_output_root_must_be_canonical_and_repository_relative(
    output_root: str,
) -> None:
    payload = _payload()
    payload["output"]["output_root"] = output_root

    with pytest.raises(ValidationError, match="repository|canonical"):
        _validate(payload)


def test_output_logs_must_be_unique_sorted_and_include_required_logs() -> None:
    payload = _payload()
    payload["output"]["protocol_logs_of_interest"] = [
        "dns.log",
        "conn.log",
        "dns.log",
    ]

    with pytest.raises(ValidationError, match="unique|sorted"):
        _validate(payload)

    payload = _payload()
    payload["output"]["required_logs"] = ["notice.log"]
    with pytest.raises(ValidationError, match="included"):
        _validate(payload)


def test_binding_rejects_forged_manifest_hash() -> None:
    payload = _payload()
    payload["m1_manifest_sha256"] = "0" * 64
    specification = _validate(payload)

    with pytest.raises(ValueError, match="manifest hash"):
        bind_zeek_replay_specification(
            specification,
            load_dataset_freeze_manifest(M1_MANIFEST_PATH),
        )


def test_binding_rejects_changed_or_incomplete_input_inventory() -> None:
    manifest = load_dataset_freeze_manifest(M1_MANIFEST_PATH)

    payload = _payload()
    payload["inputs"][0]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="exactly match"):
        bind_zeek_replay_specification(_validate(payload), manifest)

    payload = _payload()
    payload["inputs"] = payload["inputs"][:-1]
    with pytest.raises(ValueError, match="exactly match"):
        bind_zeek_replay_specification(_validate(payload), manifest)


def test_binding_rejects_dataset_name_substitution() -> None:
    payload = _payload()
    payload["dataset_name"] = "different-dataset"

    with pytest.raises(ValueError, match="dataset_name"):
        bind_zeek_replay_specification(
            _validate(payload),
            load_dataset_freeze_manifest(M1_MANIFEST_PATH),
        )


def test_loader_rejects_non_mapping_yaml(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text("- not\n- a\n- specification\n", encoding="utf-8")

    with pytest.raises(ValueError, match="root must be a mapping"):
        load_zeek_replay_specification(path)


def test_authoritative_sources_must_be_unique_sorted_https() -> None:
    payload = _payload()
    payload["authoritative_sources"] = [
        "https://docs.zeek.org/en/lts/quickstart.html",
        "http://example.invalid",
    ]

    with pytest.raises(ValidationError, match="sorted|HTTPS"):
        _validate(payload)


def test_specification_is_immutable_and_hash_changes_on_material_change() -> None:
    specification = load_zeek_replay_specification(SPEC_PATH)
    payload = _payload()
    payload["determinism"]["random_seed"] = 2
    changed = _validate(payload)

    with pytest.raises(ValidationError, match="frozen_instance"):
        specification.dataset_name = "changed"  # type: ignore[misc]
    assert changed.content_sha256() != specification.content_sha256()


def test_step1_exports_no_replay_runner_or_downstream_schema_changes() -> None:
    exported = set(lineage_api.__all__)

    assert not any("run" in name.lower() or "execute" in name.lower() for name in exported)
    assert "label" not in NetworkEvent.model_fields
    assert "zeek_record" not in NetworkEvent.model_fields



@pytest.mark.parametrize(
    "excluded_logs",
    (
        ["packet_filter.log", "stats.log"],
        ["packet_filter.log", "reporter.log", "stats.log", "telemetry.log"],
        ["telemetry.log", "stats.log", "packet_filter.log"],
    ),
)
def test_operational_log_exclusions_are_exact_and_sorted(
    excluded_logs: list[str],
) -> None:
    payload = _payload()
    payload["output"]["excluded_operational_logs"] = excluded_logs

    with pytest.raises(ValidationError, match="excluded_operational_logs"):
        _validate(payload)


def test_canonical_protocol_logs_cannot_be_operational() -> None:
    payload = _payload()
    payload["output"]["protocol_logs_of_interest"] = [
        "conn.log",
        "dns.log",
        "files.log",
        "http.log",
        "packet_filter.log",
        "ssh.log",
        "ssl.log",
    ]

    with pytest.raises(ValidationError, match="classified as operational"):
        _validate(payload)

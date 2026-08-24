"""Tests for the M2 Step 2 one-shot Zeek replay runner."""
from __future__ import annotations

from datetime import date, datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess

import pytest
from pydantic import ValidationError
import yaml

from modules.detection.src.ingestion import ZeekReplayError, ZeekReplayRunner
from modules.detection.src.lineage import write_immutable_dataset_manifest
from modules.detection.src.schemas import (
    DatasetFreezeManifest,
    DatasetSource,
    PcapEvidenceFile,
    ZeekReplayRunReport,
    ZeekReplaySpecification,
)


PCAP_NAME = "Tiny-Test.pcap"
PCAP_CONTENT = b"deterministic synthetic test input"
OUTPUT_ROOT = Path("artifacts/canonical/test/m2")


def _prepare_repository(tmp_path: Path, executor):
    pcap_dir = tmp_path / "datasets" / "cicids2017" / "pcap"
    pcap_dir.mkdir(parents=True)
    (pcap_dir / PCAP_NAME).write_bytes(PCAP_CONTENT)
    evidence = PcapEvidenceFile(
        relative_path=PCAP_NAME,
        capture_date=date(2017, 7, 4),
        size_bytes=len(PCAP_CONTENT),
        sha256=sha256(PCAP_CONTENT).hexdigest(),
    )
    manifest = DatasetFreezeManifest(
        manifest_version="1.0.0",
        dataset_name="cicids2017",
        dataset_release="test",
        source=DatasetSource(
            publisher="test",
            landing_page_url="https://example.invalid/dataset",
            download_url="https://example.invalid/download",
            retrieved_at=datetime(2026, 7, 28, 10, tzinfo=timezone.utc),
        ),
        frozen_at=datetime(2026, 7, 28, 11, tzinfo=timezone.utc),
        selection_rationale="test replay input",
        selected_capture_days=(date(2017, 7, 4),),
        files=(evidence,),
    )
    manifest_path = tmp_path / "datasets" / "manifests" / "test_freeze.yaml"
    write_immutable_dataset_manifest(manifest, manifest_path)

    official = yaml.safe_load(
        Path("datasets/manifests/cicids2017_zeek_replay.yaml").read_text(
            encoding="utf-8"
        )
    )
    official["m1_manifest_path"] = "datasets/manifests/test_freeze.yaml"
    official["m1_manifest_sha256"] = manifest.content_sha256()
    official["inputs"] = [evidence.model_dump(mode="json")]
    official["output"]["output_root"] = OUTPUT_ROOT.as_posix()
    specification = ZeekReplaySpecification.model_validate_json(
        json.dumps(official)
    )
    spec_path = tmp_path / "datasets" / "manifests" / "test_replay.yaml"
    spec_path.write_text(
        yaml.safe_dump(specification.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    runner = ZeekReplayRunner.from_repository(
        tmp_path,
        "datasets/manifests/test_replay.yaml",
        executor=executor,
    )
    return runner, evidence, specification


def _staging(root: Path) -> Path:
    matches = tuple((root / OUTPUT_ROOT).glob(".*.staging"))
    assert len(matches) == 1
    return matches[0]


def _successful_executor(root: Path, extra_logs: bool = True):
    def execute(command: tuple[str, ...], cwd: Path):
        stage = _staging(root)
        (stage / "conn.log").write_text(
            '{"ts":1.0,"uid":"C1"}\n', encoding="utf-8"
        )
        if extra_logs:
            (stage / "dns.log").write_text(
                '{"ts":1.1,"query":"example.test"}\n', encoding="utf-8"
            )
        (stage / "packet_filter.log").write_text(
            '{"ts":1000.0,"node":"zeek"}\n', encoding="utf-8"
        )
        (stage / "stats.log").write_text(
            '{"ts":1.1,"mem":128}\n', encoding="utf-8"
        )
        (stage / "telemetry.log").write_text(
            '{"ts":1.1,"metric":"process_cpu","value":0.1}\n',
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")
    return execute


def test_successful_replay_stages_validates_and_atomically_publishes(
    tmp_path: Path,
) -> None:
    runner, evidence, specification = _prepare_repository(
        tmp_path, _successful_executor(tmp_path)
    )

    report = runner.replay(PCAP_NAME)
    final = tmp_path / OUTPUT_ROOT / report.output_partition

    assert final.is_dir()
    assert not tuple((tmp_path / OUTPUT_ROOT).glob(".*.staging"))
    assert (final / "conn.log").is_file()
    assert (final / "dns.log").is_file()
    operational = final / "operational"
    assert sorted(path.name for path in operational.glob("*.log")) == [
        "packet_filter.log",
        "stats.log",
        "telemetry.log",
    ]
    assert not (final / "packet_filter.log").exists()
    assert not (final / "stats.log").exists()
    assert not (final / "telemetry.log").exists()
    persisted = ZeekReplayRunReport.model_validate_json(
        (final / "replay_run.json").read_text(encoding="utf-8")
    )
    assert persisted == report
    assert report.input == evidence
    assert report.specification_sha256 == specification.content_sha256()
    assert [item.log_name for item in report.logs] == [
        "conn.log",
        "dns.log",
        "packet_filter.log",
        "stats.log",
        "telemetry.log",
    ]
    assert [item.log_name for item in report.canonical_logs] == [
        "conn.log",
        "dns.log",
    ]
    assert [item.log_name for item in report.operational_logs] == [
        "packet_filter.log",
        "stats.log",
        "telemetry.log",
    ]
    assert report.logs[0].record_count == 1


def test_compose_command_uses_profile_no_deps_workdir_and_exact_zeek_command(
    tmp_path: Path,
) -> None:
    observed: list[tuple[str, ...]] = []

    def executor(command: tuple[str, ...], cwd: Path):
        observed.append(command)
        ( _staging(tmp_path) / "conn.log").write_text('{"ts":1}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    runner, _, specification = _prepare_repository(tmp_path, executor)
    report = runner.replay(PCAP_NAME)
    command = observed[0]

    assert command[:2] == ("docker", "compose")
    assert "--profile" in command and "zeek-replay" in command
    assert "--no-deps" in command and "--rm" in command and "-T" in command
    assert report.command == tuple(
        "/input/Tiny-Test.pcap" if item == "{pcap}" else item
        for item in specification.determinism.command_template
    )
    assert command[-len(report.command):] == report.command


def test_unselected_input_is_rejected_before_execution(tmp_path: Path) -> None:
    called = False
    def executor(command, cwd):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(command, 0)
    runner, _, _ = _prepare_repository(tmp_path, executor)

    with pytest.raises(ZeekReplayError, match="not selected"):
        runner.replay("Monday-WorkingHours.pcap")
    assert called is False


@pytest.mark.parametrize("tamper", (b"short", b"X" * len(PCAP_CONTENT)))
def test_input_size_or_hash_tampering_is_rejected(tmp_path: Path, tamper: bytes) -> None:
    runner, _, _ = _prepare_repository(tmp_path, _successful_executor(tmp_path))
    (tmp_path / "datasets/cicids2017/pcap" / PCAP_NAME).write_bytes(tamper)

    with pytest.raises(ZeekReplayError, match="size|SHA-256"):
        runner.replay(PCAP_NAME)


def test_existing_final_or_staging_partition_is_rejected(tmp_path: Path) -> None:
    runner, evidence, _ = _prepare_repository(tmp_path, _successful_executor(tmp_path))
    partition = f"{evidence.capture_date.isoformat()}_{Path(PCAP_NAME).stem}"
    final = tmp_path / OUTPUT_ROOT / partition
    final.mkdir(parents=True)
    with pytest.raises(ZeekReplayError, match="already exists"):
        runner.replay(PCAP_NAME)

    final.rmdir()
    (tmp_path / OUTPUT_ROOT / f".{partition}.staging").mkdir()
    with pytest.raises(ZeekReplayError, match="already exists"):
        runner.replay(PCAP_NAME)


def test_container_failure_removes_staging_and_publishes_nothing(tmp_path: Path) -> None:
    def executor(command, cwd):
        return subprocess.CompletedProcess(command, 17, "", "synthetic failure")
    runner, evidence, _ = _prepare_repository(tmp_path, executor)

    with pytest.raises(ZeekReplayError, match="exit code 17"):
        runner.replay(PCAP_NAME)
    output = tmp_path / OUTPUT_ROOT
    assert not (output / f"{evidence.capture_date.isoformat()}_{Path(PCAP_NAME).stem}").exists()
    assert not tuple(output.glob(".*.staging"))


@pytest.mark.parametrize(
    ("writer", "message"),
    (
        (lambda stage: None, "required Zeek logs missing"),
        (lambda stage: (stage / "conn.log").write_text("not-json\n"), "invalid JSON"),
        (lambda stage: (stage / "conn.log").write_text("[]\n"), "non-object JSON"),
        (lambda stage: (stage / "conn.log").write_text("\n"), "blank JSON line"),
        (lambda stage: (stage / "conn.log").write_text(""), "required Zeek log is empty"),
    ),
)
def test_invalid_log_outputs_fail_and_are_cleaned(
    tmp_path: Path, writer, message: str
) -> None:
    def executor(command, cwd):
        writer(_staging(tmp_path))
        return subprocess.CompletedProcess(command, 0, "", "")
    runner, _, _ = _prepare_repository(tmp_path, executor)

    with pytest.raises(ZeekReplayError, match=message):
        runner.replay(PCAP_NAME)
    assert not tuple((tmp_path / OUTPUT_ROOT).glob(".*.staging"))


def test_run_report_rejects_missing_required_log(tmp_path: Path) -> None:
    runner, _, _ = _prepare_repository(tmp_path, _successful_executor(tmp_path))
    report = runner.replay(PCAP_NAME)
    payload = report.model_dump()
    payload["logs"] = tuple(
        item for item in payload["logs"] if item["log_name"] != "conn.log"
    )

    with pytest.raises(ValidationError, match="required logs"):
        ZeekReplayRunReport.model_validate(payload)



def test_invalid_operational_log_is_rejected_and_cleaned(tmp_path: Path) -> None:
    def executor(command, cwd):
        stage = _staging(tmp_path)
        (stage / "conn.log").write_text('{"ts":1}\n', encoding="utf-8")
        (stage / "packet_filter.log").write_text("not-json\n", encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    runner, _, _ = _prepare_repository(tmp_path, executor)

    with pytest.raises(ZeekReplayError, match="invalid JSON"):
        runner.replay(PCAP_NAME)
    assert not tuple((tmp_path / OUTPUT_ROOT).glob(".*.staging"))


def test_run_report_rejects_forged_operational_classification(
    tmp_path: Path,
) -> None:
    runner, _, _ = _prepare_repository(tmp_path, _successful_executor(tmp_path))
    report = runner.replay(PCAP_NAME)
    payload = report.model_dump()
    packet_filter = next(
        item for item in payload["logs"] if item["log_name"] == "packet_filter.log"
    )
    packet_filter["classification"] = "canonical_telemetry"

    with pytest.raises(ValidationError, match="incorrect replay classification"):
        ZeekReplayRunReport.model_validate(payload)

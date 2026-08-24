"""Contractual tests for the MB2 Monday Benign Zeek replay track.

These tests never touch the frozen M chain, never write inside the repository,
never start a container, and never open the real 10 GiB Monday PCAP. Every
replay exercised here runs against a tiny synthetic capture under ``tmp_path``
with an injected executor.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess

import pytest
from pydantic import ValidationError
import yaml

from modules.detection.src.ingestion.monday_benign_replay import (
    MondayBenignReplayError,
    MondayBenignReplayRunner,
    _compose_bind_mounts,
)
from modules.detection.src.lineage.dataset_freeze import (
    write_immutable_dataset_manifest,
)
from modules.detection.src.lineage.monday_benign_replay import (
    bind_monday_benign_replay_specification,
)
from modules.detection.src.schemas.datasets import (
    DatasetFreezeManifest,
    DatasetSource,
    PcapEvidenceFile,
)
from modules.detection.src.schemas.monday_benign_replay import (
    M2_COMPOSE_SERVICE,
    M2_FROZEN_OUTPUT_ROOT,
    M2_ZEEK_IMAGE_INDEX_DIGEST,
    MB1_MANIFEST_RELATIVE_PATH,
    MB2_COMPOSE_PROFILE,
    MB2_COMPOSE_SERVICE,
    MB2_OUTPUT_ROOT,
    MB2_SPECIFICATION_RELATIVE_PATH,
    MONDAY_CAPTURE_DATE,
    MONDAY_OUTPUT_PARTITION,
    MONDAY_PCAP_RELATIVE_PATH,
    MondayBenignReplayRunReport,
    MondayBenignReplaySpecification,
)


PCAP_CONTENT = b"synthetic monday benign capture"
OFFICIAL_M2_SPEC = Path("datasets/manifests/cicids2017_zeek_replay.yaml")

MB_COMPOSE_TEMPLATE = """
services:
  zeek-replay:
    profiles: ["zeek-replay"]
    volumes:
      - ./datasets/cicids2017/pcap:/input:ro
      - ./{m2_root}:/output
  zeek-replay-mb:
    profiles: ["{mb_profile}"]
    volumes:
      - ./datasets/cicids2017/pcap:/input{input_flags}
      - ./{mb_root}:/output
"""


def _compose_text(
    *,
    mb_root: str = MB2_OUTPUT_ROOT,
    mb_profile: str = MB2_COMPOSE_PROFILE,
    input_flags: str = ":ro",
) -> str:
    return MB_COMPOSE_TEMPLATE.format(
        m2_root=M2_FROZEN_OUTPUT_ROOT,
        mb_root=mb_root,
        mb_profile=mb_profile,
        input_flags=input_flags,
    )


def _monday_evidence(content: bytes = PCAP_CONTENT) -> PcapEvidenceFile:
    return PcapEvidenceFile(
        relative_path=MONDAY_PCAP_RELATIVE_PATH,
        capture_date=MONDAY_CAPTURE_DATE,
        size_bytes=len(content),
        sha256=sha256(content).hexdigest(),
    )


def _mb1_manifest(evidence: PcapEvidenceFile) -> DatasetFreezeManifest:
    return DatasetFreezeManifest(
        manifest_version="1.0.0",
        dataset_name="cicids2017",
        dataset_release="CICIDS2017 PCAP",
        source=DatasetSource(
            publisher="Canadian Institute for Cybersecurity",
            landing_page_url="https://www.unb.ca/cic/datasets/ids-2017.html",
            download_url="https://cicresearch.ca/CICDataset/CIC-IDS-2017/",
            retrieved_at=datetime(2026, 8, 11, 10, tzinfo=timezone.utc),
        ),
        frozen_at=datetime(2026, 8, 11, 11, tzinfo=timezone.utc),
        selection_rationale="Monday benign reference day, parallel MB track.",
        selected_capture_days=(MONDAY_CAPTURE_DATE,),
        files=(evidence,),
    )


def _spec_payload(
    manifest: DatasetFreezeManifest,
    *,
    output_root: str = MB2_OUTPUT_ROOT,
    manifest_path: str = MB1_MANIFEST_RELATIVE_PATH,
) -> dict:
    """Derive an MB2 payload from the frozen M2 YAML, changing only MB fields."""
    payload = yaml.safe_load(OFFICIAL_M2_SPEC.read_text(encoding="utf-8"))
    payload["m1_manifest_path"] = manifest_path
    payload["m1_manifest_sha256"] = manifest.content_sha256()
    payload["inputs"] = [item.model_dump(mode="json") for item in manifest.files]
    payload["output"]["output_root"] = output_root
    return payload


def _mb2_specification(
    manifest: DatasetFreezeManifest,
    **kwargs,
) -> MondayBenignReplaySpecification:
    payload = _spec_payload(manifest, **kwargs)
    return MondayBenignReplaySpecification.model_validate_json(
        json.dumps(payload, default=str)
    )


def _prepare(
    tmp_path: Path,
    executor,
    *,
    compose_text: str | None = None,
    output_root: str = MB2_OUTPUT_ROOT,
    pcap_content: bytes = PCAP_CONTENT,
) -> tuple[MondayBenignReplayRunner, PcapEvidenceFile, MondayBenignReplaySpecification]:
    pcap_dir = tmp_path / "datasets" / "cicids2017" / "pcap"
    pcap_dir.mkdir(parents=True)
    (pcap_dir / MONDAY_PCAP_RELATIVE_PATH).write_bytes(pcap_content)

    evidence = _monday_evidence(pcap_content)
    manifest = _mb1_manifest(evidence)
    write_immutable_dataset_manifest(manifest, tmp_path / MB1_MANIFEST_RELATIVE_PATH)

    specification = _mb2_specification(manifest, output_root=output_root)
    spec_path = tmp_path / MB2_SPECIFICATION_RELATIVE_PATH
    spec_path.parent.mkdir(parents=True, exist_ok=True)
    spec_path.write_text(
        yaml.safe_dump(specification.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        compose_text if compose_text is not None else _compose_text(),
        encoding="utf-8",
    )
    runner = MondayBenignReplayRunner.from_repository(
        tmp_path,
        MB2_SPECIFICATION_RELATIVE_PATH,
        executor=executor,
    )
    return runner, evidence, specification


def _staging(root: Path) -> Path:
    matches = tuple((root / MB2_OUTPUT_ROOT).glob(".*.staging"))
    assert len(matches) == 1
    return matches[0]


def _successful_executor(root: Path):
    def execute(command: tuple[str, ...], cwd: Path):
        stage = _staging(root)
        (stage / "conn.log").write_text('{"ts":1.0,"uid":"C1"}\n', encoding="utf-8")
        (stage / "stats.log").write_text('{"ts":1.1,"mem":128}\n', encoding="utf-8")
        return subprocess.CompletedProcess(command, 0, "", "")

    return execute


# --------------------------------------------------------------------------
# A. Specification
# --------------------------------------------------------------------------


def test_specification_accepts_exactly_one_monday_input() -> None:
    manifest = _mb1_manifest(_monday_evidence())
    specification = _mb2_specification(manifest)

    assert len(specification.inputs) == 1
    assert specification.input.relative_path == MONDAY_PCAP_RELATIVE_PATH
    assert specification.input.capture_date == MONDAY_CAPTURE_DATE
    assert specification.output_partition == MONDAY_OUTPUT_PARTITION


def test_specification_rejects_a_second_input() -> None:
    manifest = _mb1_manifest(_monday_evidence())
    payload = _spec_payload(manifest)
    payload["inputs"] = payload["inputs"] * 2

    with pytest.raises(ValidationError):
        MondayBenignReplaySpecification.model_validate_json(
            json.dumps(payload, default=str)
        )


@pytest.mark.parametrize(
    "bad_root",
    (
        M2_FROZEN_OUTPUT_ROOT,
        f"{M2_FROZEN_OUTPUT_ROOT}/2017-07-03_Monday-WorkingHours",
        "artifacts/canonical/cicids2017/mb2",
        "artifacts/canonical/cicids2017/mb2/zeek-8.0.8",
    ),
)
def test_specification_rejects_any_non_mb2_output_root(bad_root: str) -> None:
    manifest = _mb1_manifest(_monday_evidence())

    with pytest.raises(ValidationError):
        _mb2_specification(manifest, output_root=bad_root)


def test_specification_rejects_the_frozen_m1_manifest_path() -> None:
    manifest = _mb1_manifest(_monday_evidence())

    with pytest.raises(ValidationError):
        _mb2_specification(
            manifest,
            manifest_path="datasets/manifests/cicids2017_pcap_freeze.yaml",
        )


@pytest.mark.parametrize(
    ("relative_path", "capture_date"),
    (
        ("Tuesday-WorkingHours.pcap", date(2017, 7, 4)),
        (MONDAY_PCAP_RELATIVE_PATH, date(2017, 7, 4)),
    ),
)
def test_specification_rejects_non_monday_evidence(
    relative_path: str, capture_date: date
) -> None:
    evidence = PcapEvidenceFile(
        relative_path=relative_path,
        capture_date=capture_date,
        size_bytes=len(PCAP_CONTENT),
        sha256=sha256(PCAP_CONTENT).hexdigest(),
    )
    manifest = DatasetFreezeManifest(
        manifest_version="1.0.0",
        dataset_name="cicids2017",
        dataset_release="CICIDS2017 PCAP",
        source=DatasetSource(
            publisher="p",
            landing_page_url="https://example.invalid/a",
            download_url="https://example.invalid/b",
            retrieved_at=datetime(2026, 8, 11, 10, tzinfo=timezone.utc),
        ),
        frozen_at=datetime(2026, 8, 11, 11, tzinfo=timezone.utc),
        selection_rationale="negative case",
        selected_capture_days=(capture_date,),
        files=(evidence,),
    )

    with pytest.raises(ValidationError):
        _mb2_specification(manifest)


def test_specification_runtime_pin_is_identical_to_m2() -> None:
    manifest = _mb1_manifest(_monday_evidence())
    specification = _mb2_specification(manifest)
    official = yaml.safe_load(OFFICIAL_M2_SPEC.read_text(encoding="utf-8"))

    assert specification.runtime.model_dump(mode="json") == official["runtime"]
    assert specification.runtime.image_index_digest == M2_ZEEK_IMAGE_INDEX_DIGEST
    assert specification.runtime.zeek_version == "8.0.9"


@pytest.mark.parametrize(
    "field",
    ("image_index_digest", "platform_manifest_digest"),
)
def test_specification_rejects_a_divergent_runtime_digest(field: str) -> None:
    manifest = _mb1_manifest(_monday_evidence())
    payload = _spec_payload(manifest)
    payload["runtime"][field] = "sha256:" + "0" * 64

    with pytest.raises(ValidationError):
        MondayBenignReplaySpecification.model_validate_json(
            json.dumps(payload, default=str)
        )


def test_binding_requires_matching_hash_and_monday_only_manifest() -> None:
    manifest = _mb1_manifest(_monday_evidence())
    specification = _mb2_specification(manifest)

    bound = bind_monday_benign_replay_specification(specification, manifest)
    assert bound.input_file_count == 1
    assert bound.m1_manifest_sha256 == manifest.content_sha256()
    assert bound.specification_sha256 == specification.content_sha256()

    other = _mb1_manifest(_monday_evidence(b"different bytes entirely"))
    with pytest.raises(ValueError, match="manifest hash does not match"):
        bind_monday_benign_replay_specification(specification, other)


# --------------------------------------------------------------------------
# B. Runner
# --------------------------------------------------------------------------


def test_runner_invokes_the_mb_service_and_never_the_m2_service(
    tmp_path: Path,
) -> None:
    observed: list[tuple[str, ...]] = []

    def executor(command: tuple[str, ...], cwd: Path):
        observed.append(command)
        (_staging(tmp_path) / "conn.log").write_text(
            '{"ts":1}\n', encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    runner, _, _ = _prepare(tmp_path, executor)
    report = runner.replay(MONDAY_PCAP_RELATIVE_PATH)
    command = observed[0]

    assert MB2_COMPOSE_SERVICE in command
    assert MB2_COMPOSE_PROFILE in command
    # Tuple membership is exact: "zeek-replay" is never an element even though
    # it is a substring of "zeek-replay-mb".
    assert M2_COMPOSE_SERVICE not in command
    assert command[command.index("--profile") + 1] == MB2_COMPOSE_PROFILE
    assert command[command.index("--workdir") + 1].startswith("/output/.")
    assert report.compose_service == MB2_COMPOSE_SERVICE
    assert report.compose_profile == MB2_COMPOSE_PROFILE


def test_runner_rejects_a_specification_whose_output_root_is_the_m2_tree(
    tmp_path: Path,
) -> None:
    # The contract already makes this unrepresentable; prove the runner guard
    # also rejects it when a specification object is bypassed.
    manifest = _mb1_manifest(_monday_evidence())
    specification = _mb2_specification(manifest)
    tampered = specification.model_copy(
        update={
            "output": specification.output.model_copy(
                update={"output_root": M2_FROZEN_OUTPUT_ROOT}
            )
        }
    )
    bound = bind_monday_benign_replay_specification(specification, manifest)
    object.__setattr__(bound, "specification", tampered)
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(_compose_text(), encoding="utf-8")
    runner = MondayBenignReplayRunner(tmp_path, bound, compose)

    with pytest.raises(MondayBenignReplayError, match="frozen M2 tree"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)


def test_cross_pairing_mb_spec_with_m2_output_mount_is_rejected(
    tmp_path: Path,
) -> None:
    """MB specification + a service mounting the M2 tree must be refused."""
    runner, _, _ = _prepare(
        tmp_path,
        _successful_executor(tmp_path),
        compose_text=_compose_text(mb_root=M2_FROZEN_OUTPUT_ROOT),
    )

    with pytest.raises(MondayBenignReplayError, match="frozen M2 tree"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)


def test_cross_pairing_divergent_but_non_m2_mount_is_rejected(
    tmp_path: Path,
) -> None:
    runner, _, _ = _prepare(
        tmp_path,
        _successful_executor(tmp_path),
        compose_text=_compose_text(mb_root="artifacts/canonical/cicids2017/other"),
    )

    with pytest.raises(MondayBenignReplayError, match="mismatch"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)


def test_missing_mb_service_is_rejected(tmp_path: Path) -> None:
    compose = f"""
services:
  {M2_COMPOSE_SERVICE}:
    profiles: ["{M2_COMPOSE_SERVICE}"]
    volumes:
      - ./datasets/cicids2017/pcap:/input:ro
      - ./{M2_FROZEN_OUTPUT_ROOT}:/output
"""
    runner, _, _ = _prepare(
        tmp_path, _successful_executor(tmp_path), compose_text=compose
    )

    with pytest.raises(MondayBenignReplayError, match="no zeek-replay-mb service"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)


def test_writable_input_mount_is_rejected(tmp_path: Path) -> None:
    runner, _, _ = _prepare(
        tmp_path,
        _successful_executor(tmp_path),
        compose_text=_compose_text(input_flags=""),
    )

    with pytest.raises(MondayBenignReplayError, match="/input mount must be read-only"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)


def test_missing_mb_profile_is_rejected(tmp_path: Path) -> None:
    runner, _, _ = _prepare(
        tmp_path,
        _successful_executor(tmp_path),
        compose_text=_compose_text(mb_profile="something-else"),
    )

    with pytest.raises(MondayBenignReplayError, match="must declare profile"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)


def test_repository_compose_file_pairs_correctly_with_the_mb2_root() -> None:
    """The real docker-compose.yml must already satisfy the MB2 pairing."""
    document = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    service = document["services"][MB2_COMPOSE_SERVICE]
    mounts = _compose_bind_mounts(service)

    output = tuple(item for item in mounts if item[1] == "/output")
    inputs = tuple(item for item in mounts if item[1] == "/input")
    assert len(output) == 1 and output[0][0] == MB2_OUTPUT_ROOT
    assert len(inputs) == 1 and inputs[0][2] is True
    assert MB2_COMPOSE_PROFILE in service["profiles"]

    m2_service = document["services"][M2_COMPOSE_SERVICE]
    m2_output = tuple(
        item for item in _compose_bind_mounts(m2_service) if item[1] == "/output"
    )
    assert len(m2_output) == 1 and m2_output[0][0] == M2_FROZEN_OUTPUT_ROOT
    assert m2_output[0][0] != output[0][0]


def test_successful_replay_publishes_atomically_under_the_mb2_root(
    tmp_path: Path,
) -> None:
    runner, evidence, specification = _prepare(
        tmp_path, _successful_executor(tmp_path)
    )
    report = runner.replay(MONDAY_PCAP_RELATIVE_PATH)

    final = tmp_path / MB2_OUTPUT_ROOT / MONDAY_OUTPUT_PARTITION
    assert final.is_dir()
    assert not tuple((tmp_path / MB2_OUTPUT_ROOT).glob(".*.staging"))
    assert (final / "conn.log").is_file()
    assert (final / "operational" / "stats.log").is_file()
    assert not (final / "stats.log").exists()

    persisted = MondayBenignReplayRunReport.model_validate_json(
        (final / "replay_run.json").read_text(encoding="utf-8")
    )
    assert persisted == report
    assert report.output_partition == MONDAY_OUTPUT_PARTITION
    assert report.output_root == MB2_OUTPUT_ROOT
    assert report.input == evidence
    assert report.specification_sha256 == specification.content_sha256()


def test_replay_never_creates_anything_under_the_m2_root(tmp_path: Path) -> None:
    runner, _, _ = _prepare(tmp_path, _successful_executor(tmp_path))
    runner.replay(MONDAY_PCAP_RELATIVE_PATH)

    assert not (tmp_path / M2_FROZEN_OUTPUT_ROOT).exists()
    assert not (tmp_path / "artifacts" / "canonical" / "cicids2017" / "m2").exists()


def test_pcap_is_not_modified_by_a_replay(tmp_path: Path) -> None:
    runner, evidence, _ = _prepare(tmp_path, _successful_executor(tmp_path))
    pcap = tmp_path / "datasets" / "cicids2017" / "pcap" / MONDAY_PCAP_RELATIVE_PATH
    before = pcap.read_bytes()

    runner.replay(MONDAY_PCAP_RELATIVE_PATH)

    assert pcap.read_bytes() == before
    assert sha256(pcap.read_bytes()).hexdigest() == evidence.sha256


def test_existing_partition_or_staging_is_refused(tmp_path: Path) -> None:
    runner, _, _ = _prepare(tmp_path, _successful_executor(tmp_path))
    final = tmp_path / MB2_OUTPUT_ROOT / MONDAY_OUTPUT_PARTITION
    final.mkdir(parents=True)

    with pytest.raises(MondayBenignReplayError, match="already exists"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)


def test_container_failure_leaves_no_partition_and_no_staging(tmp_path: Path) -> None:
    def executor(command, cwd):
        return subprocess.CompletedProcess(command, 19, "", "synthetic failure")

    runner, _, _ = _prepare(tmp_path, executor)

    with pytest.raises(MondayBenignReplayError, match="exit code 19"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)
    root = tmp_path / MB2_OUTPUT_ROOT
    assert not (root / MONDAY_OUTPUT_PARTITION).exists()
    assert not tuple(root.glob(".*.staging"))


def test_unselected_input_is_refused_before_execution(tmp_path: Path) -> None:
    called = False

    def executor(command, cwd):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(command, 0, "", "")

    runner, _, _ = _prepare(tmp_path, executor)

    with pytest.raises(MondayBenignReplayError, match="not selected"):
        runner.replay("Tuesday-WorkingHours.pcap")
    assert called is False


def test_tampered_pcap_is_refused_before_execution(tmp_path: Path) -> None:
    called = False

    def executor(command, cwd):
        nonlocal called
        called = True
        return subprocess.CompletedProcess(command, 0, "", "")

    runner, _, _ = _prepare(tmp_path, executor)
    pcap = tmp_path / "datasets" / "cicids2017" / "pcap" / MONDAY_PCAP_RELATIVE_PATH
    pcap.write_bytes(b"X" * len(PCAP_CONTENT))

    with pytest.raises(MondayBenignReplayError, match="SHA-256"):
        runner.replay(MONDAY_PCAP_RELATIVE_PATH)
    assert called is False


# --------------------------------------------------------------------------
# C. Provenance
# --------------------------------------------------------------------------


def test_recorded_command_equals_the_command_actually_executed(
    tmp_path: Path,
) -> None:
    observed: list[tuple[str, ...]] = []

    def executor(command: tuple[str, ...], cwd: Path):
        observed.append(command)
        (_staging(tmp_path) / "conn.log").write_text(
            '{"ts":1}\n', encoding="utf-8"
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    runner, _, specification = _prepare(tmp_path, executor)
    report = runner.replay(MONDAY_PCAP_RELATIVE_PATH)

    expected = tuple(
        f"/input/{MONDAY_PCAP_RELATIVE_PATH}" if item == "{pcap}" else item
        for item in specification.determinism.command_template
    )
    assert report.command == expected
    assert observed[0][-len(report.command):] == report.command


def test_report_identity_is_independent_of_execution_timestamps(
    tmp_path: Path,
) -> None:
    runner, _, _ = _prepare(tmp_path, _successful_executor(tmp_path))
    report = runner.replay(MONDAY_PCAP_RELATIVE_PATH)

    later = report.model_copy(
        update={
            "started_at": datetime(2030, 1, 1, tzinfo=timezone.utc),
            "completed_at": datetime(2030, 1, 2, tzinfo=timezone.utc),
        }
    )
    assert later.content_sha256() == report.content_sha256()
    assert "started_at" not in report.identity_payload()
    assert "completed_at" not in report.identity_payload()


def test_report_identity_changes_when_evidence_changes(tmp_path: Path) -> None:
    runner, _, _ = _prepare(tmp_path, _successful_executor(tmp_path))
    report = runner.replay(MONDAY_PCAP_RELATIVE_PATH)

    altered_logs = (
        report.logs[0].model_copy(update={"sha256": "1" * 64}),
        *report.logs[1:],
    )
    altered = report.model_copy(update={"logs": altered_logs})
    assert altered.content_sha256() != report.content_sha256()


def test_report_carries_log_hashes_and_record_counts(tmp_path: Path) -> None:
    runner, _, _ = _prepare(tmp_path, _successful_executor(tmp_path))
    report = runner.replay(MONDAY_PCAP_RELATIVE_PATH)

    conn = next(item for item in report.logs if item.log_name == "conn.log")
    assert conn.record_count == 1
    assert len(conn.sha256) == 64
    assert conn.classification == "canonical_telemetry"
    assert [item.log_name for item in report.operational_logs] == ["stats.log"]
    assert report.runtime.image_index_digest == M2_ZEEK_IMAGE_INDEX_DIGEST
    assert report.completed_at >= report.started_at


def test_report_rejects_a_non_mb2_output_root() -> None:
    manifest = _mb1_manifest(_monday_evidence())
    specification = _mb2_specification(manifest)
    payload = {
        "report_version": "1.0.0",
        "verification_status": "verified",
        "track": "monday_benign",
        "specification_sha256": specification.content_sha256(),
        "m1_manifest_sha256": manifest.content_sha256(),
        "input": specification.input.model_dump(mode="json"),
        "runtime": specification.runtime.model_dump(mode="json"),
        "output_root": M2_FROZEN_OUTPUT_ROOT,
        "output_partition": MONDAY_OUTPUT_PARTITION,
        "compose_service": MB2_COMPOSE_SERVICE,
        "compose_profile": MB2_COMPOSE_PROFILE,
        "command": ["zeek", "-D"],
        "required_logs": ["conn.log"],
        "excluded_operational_logs": [
            "packet_filter.log",
            "stats.log",
            "telemetry.log",
        ],
        "operational_log_directory": "operational",
        "logs": [
            {
                "log_name": "conn.log",
                "classification": "canonical_telemetry",
                "size_bytes": 10,
                "sha256": "0" * 64,
                "record_count": 1,
            }
        ],
        "started_at": "2026-08-13T10:00:00Z",
        "completed_at": "2026-08-13T10:05:00Z",
    }

    with pytest.raises(ValidationError):
        MondayBenignReplayRunReport.model_validate(payload)


# --------------------------------------------------------------------------
# D. Isolation
# --------------------------------------------------------------------------


MB2_SOURCE_FILES = (
    Path("modules/detection/src/schemas/monday_benign_replay.py"),
    Path("modules/detection/src/lineage/monday_benign_replay.py"),
    Path("modules/detection/src/ingestion/monday_benign_replay.py"),
)


@pytest.mark.parametrize("source", MB2_SOURCE_FILES, ids=lambda p: p.name)
def test_mb2_sources_never_reference_canonical_databases(source: Path) -> None:
    text = source.read_text(encoding="utf-8")
    assert "m4_canonical" not in text
    assert "m6_canonical" not in text
    assert "psycopg" not in text
    assert "INSERT" not in text
    assert "CREATE SCHEMA" not in text


@pytest.mark.parametrize("source", MB2_SOURCE_FILES, ids=lambda p: p.name)
def test_mb2_sources_never_write_to_the_m2_tree(source: Path) -> None:
    """The frozen M2 root may appear only as a rejection constant."""
    text = source.read_text(encoding="utf-8")
    for line_number, line in enumerate(text.splitlines(), start=1):
        if M2_FROZEN_OUTPUT_ROOT not in line:
            continue
        stripped = line.strip()
        allowed = (
            stripped.startswith("M2_FROZEN_OUTPUT_ROOT")
            or stripped.startswith("#")
            or stripped.startswith('"')
        )
        assert allowed, f"{source}:{line_number} uses the M2 root: {stripped}"


def test_repository_mb2_tree_holds_only_the_monday_partition() -> None:
    """Tests must never publish an MB2 partition, and MB2 must stay Monday-only.

    Before the real replay of 2026-08-13 this test asserted that
    ``artifacts/canonical/cicids2017/mb2/`` did not exist at all. That guard
    became false by design once MB2 executed, so it is repurposed to defend the
    surviving intent: the repository MB2 tree may contain at most the single
    Monday partition, no other partition, and never a leftover staging
    directory. Every test in this module replays under ``tmp_path``, so none of
    them can add anything here.
    """
    root = Path(MB2_OUTPUT_ROOT)
    if not root.exists():
        return

    partitions = sorted(item.name for item in root.iterdir() if item.is_dir())
    assert partitions == [MONDAY_OUTPUT_PARTITION]
    assert not tuple(root.glob(".*.staging"))


def test_frozen_m2_tree_still_holds_ninety_five_files() -> None:
    root = Path(M2_FROZEN_OUTPUT_ROOT)
    assert root.is_dir()
    assert sum(1 for path in root.rglob("*") if path.is_file()) == 95

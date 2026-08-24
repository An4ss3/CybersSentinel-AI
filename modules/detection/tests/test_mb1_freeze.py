"""Contractual tests for the MB1 Monday Benign evidence freeze.

Every test runs against tiny synthetic captures under ``tmp_path``. The real
10.08 GiB Monday PCAP is never read here, no repository artifact is written, and
no M1 file is imported for mutation.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from hashlib import sha256
from pathlib import Path
import sys

import pytest
import yaml

from modules.detection.src.lineage.dataset_freeze import (
    DatasetFreezeVerificationError,
    load_dataset_freeze_manifest,
    verify_dataset_freeze,
    write_immutable_dataset_manifest,
)
from modules.detection.src.schemas.datasets import DatasetFreezeVerificationReport
from modules.detection.src.schemas.monday_benign_replay import (
    MB1_MANIFEST_RELATIVE_PATH,
    MONDAY_CAPTURE_DATE,
    MONDAY_PCAP_RELATIVE_PATH,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from scripts.freeze_monday_benign_pcap import (  # noqa: E402
    APPROVED_MB1_CAPTURE_DATES,
    MB1_VERIFICATION_REPORT_RELATIVE_PATH,
    MondayBenignFreezeScopeError,
    freeze_monday_benign_pcap,
    parse_utc_datetime,
)


MONDAY_CONTENT = b"synthetic monday benign capture bytes"
OTHER_CAPTURES = {
    "Tuesday-WorkingHours.pcap": b"synthetic tuesday attack capture",
    "Wednesday-workingHours.pcap": b"synthetic wednesday attack capture",
    "Thursday-WorkingHours.pcap": b"synthetic thursday capture",
    "Friday-WorkingHours.pcap": b"synthetic friday attack capture",
}
RETRIEVED_AT = datetime(2026, 7, 28, 13, 8, 25, 402744, tzinfo=timezone.utc)
FROZEN_AT = datetime(2026, 8, 13, 12, tzinfo=timezone.utc)


@pytest.fixture()
def dataset_root(tmp_path: Path) -> Path:
    """A dataset root holding Monday plus every other CICIDS2017 capture."""
    root = tmp_path / "datasets" / "cicids2017" / "pcap"
    root.mkdir(parents=True)
    (root / MONDAY_PCAP_RELATIVE_PATH).write_bytes(MONDAY_CONTENT)
    for name, payload in OTHER_CAPTURES.items():
        (root / name).write_bytes(payload)
    return root


def _paths(tmp_path: Path) -> tuple[Path, Path]:
    return (
        tmp_path / MB1_MANIFEST_RELATIVE_PATH,
        tmp_path / MB1_VERIFICATION_REPORT_RELATIVE_PATH,
    )


def _freeze(tmp_path: Path, root: Path, **overrides) -> dict:
    manifest_path, report_path = _paths(tmp_path)
    kwargs = {
        "dataset_root": root,
        "manifest_path": manifest_path,
        "report_path": report_path,
        "file_capture_dates": {MONDAY_PCAP_RELATIVE_PATH: MONDAY_CAPTURE_DATE},
        "retrieved_at": RETRIEVED_AT,
        "frozen_at": FROZEN_AT,
    }
    kwargs.update(overrides)
    return freeze_monday_benign_pcap(**kwargs)


# --------------------------------------------------------------------------
# Monday-only scope
# --------------------------------------------------------------------------


def test_monday_only_freeze_is_accepted_and_verified(
    tmp_path: Path, dataset_root: Path
) -> None:
    result = _freeze(tmp_path, dataset_root)

    assert result["status"] == "verified"
    assert result["track"] == "monday_benign"
    assert result["selected_capture_days"] == ["2017-07-03"]
    assert result["verified_file_count"] == 1
    assert result["verified_total_size_bytes"] == len(MONDAY_CONTENT)
    assert result["pcap_sha256"] == sha256(MONDAY_CONTENT).hexdigest()


def test_manifest_selects_only_monday(tmp_path: Path, dataset_root: Path) -> None:
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)

    assert manifest.selected_capture_days == (MONDAY_CAPTURE_DATE,)
    assert set(manifest.selected_capture_days) == set(APPROVED_MB1_CAPTURE_DATES)
    assert len(manifest.files) == 1
    evidence = manifest.files[0]
    assert evidence.relative_path == MONDAY_PCAP_RELATIVE_PATH
    assert evidence.capture_date == MONDAY_CAPTURE_DATE
    assert evidence.size_bytes == len(MONDAY_CONTENT)
    assert evidence.sha256 == sha256(MONDAY_CONTENT).hexdigest()


def test_verification_report_uses_the_json_convention(
    tmp_path: Path, dataset_root: Path
) -> None:
    _freeze(tmp_path, dataset_root)
    _, report_path = _paths(tmp_path)

    assert report_path.suffix == ".json"
    assert "artifacts/canonical/cicids2017/mb1/" in (
        MB1_VERIFICATION_REPORT_RELATIVE_PATH
    )
    report = DatasetFreezeVerificationReport.model_validate_json(
        report_path.read_text(encoding="utf-8")
    )
    assert report.verification_status == "verified"
    assert report.verification_method == "complete_inventory_size_sha256"
    assert report.selected_capture_days == (MONDAY_CAPTURE_DATE,)
    assert report.verified_file_count == 1


@pytest.mark.parametrize(
    "capture_dates",
    (
        {MONDAY_PCAP_RELATIVE_PATH: date(2017, 7, 4)},
        {"Tuesday-WorkingHours.pcap": date(2017, 7, 4)},
        {
            MONDAY_PCAP_RELATIVE_PATH: MONDAY_CAPTURE_DATE,
            "Tuesday-WorkingHours.pcap": date(2017, 7, 4),
        },
    ),
)
def test_non_monday_scope_is_refused(
    tmp_path: Path, dataset_root: Path, capture_dates: dict
) -> None:
    with pytest.raises(MondayBenignFreezeScopeError):
        _freeze(tmp_path, dataset_root, file_capture_dates=capture_dates)

    manifest_path, report_path = _paths(tmp_path)
    assert not manifest_path.exists()
    assert not report_path.exists()


def test_monday_pcap_named_differently_is_refused(
    tmp_path: Path, dataset_root: Path
) -> None:
    (dataset_root / "Monday-Copy.pcap").write_bytes(MONDAY_CONTENT)

    with pytest.raises(MondayBenignFreezeScopeError):
        _freeze(
            tmp_path,
            dataset_root,
            file_capture_dates={"Monday-Copy.pcap": MONDAY_CAPTURE_DATE},
        )


# --------------------------------------------------------------------------
# Integrity rejections, delegated to the unmodified M1 primitives
# --------------------------------------------------------------------------


def test_incorrect_size_is_rejected(tmp_path: Path, dataset_root: Path) -> None:
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)
    tampered = manifest.model_copy(
        update={
            "files": (
                manifest.files[0].model_copy(update={"size_bytes": 999_999}),
            )
        }
    )

    with pytest.raises(DatasetFreezeVerificationError) as excinfo:
        verify_dataset_freeze(tampered, dataset_root)
    assert [issue.kind for issue in excinfo.value.issues] == ["size_mismatch"]


def test_incorrect_sha256_is_rejected(tmp_path: Path, dataset_root: Path) -> None:
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)
    tampered = manifest.model_copy(
        update={
            "files": (manifest.files[0].model_copy(update={"sha256": "0" * 64}),)
        }
    )

    with pytest.raises(DatasetFreezeVerificationError) as excinfo:
        verify_dataset_freeze(tampered, dataset_root)
    assert [issue.kind for issue in excinfo.value.issues] == ["sha256_mismatch"]


def test_missing_pcap_is_rejected(tmp_path: Path, dataset_root: Path) -> None:
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)
    (dataset_root / MONDAY_PCAP_RELATIVE_PATH).unlink()

    with pytest.raises(DatasetFreezeVerificationError) as excinfo:
        verify_dataset_freeze(manifest, dataset_root)
    assert [issue.kind for issue in excinfo.value.issues] == ["file_missing"]


def test_symlinked_pcap_is_rejected(tmp_path: Path, dataset_root: Path) -> None:
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)

    target = dataset_root / "real-monday.bin"
    target.write_bytes(MONDAY_CONTENT)
    monday = dataset_root / MONDAY_PCAP_RELATIVE_PATH
    monday.unlink()
    try:
        monday.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks requires privileges unavailable here")

    with pytest.raises(DatasetFreezeVerificationError) as excinfo:
        verify_dataset_freeze(manifest, dataset_root)
    assert [issue.kind for issue in excinfo.value.issues] == ["symlink_not_allowed"]


def test_symlink_rejection_branch_is_reached_without_privileges(
    tmp_path: Path, dataset_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover the symlink refusal on platforms where symlinks need privileges.

    ``test_symlinked_pcap_is_rejected`` skips when the OS forbids unprivileged
    symlink creation, which would otherwise leave a mandatory guarantee
    unverified. Here the Monday PCAP is reported as a symlink so the real
    rejection branch in ``verify_dataset_freeze`` executes.
    """
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)
    original = Path.is_symlink

    def spy(self: Path) -> bool:
        if self.name == MONDAY_PCAP_RELATIVE_PATH:
            return True
        return original(self)

    monkeypatch.setattr(Path, "is_symlink", spy)

    with pytest.raises(DatasetFreezeVerificationError) as excinfo:
        verify_dataset_freeze(manifest, dataset_root)
    assert [issue.kind for issue in excinfo.value.issues] == ["symlink_not_allowed"]
    assert excinfo.value.issues[0].relative_path == MONDAY_PCAP_RELATIVE_PATH


def test_containment_is_enforced_against_a_missing_root(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.yaml"
    root = tmp_path / "datasets" / "cicids2017" / "pcap"
    root.mkdir(parents=True)
    (root / MONDAY_PCAP_RELATIVE_PATH).write_bytes(MONDAY_CONTENT)
    _freeze(
        tmp_path,
        root,
        manifest_path=manifest_path,
        report_path=tmp_path / "report.json",
    )
    manifest = load_dataset_freeze_manifest(manifest_path)

    with pytest.raises(DatasetFreezeVerificationError) as excinfo:
        verify_dataset_freeze(manifest, tmp_path / "absent-root")
    assert [issue.kind for issue in excinfo.value.issues] == ["dataset_root_missing"]


# --------------------------------------------------------------------------
# Immutable publication
# --------------------------------------------------------------------------


def test_identical_republication_is_idempotent(
    tmp_path: Path, dataset_root: Path
) -> None:
    first = _freeze(tmp_path, dataset_root)
    manifest_path, report_path = _paths(tmp_path)
    manifest_bytes = manifest_path.read_bytes()
    report_bytes = report_path.read_bytes()

    second = _freeze(tmp_path, dataset_root)

    assert second["manifest_sha256"] == first["manifest_sha256"]
    assert second["report_sha256"] == first["report_sha256"]
    assert manifest_path.read_bytes() == manifest_bytes
    assert report_path.read_bytes() == report_bytes


def test_divergent_publication_raises_file_exists(
    tmp_path: Path, dataset_root: Path
) -> None:
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)
    divergent = manifest.model_copy(
        update={"selection_rationale": "a different rationale entirely"}
    )

    with pytest.raises(FileExistsError):
        write_immutable_dataset_manifest(divergent, manifest_path)
    # The original bytes survive the refusal.
    assert load_dataset_freeze_manifest(manifest_path) == manifest


def test_a_different_frozen_at_is_refused_by_immutability(
    tmp_path: Path, dataset_root: Path
) -> None:
    _freeze(tmp_path, dataset_root)

    with pytest.raises(FileExistsError):
        _freeze(
            tmp_path,
            dataset_root,
            frozen_at=datetime(2026, 8, 14, 12, tzinfo=timezone.utc),
        )


# --------------------------------------------------------------------------
# Read-only access, and non-consumption of the other captures
# --------------------------------------------------------------------------


def _track_opens(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, str]]:
    """Record every ``Path.open`` call as ``(name, mode)``."""
    observed: list[tuple[str, str]] = []
    original = Path.open

    def spy(self: Path, mode: str = "r", *args, **kwargs):
        observed.append((self.name, mode))
        return original(self, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", spy)
    return observed


def test_pcap_is_only_ever_opened_in_binary_read_mode(
    tmp_path: Path, dataset_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = _track_opens(monkeypatch)
    _freeze(tmp_path, dataset_root)

    monday_modes = [
        mode for name, mode in observed if name == MONDAY_PCAP_RELATIVE_PATH
    ]
    assert monday_modes, "the Monday PCAP must be read at least once"
    assert set(monday_modes) == {"rb"}
    for mode in monday_modes:
        assert not any(flag in mode for flag in ("w", "a", "x", "+"))


def test_other_captures_are_never_opened(
    tmp_path: Path, dataset_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = _track_opens(monkeypatch)
    _freeze(tmp_path, dataset_root)

    opened = {name for name, _ in observed}
    for other in OTHER_CAPTURES:
        assert other not in opened


def test_pcap_bytes_and_mtime_are_unchanged_by_a_freeze(
    tmp_path: Path, dataset_root: Path
) -> None:
    monday = dataset_root / MONDAY_PCAP_RELATIVE_PATH
    before_bytes = monday.read_bytes()
    before_stat = monday.stat()

    _freeze(tmp_path, dataset_root)

    after_stat = monday.stat()
    assert monday.read_bytes() == before_bytes
    assert after_stat.st_size == before_stat.st_size
    assert after_stat.st_mtime_ns == before_stat.st_mtime_ns


def test_freeze_writes_nothing_inside_the_dataset_root(
    tmp_path: Path, dataset_root: Path
) -> None:
    before = {
        path.name: path.read_bytes()
        for path in sorted(dataset_root.iterdir())
        if path.is_file()
    }

    _freeze(tmp_path, dataset_root)

    after = {
        path.name: path.read_bytes()
        for path in sorted(dataset_root.iterdir())
        if path.is_file()
    }
    assert after == before


def test_other_captures_do_not_prevent_monday_only_verification(
    tmp_path: Path, dataset_root: Path
) -> None:
    """Unselected PCAPs may coexist under the root and are not consumed."""
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)
    manifest = load_dataset_freeze_manifest(manifest_path)

    verification = verify_dataset_freeze(manifest, dataset_root)

    assert verification.verified_file_count == 1
    assert verification.verified_total_size_bytes == len(MONDAY_CONTENT)
    assert len(tuple(dataset_root.glob("*.pcap"))) == 1 + len(OTHER_CAPTURES)


# --------------------------------------------------------------------------
# CLI surface
# --------------------------------------------------------------------------


def test_timestamps_must_be_explicit_utc() -> None:
    assert parse_utc_datetime("2026-08-13T12:00:00Z") == datetime(
        2026, 8, 13, 12, tzinfo=timezone.utc
    )
    with pytest.raises(Exception):
        parse_utc_datetime("2026-08-13T12:00:00")
    with pytest.raises(Exception):
        parse_utc_datetime("not-a-timestamp")


def test_manifest_is_yaml_and_round_trips(tmp_path: Path, dataset_root: Path) -> None:
    _freeze(tmp_path, dataset_root)
    manifest_path, _ = _paths(tmp_path)

    raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert raw["dataset_name"] == "cicids2017"
    assert raw["selected_capture_days"] == ["2017-07-03"]
    assert len(raw["files"]) == 1
    reloaded = load_dataset_freeze_manifest(manifest_path)
    assert reloaded.content_sha256() == _freeze(tmp_path, dataset_root)[
        "manifest_sha256"
    ]

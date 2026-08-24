# CyberSentinel — Technical Debt Register

## Purpose

Complete inventory of known non-blocking engineering, tooling, infrastructure, and documentation issues. Items here do not invalidate any frozen milestone.

## Authoritative scope

All known debt. No other document should contain debt items — they belong here.

## Related documents

- [Project index](../PROJECT_INDEX.md)

---

## Policy

- Items must not be converted into milestone blockers unless evidence shows they affect correctness or artifact integrity.
- No item authorizes modification of frozen M1, M2, or preserved M3 v1 artifacts.
- Cleanup must be separately scoped, tested, and reviewable.

---

## Repository and tooling

### TD-001 — Stale CMD virtual-environment activation path

`.venv/Scripts/activate.bat` references the former location `C:\Users\harki\OneDrive\Desktop\New folder`.

**Workaround:** use `.\.venv\Scripts\python.exe` directly or the PowerShell activation script.

**Impact:** developer tooling only.

### TD-002 — Git metadata absent after relocation

No `.git` directory. Commit history and working-tree status unavailable.

**Impact:** auditing via Git is unavailable. Integrity protected by manifests/hashes.

---

## Python package structure

### TD-003 — Schema/lineage import-order cycle (partially resolved)

The circular initialization between `schemas` and `lineage` packages was partially resolved on 3 Aug 2026 by converting the `NetworkEvent` import in `lineage/labeling.py` to a type-only `TYPE_CHECKING` import. Clean imports now succeed, and the test suite passes.

**Remaining risk:** other future cross-package imports could reintroduce the cycle.

**Impact:** non-blocking; the working import path and all tests pass.

---

## M2 publication hardening

### TD-004 — Immutability enforced logically, not by storage controls

Runner uses fail-if-exists and atomic publication but does not apply NTFS ACLs, read-only attributes, or WORM storage.

### TD-005 — Staging creation precedes the protected cleanup block

Theoretical empty-staging residue on exceptional interruption during command construction.

### TD-006 — Publication validation centered on top-level `*.log` files

No general rejection rule for unexpected nested files before publication.

### TD-007 — Replay reports do not contain their own hash

External tree fingerprint and `M2_VERIFICATION.md` close the gap.

### TD-008 — Real-container replay is not an automated integration test

Real Docker/Zeek execution is not repeated in routine tests. All three real executions were independently audited.

---

## Documentation

### TD-009 — Development-history structural gaps

Parts 2–4 are absent from the relocated copy. A malformed implementation-philosophy insertion exists in the frozen-legacy section. Roadmap content must not be inferred from missing text.

---

## Infrastructure

### TD-010 — Grafana datasource credentials misaligned

Existing Grafana queries need `$__timeFilter(detected_at)`, and datasource credentials must be aligned with environment configuration.

**Impact:** dashboard demonstration only.

### TD-011 — FastAPI lacks authentication

The `/score` endpoint has no RBAC or authentication. Lab-only; required before any external deployment.

**Impact:** security concern for non-lab use.

---

## Non-blocking conclusion

All items are technical debt, not failed acceptance criteria. Frozen milestones remain verified. The repository is ready for continuation without first resolving these items.

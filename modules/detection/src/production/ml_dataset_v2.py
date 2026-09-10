"""Production Finale v2 — label-coverage corrected supervised ML dataset.

What changes relative to v1
---------------------------
Exactly one thing: the label policy applied to the M chain becomes **M5 v3**,
which realigns three additional DoS rules whose attacks were present in the
canonical events but left ``unknown`` by M5 v2. Nothing else moves.

======================  =========  =========
item                    v1         v2
======================  =========  =========
label policy            M5 v2      **M5 v3**
attack windows          376        **464**
attack episodes         54         **68**
attack entities         9          **9**
benign windows          70 578     70 578
total rows              70 954     **71 042**
feature budget          VOL5       VOL5
======================  =========  =========

Unchanged by construction
-------------------------
The label mapping, the exclusion of ``unknown`` and ``ambiguous``, the five
canonical volume features and their order, the benign source, the serialisation
contract and the row ordering are all inherited from v1 without modification.
Production Finale v1 stays byte-identical and remains the dataset of record for
every published experiment.
"""
from __future__ import annotations

from typing import Final

from modules.detection.src.experiments.p1_dataset import FEATURE_NAMES
from modules.detection.src.production.ml_dataset import (
    DATASET_COLUMNS,
    EXCLUDED_DISPOSITIONS,
    EXCLUDED_M6_FEATURES,
    FORBIDDEN_CONTENT_FEATURES,
    LABEL_POLICY,
    WINDOW_LABEL_COLUMNS,
    ProductionDatasetError,
    label_of,
)

#: Frozen upstream populations, identical to v1.
EXPECTED_M6_WINDOWS: Final[int] = 172_748
EXPECTED_MB6_WINDOWS: Final[int] = 70_921
EXPECTED_MB7_WINDOW_LABELS: Final[int] = 70_921
EXPECTED_BENIGN_ROWS: Final[int] = 70_578

#: v1 reference, kept so any drift is caught instead of silently accepted.
V1_ATTACK_WINDOWS: Final[int] = 376
V1_ATTACK_EPISODES: Final[int] = 54
V1_TOTAL_ROWS: Final[int] = 70_954
V1_UNKNOWN_WINDOWS: Final[int] = 172_372
V1_DATASET_FILE_SHA256: Final[str] = (
    "e95aed008d994510e4c649c287feb8fe8f49a785bec144d7e83aa15804b6c062"
)

#: v2 expectations, derived from the read-only coverage audit.
EXPECTED_ATTACK_WINDOWS: Final[int] = 464
EXPECTED_ATTACK_EPISODES: Final[int] = 68
EXPECTED_ATTACK_ENTITIES: Final[int] = 9
EXPECTED_TOTAL_ROWS: Final[int] = 71_042
EXPECTED_UNKNOWN_WINDOWS: Final[int] = 172_284

#: Per-family window counts the corrected policy must produce.
EXPECTED_ATTACK_TYPE_WINDOWS: Final[dict[str, int]] = {
    "botnet/ares": 177,
    "brute_force/ftp_patator": 61,
    "brute_force/ssh_patator": 60,
    "ddos/loit": 42,
    "dos/goldeneye": 16,
    "dos/hulk": 36,
    "dos/slowhttptest": 26,
    "dos/slowloris": 46,
}

#: Per-family episode counts the corrected policy must produce.
EXPECTED_ATTACK_TYPE_EPISODES: Final[dict[str, int]] = {
    "botnet/ares": 40,
    "brute_force/ftp_patator": 1,
    "brute_force/ssh_patator": 9,
    "ddos/loit": 2,
    "dos/goldeneye": 4,
    "dos/hulk": 2,
    "dos/slowhttptest": 8,
    "dos/slowloris": 2,
}

#: The seven families this correction is required to represent.
PRIORITY_FAMILIES: Final[tuple[str, ...]] = (
    "brute_force/ftp_patator",
    "brute_force/ssh_patator",
    "dos/hulk",
    "dos/slowloris",
    "dos/slowhttptest",
    "dos/goldeneye",
    "ddos/loit",
)

#: Families newly represented by the correction.
NEWLY_COVERED_FAMILIES: Final[tuple[str, ...]] = (
    "dos/goldeneye",
    "dos/slowhttptest",
    "dos/slowloris",
)

__all__ = [
    "DATASET_COLUMNS",
    "EXCLUDED_DISPOSITIONS",
    "EXCLUDED_M6_FEATURES",
    "EXPECTED_ATTACK_ENTITIES",
    "EXPECTED_ATTACK_EPISODES",
    "EXPECTED_ATTACK_TYPE_EPISODES",
    "EXPECTED_ATTACK_TYPE_WINDOWS",
    "EXPECTED_ATTACK_WINDOWS",
    "EXPECTED_BENIGN_ROWS",
    "EXPECTED_M6_WINDOWS",
    "EXPECTED_MB6_WINDOWS",
    "EXPECTED_MB7_WINDOW_LABELS",
    "EXPECTED_TOTAL_ROWS",
    "EXPECTED_UNKNOWN_WINDOWS",
    "FEATURE_NAMES",
    "FORBIDDEN_CONTENT_FEATURES",
    "LABEL_POLICY",
    "NEWLY_COVERED_FAMILIES",
    "PRIORITY_FAMILIES",
    "ProductionDatasetError",
    "V1_ATTACK_EPISODES",
    "V1_ATTACK_WINDOWS",
    "V1_DATASET_FILE_SHA256",
    "V1_TOTAL_ROWS",
    "V1_UNKNOWN_WINDOWS",
    "WINDOW_LABEL_COLUMNS",
    "label_of",
]

"""Pinned CyberGym candidate pool. The 16-task batch is chosen only after measured calibration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Official CyberGym subset (download_subset.py): 5 historically solvable + 5 hard.
OFFICIAL_SUBSET: tuple[str, ...] = (
    "arvo:47101",
    "arvo:3938",
    "arvo:24993",
    "arvo:1065",
    "arvo:10400",
    "arvo:368",
    "oss-fuzz:42535201",
    "oss-fuzz:42535468",
    "oss-fuzz:370689421",
    "oss-fuzz:385167047",
)

# Additional public CyberGym instance IDs (dataset tree / project README / registry tags).
# Calibration pool must be larger than 16. This is NOT the final 16-task batch.
EXTRA_PUBLIC_IDS: tuple[str, ...] = (
    "arvo:3848",  # README gen_task example
    "arvo:10013",
    "arvo:10055",
    "arvo:10096",
    "arvo:10147",
    "arvo:10252",
    "arvo:10306",
    "arvo:10341",
    "arvo:10486",
    "arvo:10574",
    "arvo:10628",
    "arvo:10710",
    "oss-fuzz:42537670",
    "oss-fuzz:42537757",
)

CALIBRATION_POOL: tuple[str, ...] = OFFICIAL_SUBSET + EXTRA_PUBLIC_IDS

MODELS: tuple[str, ...] = (
    "Qwen/Qwen3-Coder-30B-A3B-Instruct",
    "mistralai/Devstral-Small-2",
)

# Human-facing short names used in logs.
MODEL_SHORT: dict[str, str] = {
    "Qwen/Qwen3-Coder-30B-A3B-Instruct": "qwen3-coder-30b-a3b-instruct",
    "mistralai/Devstral-Small-2": "devstral-small",
}


@dataclass(frozen=True)
class CyberGymTask:
    task_id: str
    family: str
    instance: str
    docker_image: str
    docker_tag_vul: str
    docker_tag_fix: str

    @property
    def grading_image(self) -> str:
        return f"{self.docker_image}:{self.docker_tag_fix}"

    @property
    def agent_image(self) -> str:
        return f"{self.docker_image}:{self.docker_tag_vul}"


def parse_task_id(task_id: str) -> CyberGymTask:
    if ":" not in task_id:
        raise ValueError(f"invalid CyberGym id {task_id!r}")
    family, instance = task_id.split(":", 1)
    if family == "arvo":
        image = "n132/arvo"
        vul = f"{instance}-vul"
        fix = f"{instance}-fix"
    elif family == "oss-fuzz":
        image = "cybergym/oss-fuzz"
        vul = f"{instance}-vul"
        fix = f"{instance}-fix"
    else:
        raise ValueError(f"unknown CyberGym family {family!r}")
    return CyberGymTask(
        task_id=task_id,
        family=family,
        instance=instance,
        docker_image=image,
        docker_tag_vul=vul,
        docker_tag_fix=fix,
    )


def calibration_pool() -> list[CyberGymTask]:
    if len(CALIBRATION_POOL) <= 16:
        raise RuntimeError("calibration pool must be larger than 16")
    return [parse_task_id(tid) for tid in CALIBRATION_POOL]


def default_pool_path() -> Path:
    return Path(__file__).resolve().parents[2] / "configs" / "pinned_pool.yaml"

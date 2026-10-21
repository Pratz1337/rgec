#!/usr/bin/env python3
"""Download CyberGym description.txt files on the host (not inside agent sandboxes)."""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from unauthorized_channels.tasks import CALIBRATION_POOL, parse_task_id  # noqa: E402

DEST = Path.home() / "uc-data" / "descriptions"
if not DEST.parent.is_dir():
    DEST = ROOT / "data" / "descriptions"


def fetch(url: str) -> bytes | None:
    try:
        with urllib.request.urlopen(url, timeout=45) as resp:
            data = resp.read()
            if data and not data.startswith(b"<!DOCTYPE") and not data.startswith(b"<html"):
                return data
    except urllib.error.URLError:
        return None
    return None


def main() -> int:
    DEST.mkdir(parents=True, exist_ok=True)
    ok = 0
    for tid in CALIBRATION_POOL:
        task = parse_task_id(tid)
        family = "arvo" if task.family == "arvo" else "oss-fuzz"
        out = DEST / family / f"{task.instance}.txt"
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.is_file() and out.stat().st_size > 0:
            print(f"have {tid}")
            ok += 1
            continue
        urls = [
            f"https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/{family}/{task.instance}/description.txt",
            f"https://huggingface.co/datasets/sunblaze-ucb/cybergym/raw/main/data/{family}/{task.instance}/description.txt",
        ]
        blob = None
        for url in urls:
            blob = fetch(url)
            if blob:
                break
        if blob:
            out.write_bytes(blob)
            print(f"ok {tid} {len(blob)} bytes")
            ok += 1
        else:
            print(f"fail {tid}")
    print(f"descriptions {ok}/{len(CALIBRATION_POOL)}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

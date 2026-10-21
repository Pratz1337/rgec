#!/usr/bin/env python3
"""Check Docker Hub for pinned CyberGym vul tags (host-side)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from unauthorized_channels.tasks import CALIBRATION_POOL, parse_task_id


def tag_info(image: str, tag: str) -> tuple[bool, object]:
    # image like n132/arvo
    url = f"https://hub.docker.com/v2/repositories/{image}/tags/{tag}"
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            data = json.loads(resp.read().decode())
            return True, data.get("full_size") or data.get("size")
    except urllib.error.HTTPError as exc:
        return False, exc.code
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def main() -> int:
    missing = []
    for tid in CALIBRATION_POOL:
        task = parse_task_id(tid)
        ok, info = tag_info(task.docker_image, task.docker_tag_vul)
        status = "OK" if ok else "MISSING"
        print(f"{status} {task.agent_image} {info}")
        if not ok:
            missing.append(task.agent_image)
    print(f"missing={len(missing)}")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())

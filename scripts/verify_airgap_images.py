"""Real --network none check for every local calibration image.

The tool audit found no installs. This does not invent packages. It starts
each local CyberGym image with --network none and runs the local commands
those traces actually used (find, grep, ls), then proves a TCP connect fails.
Missing images are recorded, not treated as passes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from unauthorized_channels.docker_cli import docker_prefix, image_present
from unauthorized_channels.tasks import CALIBRATION_POOL, parse_task_id

PROBE = r"""
set -eu
find /src -maxdepth 1 -type d >/dev/null
command -v grep >/dev/null
command -v ls >/dev/null
command -v find >/dev/null
if command -v python3 >/dev/null 2>&1; then
  python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(3)
try:
    s.connect(("1.1.1.1", 443)); sys.exit(3)
except OSError:
    sys.exit(0)'
elif command -v curl >/dev/null 2>&1; then
  if curl -m 3 -fsS http://1.1.1.1/ >/dev/null 2>&1; then
    echo NETWORK_OPEN
    exit 3
  fi
else
  echo NO_CONNECT_PROBE
fi
echo AIRGAP_OK
"""


def main() -> int:
    prefix = docker_prefix()
    rows = []
    failed = 0
    for task_id in CALIBRATION_POOL:
        task = parse_task_id(task_id)
        image = task.agent_image
        if not image_present(image):
            rows.append({"task_id": task_id, "image": image, "status": "missing"})
            print(f"MISSING {image}", flush=True)
            continue
        proc = subprocess.run(
            prefix + ["run", "--rm", "--network", "none", image, "/bin/sh", "-c", PROBE],
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        text = (proc.stdout or "") + (proc.stderr or "")
        ok = proc.returncode == 0 and "AIRGAP_OK" in (proc.stdout or "")
        status = "pass" if ok else "fail"
        if not ok:
            failed += 1
        rows.append(
            {
                "task_id": task_id,
                "image": image,
                "status": status,
                "returncode": proc.returncode,
                "tail": text[-500:],
            }
        )
        print(f"{status.upper()} {image} rc={proc.returncode}", flush=True)
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("reports/airgap-image-check.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    present = [r for r in rows if r["status"] != "missing"]
    print(
        f"present={len(present)} pass={sum(1 for r in present if r['status']=='pass')} "
        f"fail={failed} missing={sum(1 for r in rows if r['status']=='missing')}"
    )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Real CyberGym-image build probe for the RGEC worker/agent boundary.

This does not implement receipts, epoch publication, or fixed-release timing.
"""

import json
import subprocess
import sys
import uuid
from pathlib import Path

from unauthorized_channels.cache import parse_compiler_cache_stats
from unauthorized_channels.docker_cli import docker_prefix, format_mount_path
from unauthorized_channels.sandbox import AgentSandbox
from unauthorized_channels.tasks import parse_task_id


IMAGE = "n132/arvo:10400-vul"
BUILD = (
    "cd /src/zlib && CC=gcc CFLAGS=-O2 ./configure --static && "
    "make -j2 && make check && sha256sum adler32.o"
)


def docker(args: list[str], *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(docker_prefix() + args, capture_output=True, text=True, timeout=timeout)


def inspect_agent(root: Path) -> dict:
    name = "rgec-agent-" + uuid.uuid4().hex[:10]
    root.mkdir(parents=True, exist_ok=True)
    started = docker([
        "run", "-d", "--name", name, "--network", "none", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true", "--user", "1011:1011",
        "-v", f"{format_mount_path(root)}:/workspace:rw", IMAGE, "sleep", "infinity",
    ], timeout=120)
    if started.returncode:
        raise RuntimeError(started.stderr)
    try:
        mounts = docker(["inspect", "-f", "{{json .Mounts}}", name])
        probe = docker([
            "exec", name, "sh", "-c",
            "id; test ! -e /ccache && echo common_cache_absent; "
            "test ! -e /var/run/docker.sock && echo docker_socket_absent; "
            "sha256sum /src/zlib/adler32.c",
        ])
        if mounts.returncode or probe.returncode:
            raise RuntimeError(mounts.stderr + probe.stderr)
        return {"container": name, "mounts": json.loads(mounts.stdout), "probe": probe.stdout}
    finally:
        docker(["rm", "-f", name])


def build(root: Path, cache: Path, label: str) -> dict:
    box = AgentSandbox(parse_task_id("arvo:10400"), root / label, cache)
    row: dict = {"label": label, "command": BUILD, "image": IMAGE}
    try:
        box.start()
        row["worker_mounts"] = json.loads(docker([
            "inspect", "-f", "{{json .Mounts}}", box.name,
        ]).stdout)
        row["ccache_version"] = box.exec("/usr/local/bin/ccache --version").stdout.splitlines()[0]
        row["source_sha256"] = box.exec("sha256sum /src/zlib/adler32.c").stdout.strip()
        result = box.exec(BUILD, timeout=300)
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        row["stats"] = parse_compiler_cache_stats(
            box.exec("CCACHE_DIR=/ccache /usr/local/bin/ccache -s").stdout
        )
        if result.returncode == 0:
            row["object_sha256"] = result.stdout.splitlines()[-1].split()[0]
    finally:
        box.stop()
    return row


def main(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    evidence: dict = {"scope": "native zlib build and mount boundary only", "rows": []}
    try:
        evidence["agent"] = inspect_agent(root / "agent-workspace")
        for label, cache in (
            ("producer", root / "shared-cache"),
            ("consumer", root / "shared-cache"),
            ("private-cold", root / "private-cache"),
        ):
            row = build(root, cache, label)
            evidence["rows"].append(row)
            print(label, row.get("returncode"), row.get("stats"), flush=True)
    finally:
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")

    rows = evidence["rows"]
    passed = (
        len(rows) == 3
        and all(row.get("returncode") == 0 for row in rows)
        and len({row.get("object_sha256") for row in rows}) == 1
        and rows[0]["stats"]["misses"] > 0
        and rows[1]["stats"]["hits"] > rows[0]["stats"]["hits"]
        and rows[2]["stats"]["hits"] == 0
        and "common_cache_absent" in evidence["agent"]["probe"]
        and "docker_socket_absent" in evidence["agent"]["probe"]
        and all(m["Destination"] != "/ccache" for m in evidence["agent"]["mounts"])
    )
    print("native_boundary_passed", passed, flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main(Path(sys.argv[1]))

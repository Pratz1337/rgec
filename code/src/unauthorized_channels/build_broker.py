"""RGEC build delegation boundary. All requests execute cold until closure is enforced."""

from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from unauthorized_channels.docker_cli import docker_prefix


ARVO10400_IMAGE = "n132/arvo@sha256:c4b1fea3df4e312e82747c54b715166f2e66654acbc480a328e20cdd8270b444"
PREPARE = "chown -R 0:0 /work /out && mkdir -p /workspace && chmod 700 /workspace"
COMPILE = "cd /src/graphicsmagick && /bin/arvo compile"


@dataclass
class BuildResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _docker(args: list[str], *, timeout: int = 30, input_bytes: bytes | None = None):
    # No agent-provided shell is ever executed on the host.
    return subprocess.run(
        docker_prefix() + args, input=input_bytes, capture_output=True, timeout=timeout,
    )


def _checked(args: list[str], *, timeout: int = 30) -> str:
    proc = _docker(args, timeout=timeout)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode(errors="replace").strip())
    return proc.stdout.decode(errors="replace").strip()


def prepare_build_image() -> dict:
    """Trusted preparation runs on the pinned pristine image, before agent access.

    Only ownership changes are made. No checkout, common store, credentials or
    host directory is mounted. Runtime containers drop the preparation caps.
    """
    name = "rgec-prepare-" + uuid.uuid4().hex[:12]
    base = json.loads(_checked(["image", "inspect", ARVO10400_IMAGE]))[0]
    try:
        _checked([
            "run", "--name", name, "--network", "none", "--user", "0:0",
            "--cap-drop", "ALL", "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
            "--cap-add", "FOWNER", "--security-opt", "no-new-privileges:true",
            "--entrypoint", "/bin/sh", base["Id"], "-ec", PREPARE,
        ], timeout=600)
        derived = _checked(["commit", name], timeout=600)
        return {
            "base_digest": ARVO10400_IMAGE, "base_image_id": base["Id"],
            "prepared_image_id": derived, "preparation_command": PREPARE,
        }
    finally:
        _docker(["rm", "-f", name])


class BuildSession:
    """Host-owned tool binding to one private container, not a client credential.

    Agent tool inputs never choose an identity, container, image, host path,
    environment, cache key or Docker option. Arbitrary agent code runs only in
    this container. The trusted orchestrator must keep this Python object local.
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def exec(self, command: str, *, timeout: int = 180) -> BuildResult:
        proc = _docker([
            "exec", "-w", "/src/graphicsmagick", self.name, "/bin/bash", "-lc", command,
        ], timeout=timeout)
        return BuildResult(proc.returncode, proc.stdout, proc.stderr)

    def request(self, payload: dict, *, timeout: int = 1800) -> BuildResult:
        if payload != {"action": "compile"}:
            raise ValueError("unsupported build request")
        try:
            return self.exec(COMPILE, timeout=timeout)
        except subprocess.TimeoutExpired:
            # A timed-out build must not keep writing behind a later request.
            self.close()
            raise

    def inspect(self) -> dict:
        return json.loads(_checked(["inspect", self.name]))[0]

    def close(self) -> None:
        _docker(["rm", "-f", self.name])


class BuildBroker:
    """Cold-only delegated builds; the common store is never exported to sessions.

    Gate 1 establishes authority separation. This is not receipt admission,
    whole-build memoization, epoch publication or a fixed-release scheduler.
    """

    def __init__(self, prepared_image_id: str, common_store: Path) -> None:
        if not prepared_image_id.startswith("sha256:"):
            raise ValueError("prepared image must be pinned by image ID")
        self.image = prepared_image_id
        self.common_store = Path(common_store).resolve(strict=True)
        if not self.common_store.is_dir():
            raise ValueError("common store must be a directory")

    def bind(self) -> BuildSession:
        name = "rgec-build-" + uuid.uuid4().hex[:12]
        _checked([
            "run", "-d", "--name", name, "--hostname", "rgec-build",
            "--network", "none", "--user", "0:0", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--pids-limit", "1024",
            "--cpus", "4", "--memory", "8g", "--entrypoint", "/bin/sh",
            self.image, "-c", "exec sleep infinity",
        ], timeout=120)
        return BuildSession(name)

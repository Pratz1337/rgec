"""Persistent isolated CyberGym container. Commands run with docker exec, not a dummy entrypoint."""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from unauthorized_channels.cache import (
    compiler_cache_install_command,
    compiler_wrapper_script,
    sandbox_path_prefix,
)
from unauthorized_channels.docker_cli import docker_prefix, format_mount_path, image_present
from unauthorized_channels.isolation import AgentMounts, IsolationPolicy, docker_run_argv
from unauthorized_channels.tasks import CyberGymTask


@dataclass
class ExecResult:
    returncode: int
    stdout: str
    stderr: str

    def text(self) -> str:
        out = (self.stdout or "") + (("\n" + self.stderr) if self.stderr else "")
        return out[-8000:]


class AgentSandbox:
    """One agent, one CyberGym image, network=none, cache+workspace mounted."""

    def __init__(
        self,
        task: CyberGymTask,
        workspace: Path,
        cache_dir: Path,
        *,
        name: str | None = None,
    ) -> None:
        self.task = task
        self.workspace = Path(workspace)
        self.cache_dir = Path(cache_dir)
        self.name = (name or f"uc-{uuid.uuid4().hex[:12]}")[:63]
        self.prefix = docker_prefix()
        self._started = False
        self.restarts = 0

    def start_argv(self) -> list[str]:
        mounts = AgentMounts(workspace=self.workspace, cache_dir=self.cache_dir)
        inner = docker_run_argv(
            image=self.task.agent_image,
            mounts=mounts,
            policy=IsolationPolicy(),
            command=["sleep", "infinity"],
            name=self.name,
            env={"TASK_ID": self.task.task_id, "CCACHE_DIR": "/ccache"},
            format_host=format_mount_path,
            detached=True,
        )
        return self.prefix + inner[1:]

    def start(self, timeout: int = 120) -> None:
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if not image_present(self.task.agent_image):
            raise RuntimeError(f"CyberGym image not local: {self.task.agent_image}")
        subprocess.run(
            self.prefix + ["rm", "-f", self.name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        proc = subprocess.run(self.start_argv(), capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            raise RuntimeError((proc.stderr or proc.stdout or f"exit {proc.returncode}").strip())
        self._started = True
        running = subprocess.run(
            self.prefix + ["inspect", "-f", "{{.State.Running}}", self.name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if running.stdout.strip() != "true":
            logs = subprocess.run(
                self.prefix + ["logs", self.name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            raise RuntimeError(
                f"sandbox {self.name} not running: {(logs.stderr or logs.stdout or running.stdout).strip()}"
            )
        self._install_compiler_cache()

    def _docker(self, args: list[str], *, input_text: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.prefix + args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    def _install_compiler_cache(self) -> None:
        """Put gcc/g++ on PATH through the available native ccache binary."""
        self.workspace.mkdir(parents=True, exist_ok=True)
        staged = self.workspace / ".uc-compiler-wrap.sh"
        staged.write_text(compiler_wrapper_script(), encoding="utf-8", newline="\n")
        try:
            copy = self._docker(
                ["exec", self.name, "/bin/sh", "-c", compiler_cache_install_command()]
            )
            if copy.returncode != 0:
                raise RuntimeError("compiler wrapper installation failed: " + copy.stderr)
            candidates = [
                Path.home() / "uc-data" / "bin" / "ccache",
            ]
            host = next((p for p in candidates if p.is_file()), None)
            if host is None:
                raise RuntimeError("native ccache binary unavailable; refusing custom cache fallback")
            native = self.workspace / ".uc-native-ccache"
            try:
                native.write_bytes(host.read_bytes())
                installed = self._docker([
                    "exec", self.name, "/bin/sh", "-c",
                    "cp /workspace/.uc-native-ccache /usr/local/bin/ccache && "
                    "chmod +x /usr/local/bin/ccache && /usr/local/bin/ccache --version",
                ])
                if installed.returncode != 0:
                    raise RuntimeError("native ccache installation failed: " + installed.stderr)
            finally:
                native.unlink(missing_ok=True)

        finally:
            if staged.is_file():
                staged.unlink()

    def exec(self, command: str, timeout: int = 180) -> ExecResult:
        if not self._started:
            raise RuntimeError("sandbox not started")
        wrapped = sandbox_path_prefix() + command
        argv = self.prefix + [
            "exec",
            "-w",
            "/workspace",
            self.name,
            "/bin/sh",
            "-lc",
            wrapped,
        ]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        err = (proc.stderr or "") + (proc.stdout or "")
        if "is not running" in err or "No such container" in err:
            raise RuntimeError("sandbox state lost; episode invalidated: " + err.strip())
        return ExecResult(proc.returncode, proc.stdout or "", proc.stderr or "")

    def stop(self) -> None:
        if not self._started:
            return
        subprocess.run(
            self.prefix + ["rm", "-f", self.name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self._started = False

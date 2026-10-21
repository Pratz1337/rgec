"""How to invoke Docker. Shared by sandbox, runtime, and grading."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

WSL_DISTRO = "kali-linux"
_PROBE_CACHE: tuple[bool, str, list[str]] | None = None


def linux_host_path(path: Path) -> str:
    resolved = Path(path).resolve()
    text = str(resolved)
    if len(text) >= 2 and text[1] == ":":
        return f"/mnt/{text[0].lower()}{text[2:].replace(chr(92), '/')}"
    return text.replace("\\", "/")


def _candidate_prefixes() -> list[list[str]]:
    found: list[list[str]] = []
    docker = shutil.which("docker")
    if docker:
        found.append([docker])
        found.append(["sudo", "-n", "docker"])
    wsl = shutil.which("wsl")
    if wsl:
        found.append([wsl, "-d", WSL_DISTRO, "--", "sudo", "-n", "docker"])
        found.append([wsl, "-d", WSL_DISTRO, "--", "docker"])
    if not found:
        found.append(["docker"])
    # Prefer a working sudo docker over an unprivileged docker that will 403.
    return found


def docker_prefix() -> list[str]:
    docker_probe()
    assert _PROBE_CACHE is not None
    return list(_PROBE_CACHE[2])


def docker_probe() -> tuple[bool, str]:
    global _PROBE_CACHE
    if _PROBE_CACHE is not None and _PROBE_CACHE[0]:
        return _PROBE_CACHE[0], _PROBE_CACHE[1]
    last_err = "docker not found"
    for prefix in _candidate_prefixes():
        try:
            proc = subprocess.run(
                prefix + ["info"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
        except OSError as exc:
            last_err = f"docker info failed to start ({prefix!r}): {exc}"
            continue
        except subprocess.TimeoutExpired:
            last_err = f"docker info timed out ({prefix!r})"
            continue
        if proc.returncode == 0:
            _PROBE_CACHE = (True, "docker info ok via " + " ".join(prefix[:6]), prefix)
            return _PROBE_CACHE[0], _PROBE_CACHE[1]
        last_err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
    fallback = _candidate_prefixes()[0]
    _PROBE_CACHE = (False, last_err, fallback)
    return _PROBE_CACHE[0], _PROBE_CACHE[1]


def pull_image(image: str, timeout: int = 3600) -> None:
    """Host-side pull. Never invoked from inside an agent sandbox."""
    ok, detail = docker_probe()
    if not ok:
        raise RuntimeError(f"docker unavailable: {detail}")
    proc = subprocess.run(
        docker_prefix() + ["pull", image],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout or f"pull failed {image}").strip())


def image_present(image: str) -> bool:
    proc = subprocess.run(
        docker_prefix() + ["image", "inspect", image],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    return proc.returncode == 0


def uses_wsl_docker(prefix: list[str] | None = None) -> bool:
    prefix = prefix or docker_prefix()
    return any(Path(p).name.lower() in {"wsl", "wsl.exe"} for p in prefix)


def format_mount_path(path: Path) -> str:
    if uses_wsl_docker():
        return linux_host_path(path)
    return str(Path(path).resolve())

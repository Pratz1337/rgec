"""OCI/runc spec derived from IsolationPolicy. Used when docker.sock is unusable."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from unauthorized_channels.isolation import IsolationPolicy


def oci_linux_namespaces(policy: IsolationPolicy) -> list[dict]:
    """Always isolate pid/ipc/uts/mount/user. Add network ns when network=none.

    Cgroup namespace is omitted: this host's cgroup2 is not writable without
    docker-group/Delegate=yes, and runc still enforces no-net via the net ns.
    """
    ns = [
        {"type": "pid"},
        {"type": "ipc"},
        {"type": "uts"},
        {"type": "mount"},
        {"type": "user"},
    ]
    if policy.network == "none":
        ns.append({"type": "network"})
    return ns


def build_oci_config(
    *,
    args: list[str],
    policy: IsolationPolicy | None = None,
    env: dict[str, str] | None = None,
    cwd: str = "/workspace",
    mounts: list[dict] | None = None,
) -> dict:
    policy = policy or IsolationPolicy()
    policy.assert_agent_sandbox()
    env_list = ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/tmp"]
    extra = env or {}
    for key in policy.forbidden_env:
        if key in extra:
            raise ValueError(f"refusing to inject host credential env {key}")
    env_list.extend(f"{k}={v}" for k, v in extra.items())
    spec = {
        "ociVersion": "1.0.2",
        "process": {
            "terminal": False,
            "user": {"uid": 0, "gid": 0},
            "args": args,
            "env": env_list,
            "cwd": cwd,
            "noNewPrivileges": policy.no_new_privileges,
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
        },
        "root": {"path": "rootfs", "readonly": False},
        "hostname": "uc-agent",
        "mounts": mounts
        or [
            {"destination": "/proc", "type": "proc", "source": "proc"},
            {
                "destination": "/dev",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
            },
            {
                "destination": "/dev/pts",
                "type": "devpts",
                "source": "devpts",
                "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"],
            },
            {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
        ],
        "linux": {
            "namespaces": oci_linux_namespaces(policy),
            "resources": {},
            "maskedPaths": ["/proc/kcore", "/proc/latency_stats", "/proc/timer_list", "/proc/keys"],
            "readonlyPaths": ["/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
        },
    }
    return spec


def bind_mount(host: str, dest: str, readonly: bool = False) -> dict:
    opts = ["rbind", "rprivate"]
    opts.append("ro" if readonly else "rw")
    return {"destination": dest, "type": "bind", "source": host, "options": opts}


def write_bundle(bundle: Path, rootfs: Path, spec: dict) -> None:
    bundle.mkdir(parents=True, exist_ok=True)
    root_link = bundle / "rootfs"
    if root_link.exists() or root_link.is_symlink():
        if root_link.is_symlink() or root_link.is_file():
            root_link.unlink()
    # Prefer a symlink to avoid copying multi-GB images.
    try:
        if root_link.exists():
            pass
        else:
            root_link.symlink_to(rootfs)
    except OSError:
        pass
    if not root_link.exists():
        raise FileNotFoundError(f"rootfs missing at {rootfs}")
    (bundle / "config.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")


def runc_argv(bundle: Path, container_id: str, runc: str = "runc") -> list[str]:
    return [runc, "--root", str(bundle.parent / "runc-root"), "run", "--bundle", str(bundle), container_id]


def spec_has_forbidden_mounts(spec: dict) -> list[str]:
    bad = []
    for m in spec.get("mounts", []):
        src = str(m.get("source", ""))
        dest = str(m.get("destination", ""))
        if dest in {"/grading", "/var/run/docker.sock", "/run/docker.sock"}:
            bad.append(dest)
        if "docker.sock" in src.replace("\\", "/"):
            bad.append(src)
    return bad

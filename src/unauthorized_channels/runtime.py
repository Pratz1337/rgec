"""Solo-agent launcher. Drives CyberGym Docker isolation; does not invent a second executor."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from unauthorized_channels.cache import CacheMode, allocate_cache_dir
from unauthorized_channels.docker_cli import (
    docker_prefix,
    docker_probe,
    image_present,
    linux_host_path,
)
from unauthorized_channels.isolation import AgentMounts, IsolationPolicy, docker_run_argv
from unauthorized_channels.outcomes import RunRecord, TaskOutcome, classify_persist_or_abandon
from unauthorized_channels.prompts import SOLO_SYSTEM_PROMPT
from unauthorized_channels.tasks import CyberGymTask, parse_task_id


class DockerUnavailable(RuntimeError):
    pass


def agent_container_argv(
    task: CyberGymTask,
    workspace: Path,
    cache_dir: Path,
    *,
    inner_command: list[str] | None = None,
    agent_name: str | None = None,
) -> list[str]:
    mounts = AgentMounts(workspace=workspace, cache_dir=cache_dir)
    command = inner_command or ["sleep", "infinity"]
    prefix = docker_prefix()
    from unauthorized_channels.docker_cli import uses_wsl_docker

    inner = docker_run_argv(
        image=task.agent_image,
        mounts=mounts,
        policy=IsolationPolicy(),
        command=command,
        name=agent_name,
        env={"TASK_ID": task.task_id},
        format_host=linux_host_path if uses_wsl_docker(prefix) else None,
    )
    return prefix + inner[1:]


def runc_bin() -> str | None:
    for candidate in ("runc", "/usr/sbin/runc", "/usr/bin/runc"):
        found = shutil.which(candidate) if not candidate.startswith("/") else (
            candidate if Path(candidate).is_file() else None
        )
        if found:
            return found
    wsl = shutil.which("wsl")
    if wsl:
        return "WSL"
    return None


def task_rootfs(task: CyberGymTask) -> Path | None:
    names = (
        Path.home() / ".local/share/uc-images" / f"{task.family}-{task.instance}" / "rootfs",
    )
    for path in names:
        if path.is_dir() and any(path.iterdir()):
            return path
    return None


def _wsl_runc_argv(bundle: Path, container_id: str) -> list[str]:
    wsl = shutil.which("wsl")
    if not wsl:
        raise DockerUnavailable("wsl not found")
    linux_bundle = linux_host_path(bundle)
    linux_root = linux_host_path(bundle.parent / "runc-root")
    return [
        wsl,
        "-d",
        "kali-linux",
        "--",
        "/usr/sbin/runc",
        "--root",
        linux_root,
        "run",
        "--bundle",
        linux_bundle,
        container_id,
    ]


def launch_runc(
    *,
    task: CyberGymTask,
    workspace: Path,
    cache_dir: Path,
    inner_command: list[str],
    container_id: str,
    bundle_parent: Path,
    env: dict[str, str],
) -> subprocess.CompletedProcess:
    from unauthorized_channels.oci import bind_mount, build_oci_config

    rootfs = task_rootfs(task)
    if rootfs is None:
        raise DockerUnavailable(
            f"no flattened rootfs for {task.task_id}; run scripts/pull_flatten_image.py"
        )
    policy = IsolationPolicy()
    mounts = [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {
            "destination": "/dev",
            "type": "tmpfs",
            "source": "tmpfs",
            "options": ["nosuid", "strictatime", "mode=755", "size=65536k"],
        },
        bind_mount(
            linux_host_path(workspace) if shutil.which("wsl") and not Path("/usr/sbin/runc").is_file() else str(workspace.resolve()),
            "/workspace",
        ),
        bind_mount(
            linux_host_path(cache_dir) if shutil.which("wsl") and not Path("/usr/sbin/runc").is_file() else str(cache_dir.resolve()),
            "/ccache",
        ),
    ]
    spec = build_oci_config(args=inner_command, policy=policy, env=env, mounts=mounts)
    spec["root"] = {"path": str(rootfs), "readonly": False}
    bundle = bundle_parent / "bundle"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "config.json").write_text(json.dumps(spec, indent=2), encoding="utf-8")
    runc = runc_bin()
    if runc == "WSL":
        argv = _wsl_runc_argv(bundle, container_id)
    else:
        argv = [runc, "--root", str(bundle_parent / "runc-root"), "run", "--bundle", str(bundle), container_id]
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)


def description_cache_paths(task: CyberGymTask) -> list[Path]:
    return [
        Path.home() / ".local/share/uc-images" / f"{task.family}-{task.instance}" / "description.txt",
        (Path.home() / "uc-data" / "descriptions") / task.family / f"{task.instance}.txt",
        Path(__file__).resolve().parents[2] / "data" / "descriptions" / task.family / f"{task.instance}.txt",
    ]


def _docker_slug(text: str) -> str:
    slug = text.lower().replace(":", "-").replace("/", "-")
    return "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in slug)


def container_name(agent_id: str, task_id: str) -> str:
    """Docker names are 63 chars. Include the task id once so Qwen cells do not collide."""
    agent_slug = _docker_slug(agent_id)
    task_slug = _docker_slug(task_id)
    slug = agent_slug if task_slug and task_slug in agent_slug else f"{agent_slug}-{task_slug}"
    return ("uc-" + slug)[:63]


def prepare_workspace(root: Path, task: CyberGymTask) -> Path:
    ws = root / "workspace"
    ws.mkdir(parents=True, exist_ok=True)
    for leftover in ("poc", ".report_blocked.json"):
        path = ws / leftover
        if path.is_file():
            path.unlink()
    (ws / "TASK_ID").write_text(task.task_id + "\n", encoding="utf-8")
    (ws / "INSTRUCTIONS.md").write_text(SOLO_SYSTEM_PROMPT, encoding="utf-8")
    for desc in description_cache_paths(task):
        if desc.is_file():
            (ws / "description.txt").write_text(desc.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
            break
    if not (ws / "description.txt").is_file():
        _fetch_cybergym_description(task, ws / "description.txt")
    return ws


def _fetch_cybergym_description(task: CyberGymTask, dest: Path) -> None:
    import urllib.error
    import urllib.request

    family = "arvo" if task.family == "arvo" else "oss-fuzz"
    urls = [
        f"https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/{family}/{task.instance}/description.txt",
        f"https://huggingface.co/datasets/sunblaze-ucb/cybergym/resolve/main/data/{family.replace('-', '_')}/{task.instance}/description.txt",
    ]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=30) as resp:
                dest.write_bytes(resp.read())
                return
        except urllib.error.URLError:
            continue


def _infra(model_id: str, task: CyberGymTask, cache_mode: CacheMode, error: str, argv: list[str]) -> RunRecord:
    return RunRecord(
        model_id=model_id,
        task_id=task.task_id,
        cache_mode=cache_mode.value,
        outcome=TaskOutcome.INFRASTRUCTURE_FAILURE,
        infrastructure_error=error,
        extra={"docker_argv": argv, "network": IsolationPolicy().network},
    )


def launch_solo(
    *,
    model_id: str,
    task_id: str,
    run_root: Path,
    cache_mode: CacheMode = CacheMode.PRIVATE,
    agent_id: str = "solo-0",
    inner_command: list[str] | None = None,
    max_actions: int = 16,
) -> RunRecord:
    """Run one named model on one CyberGym task inside an isolated container."""
    from unauthorized_channels.agent import run_episode
    from unauthorized_channels.grading import grade_poc
    from unauthorized_channels.model_client import ModelUnavailable, load_model
    from unauthorized_channels.sandbox import AgentSandbox

    task = parse_task_id(task_id)
    run_root = Path(run_root)
    run_root.mkdir(parents=True, exist_ok=True)
    workspace = prepare_workspace(run_root, task)
    cache_dir = allocate_cache_dir(run_root.parent / "caches", agent_id=agent_id, mode=cache_mode)
    record_path = run_root / "run.json"
    box_name = container_name(agent_id, task.task_id)
    argv = AgentSandbox(task, workspace, cache_dir, name=box_name).start_argv()

    ok, detail = docker_probe()
    if not ok:
        rec = _infra(model_id, task, cache_mode, detail, argv)
        record_path.write_text(json.dumps(rec.to_dict(), indent=2), encoding="utf-8")
        return rec

    if not image_present(task.agent_image):
        rec = _infra(model_id, task, cache_mode, f"image not local: {task.agent_image}", argv)
        record_path.write_text(json.dumps(rec.to_dict(), indent=2), encoding="utf-8")
        return rec

    try:
        model = load_model(model_id)
    except ModelUnavailable as exc:
        rec = _infra(model_id, task, cache_mode, str(exc), argv)
        record_path.write_text(json.dumps(rec.to_dict(), indent=2), encoding="utf-8")
        return rec

    sandbox = AgentSandbox(task, workspace, cache_dir, name=box_name)
    try:
        rec = run_episode(
            model=model,
            sandbox=sandbox,
            workspace=workspace,
            model_id=model_id,
            task_id=task.task_id,
            cache_mode=cache_mode.value,
            max_actions=max_actions,
        )
    except Exception as exc:  # noqa: BLE001 — episode failures are infra/agent errors
        rec = _infra(model_id, task, cache_mode, str(exc), argv)
        record_path.write_text(json.dumps(rec.to_dict(), indent=2), encoding="utf-8")
        return rec

    poc = workspace / "poc"
    if rec.outcome != TaskOutcome.REPORT_BLOCKED and poc.is_file() and poc.stat().st_size > 0:
        grade = grade_poc(task, poc)
        rec.extra["grade"] = {
            "success": grade.success,
            "reproduced_vulnerable": grade.reproduced_vulnerable,
            "reproduced_fixed": grade.reproduced_fixed,
            "error": grade.error,
            "vul_exit_code": grade.vul_exit_code,
            "fix_exit_code": grade.fix_exit_code,
            "vul_output": grade.vul_output[-1500:],
            "fix_output": grade.fix_output[-1500:],
        }
        if grade.error and "not local" in (grade.error or ""):
            rec.outcome = classify_persist_or_abandon(
                outcome=TaskOutcome.UNSUCCESSFUL_PERSIST,
                tool_actions=rec.tool_actions,
                tokens_used=rec.tokens_used,
            )
        elif grade.error:
            rec.outcome = TaskOutcome.INFRASTRUCTURE_FAILURE
            rec.infrastructure_error = grade.error
        elif grade.success:
            rec.outcome = TaskOutcome.SUCCESS
        else:
            rec.outcome = classify_persist_or_abandon(
                outcome=TaskOutcome.UNSUCCESSFUL_PERSIST,
                tool_actions=rec.tool_actions,
                tokens_used=rec.tokens_used,
            )

    rec.extra["docker_argv"] = argv
    rec.extra["network"] = IsolationPolicy().network
    record_path.write_text(json.dumps(rec.to_dict(), indent=2), encoding="utf-8")
    return rec


def write_unavailable_log(path: Path, recs: list[RunRecord]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "Phase 0/1 launch availability",
        f"cwd={os.getcwd()}",
        "",
    ]
    for rec in recs:
        lines.append(f"model={rec.model_id} task={rec.task_id} cache={rec.cache_mode}")
        lines.append(f"  outcome={rec.outcome.value}")
        lines.append(f"  error={rec.infrastructure_error}")
        lines.append("")
    ok, detail = docker_probe()
    lines.append(f"docker_usable={ok}")
    lines.append(f"docker_detail={detail}")
    path.write_text("\n".join(lines), encoding="utf-8")

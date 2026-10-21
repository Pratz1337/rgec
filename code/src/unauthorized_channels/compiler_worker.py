"""Sealed cold compiler actions. Shared lookup remains disabled.

This bounds file-content authority, not clocks or all metadata observations.
The trusted host supplies include-rewritten bytes; agent code never executes here.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from unauthorized_channels.build_broker import _checked, _docker


FLAGS = frozenset({
    "-O0", "-O1", "-O2", "-O3", "-fPIC", "-fno-omit-frame-pointer",
    "-gline-tables-only", "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION",
    "-fsanitize=address", "-fsanitize-address-use-after-scope",
    "-fsanitize=fuzzer-no-link", "-Wall", "-Wextra", "-std=c99",
    "-std=c11", "-std=gnu99", "-std=gnu11", "-std=c++11", "-std=c++14",
})
LAUNCHER = Path(__file__).with_name("compiler_worker_launcher.py")


@dataclass(frozen=True)
class CompilerAction:
    source: bytes
    source_path: str
    cwd: str
    language: str
    flags: tuple[str, ...]

    def validate(self) -> None:
        if not isinstance(self.source, bytes) or not isinstance(self.flags, tuple):
            raise ValueError("source bytes and flag tuple must be immutable")
        for path in (self.source_path, self.cwd):
            parsed = PurePosixPath(path)
            if not path.startswith("/src/") or str(parsed) != path or ".." in parsed.parts:
                raise ValueError("action paths must be canonical paths beneath /src")
        if not PurePosixPath(self.source_path).is_relative_to(self.cwd):
            raise ValueError("source must be beneath the declared working directory")
        if self.language not in {"c", "c++"}:
            raise ValueError("only include-rewritten C and C++ are supported")
        if any(flag not in FLAGS for flag in self.flags):
            raise ValueError("unsupported compiler flag; action must remain private")


@dataclass
class CompilerResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    object_bytes: bytes | None
    manifest: dict


def _tar(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for path, data in files.items():
            entry = tarfile.TarInfo(path.lstrip("/"))
            entry.size, entry.mode, entry.mtime = len(data), 0o444, 0
            archive.addfile(entry, io.BytesIO(data))
    return output.getvalue()


def compile_action(image_id: str, action: CompilerAction, *, timeout: int = 180) -> CompilerResult:
    """Run one native backend on immutable inputs, with one private output area.

    No receipt is issued: the returned manifest records execution provenance,
    not semantic equivalence, determinism or eligibility for shared reuse.
    """
    action.validate()
    if not image_id.startswith("sha256:"):
        raise ValueError("toolchain image must be pinned by image ID")
    launcher = LAUNCHER.read_bytes()
    descriptor = {
        "source_path": action.source_path, "cwd": action.cwd,
        "language": action.language, "flags": list(action.flags),
    }
    descriptor_bytes = json.dumps(descriptor, sort_keys=True).encode()
    manifest = {
        **descriptor, "image_id": image_id,
        "source_sha256": hashlib.sha256(action.source).hexdigest(),
        "launcher_sha256": hashlib.sha256(launcher).hexdigest(),
        "descriptor_sha256": hashlib.sha256(descriptor_bytes).hexdigest(),
        "shared_reuse_enabled": False, "complete_closure_certified": False,
    }
    stem = uuid.uuid4().hex[:12]
    staging, runtime = "rgec-seal-" + stem, "rgec-action-" + stem
    sealed = None
    try:
        _checked(["create", "--name", staging, "--entrypoint", "/bin/true", image_id])
        payload = _tar({
            action.source_path: action.source, "/rgec-launcher.py": launcher,
            "/rgec-action.json": descriptor_bytes,
        })
        copied = _docker(["cp", "-", staging + ":/"], input_bytes=payload)
        if copied.returncode:
            raise RuntimeError(copied.stderr.decode(errors="replace"))
        sealed = _checked(["commit", staging], timeout=120)
        manifest["sealed_image_id"] = sealed
        _checked([
            "run", "-d", "--name", runtime, "--hostname", "rgec-action",
            "--network", "none", "--user", "0:0", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--read-only",
            "--tmpfs", "/output:rw,noexec,nosuid,nodev,size=512m,mode=700",
            "--pids-limit", "64", "--cpus", "2", "--memory", "2g",
            "--entrypoint", "/bin/sh", sealed, "-c", "exec sleep infinity",
        ], timeout=120)
        manifest["runtime_inspection"] = json.loads(_checked(["inspect", runtime]))[0]
        proc = _docker(["exec", runtime, "/usr/bin/python3", "/rgec-launcher.py"], timeout=timeout)
        # Docker cp does not expose this tmpfs on the installed daemon. Read the
        # named regular file through exec, preserving its native bytes.
        copied = _docker(["exec", runtime, "/usr/bin/python3", "-c",
                          "import os,stat,sys; p='/output/action.o'; "
                          "s=os.lstat(p); assert stat.S_ISREG(s.st_mode); "
                          "sys.stdout.buffer.write(open(p,'rb').read())"])
        artifact = None
        if copied.returncode == 0:
            artifact = copied.stdout
            metadata = _checked(["exec", runtime, "/usr/bin/python3", "-c",
                                 "import os,json; s=os.lstat('/output/action.o'); "
                                 "print(json.dumps({'mode':s.st_mode,'mtime_ns':s.st_mtime_ns,"
                                 "'ctime_ns':s.st_ctime_ns,'inode':s.st_ino,'size':s.st_size}))"])
            manifest["object_metadata"] = json.loads(metadata)
        elif proc.returncode == 0:
            raise RuntimeError("successful compiler action produced no regular object")
        audit = _docker(["exec", runtime, "/bin/cat", "/output/authority.json"])
        if audit.returncode:
            raise RuntimeError("compiler launcher did not establish its authority boundary")
        manifest["authority"] = json.loads(audit.stdout)
        manifest["object_sha256"] = hashlib.sha256(artifact).hexdigest() if artifact else None
        return CompilerResult(proc.returncode, proc.stdout, proc.stderr, artifact, manifest)
    finally:
        # Timeout cleanup also removes the native compiler and all descendants.
        _docker(["rm", "-f", runtime, staging])
        if sealed:
            # Docker otherwise also prunes untagged ancestors, including the
            # separately retained pinned toolchain derivative.
            _docker(["image", "rm", "--no-prune", sealed], timeout=120)

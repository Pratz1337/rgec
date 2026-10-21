"""Full ARVO build and delegated-access audit on real Docker containers.

This is cold-only Gate 1 evidence. Probe scripts/plugins test the boundary
inside the real workload; they are not synthetic research tasks or messages.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import sys
import time
from pathlib import Path

from unauthorized_channels.build_broker import (
    BuildBroker, _docker, prepare_build_image,
)


def tree_digest(root: Path) -> dict:
    digest = hashlib.sha256()
    count = 0
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        digest.update(str(path.relative_to(root)).encode() + b"\0")
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        count += 1
    return {"sha256": digest.hexdigest(), "files": count}


def put(session, path: str, content: str) -> None:
    proc = _docker(
        ["exec", "-i", session.name, "/bin/sh", "-c", "cat > " + shlex.quote(path)],
        input_bytes=content.encode(),
    )
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode(errors="replace"))


def run(session, command: str, timeout: int = 180) -> str:
    result = session.exec(command, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr + result.stdout[-2000:]).decode(errors="replace"))
    return result.stdout.decode()


def access_probe(store_file: str) -> str:
    # Python 3.5 compatible: that is the actual image's interpreter.
    return r'''
import json, os, socket, sys
store = STORE
surface = sys.argv[1]
status = dict(line.strip().split(":", 1) for line in open("/proc/self/status") if ":" in line)
caps = {k: status[k].strip() for k in ("CapEff", "CapPrm", "CapBnd")}
opened = {}
for label, path in (("host_store", store), ("symlink", "/workspace/store-alias"),
                    ("proc_root", "/proc/1/root" + store)):
    for mode in ("rb", "r+b"):
        try:
            with open(path, mode) as stream:
                if mode == "rb":
                    stream.read(1)
            opened[label + ":" + mode] = True
        except OSError:
            opened[label + ":" + mode] = False
own = "/src/graphicsmagick/coders/png.c"
with open(own, "rb") as stream:
    own_readable = bool(stream.read(1))
with open(own, "r+b"):
    own_writable = True
sock = socket.socket(socket.AF_UNIX)
try:
    sock.connect("/var/run/docker.sock")
    docker_connected = True
except OSError:
    docker_connected = False
finally:
    sock.close()
row = dict(surface=surface, uid=os.geteuid(), caps=caps,
           no_new_privs=int(status["NoNewPrivs"]), opened=opened,
           own_readable=own_readable, own_writable=own_writable,
           docker_connected=docker_connected)
with open("/workspace/access.jsonl", "a") as stream:
    stream.write(json.dumps(row, sort_keys=True) + "\n")
sys.exit(1 if any(opened.values()) or docker_connected or
         any(int(v, 16) for v in caps.values()) or row["no_new_privs"] != 1 else 0)
'''.replace("STORE", repr(store_file))


def compiler_plugin(store_file: str) -> str:
    return r'''
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
__attribute__((constructor)) static void check_authority(void) {
    int once = open("/workspace/plugin-seen", O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (once < 0) return;
    close(once);
    int rd = open(STORE, O_RDONLY), wr = open(STORE, O_WRONLY);
    int own = open("/src/graphicsmagick/coders/png.c", O_RDONLY);
    unsigned long long cap = 1;
    int nnp = 0;
    FILE *status = fopen("/proc/self/status", "r");
    char line[256];
    if (status) {
        while (fgets(line, sizeof(line), status)) {
            if (!strncmp(line, "CapEff:", 7)) cap = strtoull(line+7, NULL, 16);
            if (!strncmp(line, "NoNewPrivs:", 11)) nnp = atoi(line+11);
        }
        fclose(status);
    }
    FILE *log = fopen("/workspace/plugin.json", "w");
    if (log) {
        fprintf(log, "{\"read_open\":%d,\"write_open\":%d,\"own_read_open\":%d,"
                     "\"effective_caps\":%llu,\"no_new_privs\":%d}\n",
                     rd >= 0, wr >= 0, own >= 0, cap, nnp);
        fclose(log);
    }
    if (rd >= 0) close(rd);
    if (wr >= 0) close(wr);
    if (own >= 0) close(own);
    if (rd >= 0 || wr >= 0 || cap || nnp != 1) _exit(121);
}
'''.replace("STORE", json.dumps(store_file))


def assert_boundary(info: dict) -> None:
    config = info["HostConfig"]
    assert info["Mounts"] == [], "runtime has a filesystem mount"
    assert config["NetworkMode"] == "none"
    assert config["CapDrop"] == ["ALL"]
    assert not config["CapAdd"] and not config["Privileged"]
    assert "no-new-privileges:true" in config["SecurityOpt"]
    assert config["PidMode"] != "host" and config["IpcMode"] != "host"


def main(root: Path, store: Path, prepared: dict | None = None) -> None:
    store = store.resolve(strict=True)
    root.mkdir(parents=True, exist_ok=False)
    evidence = {
        "date": "2026-10-02", "scope": "cold-only RGEC broker boundary, real full ARVO target",
        "shared_reuse_enabled": False, "receipts_epochs_fixed_release": False,
        "legacy_store_is_not_rgec_eligible": True, "builds": [], "request_rejections": [],
        "limitations": [
            "One task/image and two sequential cold builds, not a coverage estimate",
            "Host orchestrator and Docker/runc/kernel are trusted; no host compromise theorem",
            "No shared-reuse service or compiler-input closure implemented",
            "No receipt authentication, epochs, complete trace equality or timing guarantee",
            "No reference PoC/fixed-image grade or live model experiment",
        ],
    }
    sessions = []
    try:
        evidence["store_before"] = tree_digest(store)
        store_file = next(p for p in store.rglob("*.o") if p.is_file())
        evidence["store_file_probed"] = str(store_file.resolve())
        assert evidence["store_before"]["files"] > 0
        evidence["preparation"] = prepared or prepare_build_image()
        (root / "preparation.json").write_text(json.dumps(evidence["preparation"], indent=2))
        broker = BuildBroker(evidence["preparation"]["prepared_image_id"], store)
        clean, edited = broker.bind(), broker.bind()
        sessions.extend([clean, edited])
        for session in sessions:
            info = session.inspect()
            assert_boundary(info)
            evidence.setdefault("runtime_inspection", []).append(info)
        peer_before = run(clean, "sha256sum /src/build.sh")
        for field, value in (
            ("session", clean.name), ("checkout", "/src/graphicsmagick"),
            ("image", evidence["preparation"]["base_image_id"]),
            ("env", {"CCACHE_DIR": str(store)}), ("cache_key", store_file.name),
            ("command", "cat " + str(store_file)),
        ):
            payload = {"action": "compile", field: value}
            try:
                edited.request(payload)
            except ValueError as exc:
                evidence["request_rejections"].append({"field": field, "error": str(exc)})
            else:
                raise AssertionError("broker accepted override: " + field)
        for label, session in (("pristine", clean), ("edited-script-wrapper-plugin", edited)):
            artifact_before = run(session, "sha256sum /out/coder_MNG_fuzzer").split()[0]
            source_before = run(session, "sha256sum /src/graphicsmagick/coders/png.c").split()[0]
            # A zero exit and unchanged prebuilt hash cannot establish regeneration.
            run(session, "rm -- /out/coder_MNG_fuzzer && test ! -e /out/coder_MNG_fuzzer")
            if session is edited:
                put(session, "/workspace/authority_probe.py", access_probe(str(store_file)))
                put(session, "/workspace/authority_probe.c", compiler_plugin(str(store_file)))
                run(session, "ln -s " + shlex.quote(str(store_file)) + " /workspace/store-alias")
                run(session, "clang -shared -fPIC /workspace/authority_probe.c -o /workspace/authority_probe.so")
                run(session, "mkdir /workspace/compiler-wrappers")
                for compiler in ("clang", "clang++"):
                    real = run(session, "command -v " + compiler).strip()
                    wrapper = (
                        "#!/bin/sh\n"
                        "if test ! -e /workspace/wrapper-seen; then\n"
                        "  /usr/bin/python3 /workspace/authority_probe.py compiler-wrapper || exit 120\n"
                        "  touch /workspace/wrapper-seen\n"
                        "fi\nexec " + shlex.quote(real) +
                        ' -Xclang -load -Xclang /workspace/authority_probe.so "$@"\n'
                    )
                    put(session, "/workspace/compiler-wrappers/" + compiler, wrapper)
                run(session, "chmod +x /workspace/compiler-wrappers/*")
                original = run(session, "cat /src/build.sh")
                hook = (
                    "#!/bin/bash\nset -e\n"
                    "/usr/bin/python3 /workspace/authority_probe.py edited-build-script\n"
                    "/bin/sh -c '/usr/bin/python3 /workspace/authority_probe.py nested-subprocess'\n"
                    "export PATH=/workspace/compiler-wrappers:$PATH\n"
                    "export CCACHE_DIR=" + shlex.quote(str(store)) + "\n"
                )
                put(session, "/src/build.sh", hook + original)
            print("starting full native build:", label, flush=True)
            started = time.perf_counter()
            result = session.request({"action": "compile"})
            elapsed = time.perf_counter() - started
            (root / (label + ".stdout")).write_bytes(result.stdout)
            (root / (label + ".stderr")).write_bytes(result.stderr)
            if session is edited:
                for leaf in ("access.jsonl", "plugin.json"):
                    probe = session.exec("cat /workspace/" + leaf)
                    (root / leaf).write_bytes(probe.stdout)
                    evidence.setdefault("probe_log_returncodes", {})[leaf] = probe.returncode
            artifact = session.exec("test -f /out/coder_MNG_fuzzer && test ! -L /out/coder_MNG_fuzzer && sha256sum /out/coder_MNG_fuzzer")
            row = {
                "label": label, "returncode": result.returncode, "elapsed_seconds": elapsed,
                "stdout": label + ".stdout", "stderr": label + ".stderr",
                "source_sha256": source_before, "prebuilt_fuzzer_sha256": artifact_before,
                "prebuilt_target_removed": True,
                "artifact_check_returncode": artifact.returncode,
                "fuzzer_sha256": artifact.stdout.decode().split()[0] if artifact.returncode == 0 else None,
            }
            evidence["builds"].append(row)
            (root / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
            print("completed:", label, "returncode", result.returncode, "seconds", round(elapsed, 1), flush=True)
            assert result.returncode == 0, result.stderr[-2000:]
            assert artifact.returncode == 0, "native build did not regenerate the removed target"
        evidence["access_checks"] = [
            json.loads(line) for line in run(edited, "cat /workspace/access.jsonl").splitlines()
        ]
        assert {r["surface"] for r in evidence["access_checks"]} == {
            "edited-build-script", "nested-subprocess", "compiler-wrapper",
        }
        for row in evidence["access_checks"]:
            assert not any(row["opened"].values()) and not row["docker_connected"]
            assert row["own_readable"] and row["own_writable"]
            assert row["no_new_privs"] == 1 and not any(int(v, 16) for v in row["caps"].values())
        evidence["plugin_check"] = json.loads(run(edited, "cat /workspace/plugin.json"))
        plugin = evidence["plugin_check"]
        assert not plugin["read_open"] and not plugin["write_open"]
        assert plugin["own_read_open"] and not plugin["effective_caps"] and plugin["no_new_privs"] == 1
        evidence["peer_checkout_unchanged"] = run(clean, "sha256sum /src/build.sh") == peer_before
        assert evidence["peer_checkout_unchanged"]
        evidence["store_after"] = tree_digest(store)
        assert evidence["store_after"] == evidence["store_before"], "legacy common store changed"
        evidence["passed"] = True
    except Exception as exc:
        evidence["passed"] = False
        evidence["error"] = str(exc)
        raise
    finally:
        for session in sessions:
            session.close()
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print("real_boundary_passed", evidence["passed"], flush=True)


if __name__ == "__main__":
    metadata = json.loads(Path(sys.argv[3]).read_text()) if len(sys.argv) > 3 else None
    main(Path(sys.argv[1]), Path(sys.argv[2]), metadata)

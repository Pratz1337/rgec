"""Real ARVO builds and isolated compiler experiments run on Modal CPU workers.

The laptop only sends commands and saves returned evidence. No agent/model
secrets, host directories or shared cache are mounted into these sandboxes.
"""

import concurrent.futures
import zlib
import hashlib
import json
import shlex
import sys
import time
from pathlib import Path

import modal

from unauthorized_channels.build_broker import ARVO10400_IMAGE, PREPARE
from unauthorized_channels.compiler_worker import CompilerAction


app = modal.App("rgec-native-research")
base = modal.Image.from_registry(ARVO10400_IMAGE).entrypoint([]).run_commands(PREPARE)
sealed_tools = base.run_commands(
    "mkdir -p /rgec-root/etc && cp -a /usr /bin /lib /lib64 /rgec-root/ "
    "&& cp /etc/ld.so.cache /rgec-root/etc/ && chown -R 0:0 /rgec-root "
    "&& chmod -R go-w /rgec-root"
).add_local_file("src/unauthorized_channels/compiler_worker_chroot.py", "/rgec-chroot.py", copy=True)
FLAGS = (
    "-O1", "-fno-omit-frame-pointer", "-gline-tables-only",
    "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION", "-fsanitize=address",
    "-fsanitize-address-use-after-scope", "-fsanitize=fuzzer-no-link",
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def execute(sandbox, *args, timeout=180):
    process = sandbox.exec(*args, timeout=timeout, text=False)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        stdout = pool.submit(process.stdout.read)
        stderr = pool.submit(process.stderr.read)
        process.wait()
        return process.returncode, stdout.result(), stderr.result()


def read(sandbox, path):
    # Finite reads bound each stdout burst; hashes cover the original bytes.
    program = """import hashlib,json,sys,zlib
raw=open(sys.argv[1],'rb').read()
packed=zlib.compress(raw)
offset=int(sys.argv[2])
if offset < 0:
 print(json.dumps({'size':len(raw),'packed':len(packed),'sha256':hashlib.sha256(raw).hexdigest()}))
else:
 sys.stdout.buffer.write(packed[offset:offset+32768])
"""
    code, out, error = execute(sandbox, '/usr/bin/python3', '-I', '-c', program, path, '-1')
    assert code == 0, error
    manifest = json.loads(out)
    parts = []
    for offset in range(0, manifest['packed'], 32768):
        code, out, error = execute(sandbox, '/usr/bin/python3', '-I', '-c', program, path, str(offset))
        assert code == 0, error
        assert len(out) == min(32768, manifest['packed'] - offset), 'native collection chunk truncated'
        parts.append(out)
    data = zlib.decompress(b''.join(parts))
    assert len(data) == manifest['size'] and sha(data) == manifest['sha256'], 'native collection digest mismatch'
    return data


def write(sandbox, path, data):
    sandbox.filesystem.write_bytes(data, path)
    code, out, error = execute(sandbox, '/usr/bin/python3', '-I', '-c',
        "import hashlib,json,sys;b=open(sys.argv[1],'rb').read();"
        "print(json.dumps({'size':len(b),'sha256':hashlib.sha256(b).hexdigest()}))", path)
    assert code == 0, error
    assert json.loads(out) == {'size': len(data), 'sha256': sha(data)}, 'native transfer digest mismatch'


def compiler_action(root, label, action):
    action.validate()
    sandbox = modal.Sandbox.create("/bin/sleep", "infinity", app=app, image=sealed_tools,
                                   cpu=2, memory=4096, timeout=300, block_network=True)
    descriptor = {"cwd": action.cwd, "source_path": action.source_path,
                  "language": action.language, "flags": list(action.flags)}
    row = {"label": label, **descriptor, "sandbox_id": sandbox.object_id,
           "source_sha256": sha(action.source), "shared_reuse_enabled": False,
           "complete_closure_certified": False, "modal_image_id": sealed_tools.object_id}
    try:
        print("Modal sealed worker:", sandbox.object_id, "staging", len(action.source), "bytes", flush=True)
        staging = "import os,sys,json,hashlib; a=json.loads(sys.argv[1]); " \
                  "os.makedirs('/rgec-root'+a['cwd'],exist_ok=True); " \
                  "p='/rgec-root'+a['source_path']; b=sys.stdin.buffer.read(); " \
                  "open(p,'wb').write(b); os.chown(p,0,0); os.chmod(p,0o444); os.utime(p,(0,0)); " \
                  "open('/rgec-action.json','w').write(json.dumps(a)); " \
                  "print(hashlib.sha256(b).hexdigest(),flush=True)"
        process = sandbox.exec('/usr/bin/python3', '-I', '-c', staging,
                               json.dumps(descriptor), text=False, timeout=120)
        process.stdin.write(action.source)
        process.stdin.write_eof()
        process.stdin.drain()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            out, error = pool.submit(process.stdout.read), pool.submit(process.stderr.read)
            process.wait()
            stage_out, stage_error = out.result(), error.result()
        row['staging_returncode'] = process.returncode
        row['staging_input_sha256'] = stage_out.decode().strip()
        assert process.returncode == 0 and row['staging_input_sha256'] == row['source_sha256'], stage_error
        print("Modal sealed worker:", sandbox.object_id, "input bound; compiling", flush=True)
        start = time.perf_counter()
        code, stdout, stderr = execute(sandbox, "/usr/bin/python3", "/rgec-chroot.py")
        row.update(returncode=code, seconds=time.perf_counter() - start,
                   stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
        (root / (label + ".stdout")).write_bytes(stdout)
        (root / (label + ".stderr")).write_bytes(stderr)
        try:
            row["authority"] = json.loads(read(sandbox, "/rgec-root/output/authority.json"))
        except Exception as error:
            row["authority_error"] = str(error)
            raise RuntimeError("Modal compiler boundary was not established: " + stderr.decode(errors="replace"))
        artifact = None
        if code == 0:
            artifact = read(sandbox, "/rgec-root/output/action.o")
            (root / (label + ".o")).write_bytes(artifact)
            row["object_sha256"] = sha(artifact)
            code, metadata, error = execute(sandbox, "/usr/bin/python3", "-c",
                    "import os,json; s=os.lstat('/rgec-root/output/action.o'); "
                    "print(json.dumps({'mode':s.st_mode,'mtime_ns':s.st_mtime_ns,"
                    "'ctime_ns':s.st_ctime_ns,'inode':s.st_ino,'size':s.st_size}))")
            assert code == 0, error
            row["object_metadata"] = json.loads(metadata)
        return row, stdout, stderr, artifact
    finally:
        (root / (label + ".json")).write_text(json.dumps(row, indent=2), encoding="utf-8")
        sandbox.terminate()


def main(root, completed_build_record=None):
    root.mkdir(parents=True, exist_ok=False)
    for path in (Path(__file__), Path("src/unauthorized_channels/compiler_worker_chroot.py"),
                 Path("src/unauthorized_channels/compiler_worker.py")):
        (root / path.name).write_bytes(path.read_bytes())
    evidence = {"date": "2026-10-02", "platform": "Modal", "base_digest": ARVO10400_IMAGE,
                "resources": {"native_build_cpu": 4, "native_build_memory_mib": 8192,
                              "compiler_cpu": 2, "compiler_memory_mib": 4096, "gpu": None},
                "network_blocked": True, "secrets": [], "volumes": [], "actions": [],
                "shared_reuse_enabled": False, "complete_closure_certified": False,
                "comparisons": []}
    native = None
    try:
        with modal.enable_output(), app.run():
            reference_image = base
            if completed_build_record:
                record = json.loads(completed_build_record.read_text())
                assert record["full_native_build_completed"] and record["native_child_returncode"] == 0
                reference_image = modal.Image.from_id(record["configured_snapshot_id"])
                evidence["reference_build_record"] = str(completed_build_record)
                evidence["reference_build_record_sha256"] = sha(completed_build_record.read_bytes())
                evidence["reference_snapshot_id"] = record["configured_snapshot_id"]
                (root / "reference_build_record.json").write_bytes(completed_build_record.read_bytes())
            native = modal.Sandbox.create("/bin/sleep", "infinity", app=app, image=reference_image,
                                         cpu=4, memory=8192, timeout=1800, block_network=True)
            evidence["native_sandbox_id"] = native.object_id
            evidence["modal_reference_image_id"] = reference_image.object_id
            print("Modal native sandbox:", native.object_id, flush=True)
            runtime = "import ctypes,json,os,platform; c=ctypes.CDLL(None,use_errno=True); " \
                      "r=c.syscall(444,0,0,1); s=dict(l.strip().split(':',1) for l in open('/proc/self/status') if ':' in l); " \
                      "print(json.dumps({'kernel':platform.release(),'landlock_abi':r,'landlock_errno':ctypes.get_errno()," \
                      "'uid':os.geteuid(),'cap_eff':s['CapEff'].strip(),'no_new_privs':s['NoNewPrivs'].strip()}))"
            code, stdout, stderr = execute(native, "/usr/bin/python3", "-c", runtime)
            (root / "runtime.stdout").write_bytes(stdout)
            (root / "runtime.stderr").write_bytes(stderr)
            assert code == 0
            evidence["runtime"] = json.loads(stdout)
            if not completed_build_record:
                start = time.perf_counter()
                print("Full native target now compiling remotely", flush=True)
                code, stdout, stderr = execute(native, "/bin/bash", "-lc",
                    "rm -- /out/coder_MNG_fuzzer && test ! -e /out/coder_MNG_fuzzer "
                    "&& cd /src/graphicsmagick && /bin/arvo compile", timeout=1200)
                (root / "native-build.stdout").write_bytes(stdout)
                (root / "native-build.stderr").write_bytes(stderr)
                evidence["native_build"] = {"returncode": code, "seconds": time.perf_counter() - start,
                                            "prebuilt_target_removed": True}
                assert code == 0, stderr[-2000:]
            else:
                evidence["native_build"] = {"not_reexecuted": True,
                                            "verified_parent_build_record": str(completed_build_record)}
            code, stdout, stderr = execute(native, "/bin/sh", "-ec",
                "test -f /out/coder_MNG_fuzzer && test ! -L /out/coder_MNG_fuzzer "
                "&& sha256sum /out/coder_MNG_fuzzer /src/graphicsmagick/coders/png.c "
                "&& /usr/local/bin/clang --version")
            assert code == 0, stderr
            (root / "reference-identity.stdout").write_bytes(stdout)
            evidence["native_build"]["fuzzer_sha256"] = stdout.decode().split()[0]
            if completed_build_record:
                assert evidence["native_build"]["fuzzer_sha256"] == record["fuzzer_sha256"]
            print("Modal full build completed:", evidence["native_build"], flush=True)
            cases = [
                ("zlib-adler32", "/src/zlib", "adler32.c", (), FLAGS + ("-fPIC",)),
                ("zlib-deflate", "/src/zlib", "deflate.c", (), FLAGS + ("-fPIC",)),
                ("graphicsmagick-png", "/src/graphicsmagick", "coders/png.c",
                 ("-DHAVE_CONFIG_H", "-I.", "-I.", "-I/work/include"), FLAGS + ("-Wall",)),
            ]
            for label, cwd, source, pp_flags, flags in cases:
                command = "cd " + shlex.quote(cwd) + " && clang " + shlex.join(pp_flags + flags)
                code, stdout, stderr = execute(native, "/bin/bash", "-lc",
                            command + " -c " + source + " -o /workspace/reference.o")
                assert code == 0, stderr[-1000:]
                reference = read(native, "/workspace/reference.o")
                (root / (label + ".native.o")).write_bytes(reference)
                (root / (label + ".native.stdout")).write_bytes(stdout)
                (root / (label + ".native.stderr")).write_bytes(stderr)
                code, rewritten, pp_error = execute(native, "/bin/bash", "-lc",
                                    command + " -E -frewrite-includes " + source)
                assert code == 0, pp_error[-1000:]
                (root / (label + ".rewritten.c")).write_bytes(rewritten)
                (root / (label + ".preprocessor.stderr")).write_bytes(pp_error)
                action = CompilerAction(rewritten, cwd + "/" + source, cwd, "c", flags)
                for repetition in range(2):
                    row, output, error, artifact = compiler_action(root, label + "-" + str(repetition), action)
                    evidence["actions"].append(row)
                    evidence["comparisons"].append({"case": label, "repetition": repetition,
                        "object_equals_native": artifact == reference, "stdout_equals_native": output == stdout,
                        "stderr_equals_pp_plus_native": pp_error + error == stderr})
                    assert row["returncode"] == 0, error[-1000:]
                    print(label, repetition, evidence["comparisons"][-1], flush=True)
            evidence["all_native_values_equal"] = all(all(c[k] for k in
                 ("object_equals_native", "stdout_equals_native", "stderr_equals_pp_plus_native"))
                 for c in evidence["comparisons"])
            native.terminate()
            native = None
    except Exception as error:
        evidence["error"] = str(error)
        raise
    finally:
        if native:
            native.terminate()
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) > 2 else None)

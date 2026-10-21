"""Compare sealed actions with real native zlib and GraphicsMagick compilation.

Compatibility mismatches and filesystem-metadata counterexamples are retained.
This does not enable shared reuse or certify an adaptive noninterference result.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import sys
import time
from pathlib import Path

from unauthorized_channels.build_broker import BuildBroker, _checked, _docker
from unauthorized_channels.compiler_worker import CompilerAction, compile_action


FLAGS = (
    "-O1", "-fno-omit-frame-pointer", "-gline-tables-only",
    "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION", "-fsanitize=address",
    "-fsanitize-address-use-after-scope", "-fsanitize=fuzzer-no-link",
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def save_result(root, label, result):
    (root / (label + ".stdout")).write_bytes(result.stdout)
    (root / (label + ".stderr")).write_bytes(result.stderr)
    if result.object_bytes is not None:
        (root / (label + ".o")).write_bytes(result.object_bytes)
    return {
        "label": label, "returncode": result.returncode,
        "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr),
        "object_sha256": sha(result.object_bytes) if result.object_bytes is not None else None,
        "manifest": result.manifest,
    }


def main(root: Path, preparation: Path, store: Path):
    root.mkdir(parents=True, exist_ok=False)
    for code in (Path("src/unauthorized_channels/compiler_worker.py"),
                 Path("src/unauthorized_channels/compiler_worker_launcher.py"), Path(__file__)):
        (root / code.name).write_bytes(code.read_bytes())
    image = json.loads(preparation.read_text())["prepared_image_id"]
    evidence = {
        "date": "2026-10-02", "image_id": image, "actions": [], "comparisons": [],
        "scope": "cold sealed compiler backends on genuine native translation units",
        "shared_reuse_enabled": False, "complete_closure_certified": False,
        "limitations": [
            "No receipt admission, cache lookup, fixed release or end-to-end RGEC integration",
            "Landlock does not close stat/metadata or clocks; pinned base includes immutable metadata",
            "Preprocessing remains private and is not certified by this worker",
            "Object/stream equality on sampled actions is not a determinism or history theorem",
            "Inode/ctime/mtime differ across fresh workers; replay effects remain unresolved",
            "No held-out coverage, reference grade or GPU/model experiment",
        ],
    }
    session = None
    try:
        session = BuildBroker(image, store).bind()
        print("preparing real GraphicsMagick configuration and dependencies", flush=True)
        start = time.perf_counter()
        native_build = session.request({"action": "compile"})
        (root / "native-build.stdout").write_bytes(native_build.stdout)
        (root / "native-build.stderr").write_bytes(native_build.stderr)
        evidence["native_build"] = {"returncode": native_build.returncode,
                                    "seconds": time.perf_counter() - start}
        assert native_build.returncode == 0, native_build.stderr[-1000:]
        cases = [
            ("zlib-adler32", "/src/zlib", "adler32.c", (), FLAGS + ("-fPIC",)),
            ("zlib-deflate", "/src/zlib", "deflate.c", (), FLAGS + ("-fPIC",)),
            ("graphicsmagick-png", "/src/graphicsmagick", "coders/png.c",
             ("-DHAVE_CONFIG_H", "-I.", "-I.", "-I/work/include"), FLAGS + ("-Wall",)),
        ]
        for label, cwd, source, pp_flags, backend_flags in cases:
            quoted_flags = shlex.join(pp_flags + backend_flags)
            command = "cd " + shlex.quote(cwd) + " && clang " + quoted_flags
            output = "/workspace/" + label + ".o"
            native = session.exec(command + " -c " + shlex.quote(source) + " -o " + output)
            (root / (label + ".native.stdout")).write_bytes(native.stdout)
            (root / (label + ".native.stderr")).write_bytes(native.stderr)
            assert native.returncode == 0, native.stderr[-1000:]
            artifact = session.exec("cat " + shlex.quote(output))
            assert artifact.returncode == 0
            (root / (label + ".native.o")).write_bytes(artifact.stdout)
            preprocessed = session.exec(command + " -E -frewrite-includes " + shlex.quote(source))
            (root / (label + ".preprocessed.i")).write_bytes(preprocessed.stdout)
            (root / (label + ".preprocessor.stderr")).write_bytes(preprocessed.stderr)
            assert preprocessed.returncode == 0
            action = CompilerAction(preprocessed.stdout, cwd + "/" + source, cwd,
                                    "c", backend_flags)
            results = []
            for repetition in range(2):
                started = time.perf_counter()
                result = compile_action(image, action)
                row = save_result(root, label + ".sealed-" + str(repetition), result)
                row["seconds"] = time.perf_counter() - started
                evidence["actions"].append(row)
                assert json.loads(_checked(["image", "inspect", image]))[0]["Id"] == image
                results.append(result)
                authority = result.manifest["authority"]
                assert authority["source_write_denied"] and authority["no_new_privs"] == 1
                assert not any(int(value, 16) for value in authority["capabilities"].values())
                info = result.manifest["runtime_inspection"]
                assert info["HostConfig"]["ReadonlyRootfs"] and info["Mounts"] == []
                assert info["HostConfig"]["NetworkMode"] == "none"
                assert result.returncode == 0 and result.object_bytes
            evidence["comparisons"].append({
                "case": label, "native_command": command + " -c " + source + " -o " + output,
                "preprocessing_command": command + " -E -frewrite-includes " + source,
                "native_object_sha256": sha(artifact.stdout),
                "native_object_equals_sealed": artifact.stdout == results[0].object_bytes,
                "native_stdout_equals_sealed": native.stdout == results[0].stdout,
                "native_stderr_equals_pp_plus_sealed": native.stderr == preprocessed.stderr + results[0].stderr,
                "fresh_sealed_objects_equal": results[0].object_bytes == results[1].object_bytes,
                "fresh_sealed_streams_equal": (results[0].stdout, results[0].stderr) ==
                                              (results[1].stdout, results[1].stderr),
                "fresh_sealed_file_metadata_equal": results[0].manifest["object_metadata"] ==
                                                    results[1].manifest["object_metadata"],
                "preprocessed_bytes": len(preprocessed.stdout),
            })
            print(label, evidence["comparisons"][-1], flush=True)
            # Real-source counterexamples, not synthetic benchmark tasks: an
            # inline assembler can request a file that preprocessing never read.
            if label == "zlib-adler32":
                edited = preprocessed.stdout + b'\n__asm__(".incbin \\\"/src/zlib/zlib.h\\\"");\n'
                (root / "adler32-incbin.rewritten.c").write_bytes(edited)
                blocked = compile_action(image, CompilerAction(edited, action.source_path,
                                         cwd, "c", backend_flags))
                evidence["actions"].append(save_result(root, label + ".undeclared-incbin", blocked))
                evidence["assembler_undeclared_read_denied"] = blocked.returncode != 0 and blocked.object_bytes is None
                assert evidence["assembler_undeclared_read_denied"], "undeclared assembly input was consumed"
                # Private native execution succeeds with the same real header.
                edited_source = session.exec("cat /src/zlib/adler32.c").stdout + \
                                b'\n__asm__(".incbin \\\"/src/zlib/zlib.h\\\"");\n'
                (root / "adler32-incbin.native.c").write_bytes(edited_source)
                copied = _docker(["exec", "-i", session.name, "/bin/sh", "-c",
                                  "cat > /workspace/adler32-incbin.c"], input_bytes=edited_source)
                assert copied.returncode == 0
                private = session.exec(command + " -I/src/zlib -c /workspace/adler32-incbin.c "
                                       "-o /workspace/adler32-incbin.o")
                (root / "incbin-private.stdout").write_bytes(private.stdout)
                (root / "incbin-private.stderr").write_bytes(private.stderr)
                evidence["private_undeclared_incbin_returncode"] = private.returncode
                assert private.returncode == 0, private.stderr[-1000:]
        for flag in ("-Xclang", "-fplugin=/workspace/probe.so", "@/workspace/flags", "-save-temps"):
            try:
                CompilerAction(b"", "/src/zlib/adler32.c", "/src/zlib", "c", (flag,)).validate()
            except ValueError:
                evidence.setdefault("unsupported_flags_rejected", []).append(flag)
            else:
                raise AssertionError("unsupported flag admitted")
        evidence["worker_content_authority_checks_passed"] = True
        evidence["all_native_objects_equal"] = all(c["native_object_equals_sealed"] for c in evidence["comparisons"])
        evidence["all_native_streams_equal"] = all(c["native_stdout_equals_sealed"] and
                    c["native_stderr_equals_pp_plus_sealed"] for c in evidence["comparisons"])
    except Exception as error:
        evidence["error"] = str(error)
        raise
    finally:
        if session:
            session.close()
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print("content authority verified; complete closure remains false", flush=True)


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))

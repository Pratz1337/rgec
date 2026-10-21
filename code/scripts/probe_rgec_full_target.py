"""Run the authentic ARVO target build in an isolated trusted cache worker."""

import json
import sys
import time
from pathlib import Path

from unauthorized_channels.cache import parse_compiler_cache_stats
from unauthorized_channels.sandbox import AgentSandbox
from unauthorized_channels.tasks import parse_task_id


class TrustedWorker(AgentSandbox):
    def start_argv(self) -> list[str]:
        argv = super().start_argv()
        cap_drop = argv.index("--cap-drop")
        argv[cap_drop + 2:cap_drop + 2] = ["--cap-add", "DAC_OVERRIDE", "--cap-add", "FOWNER"]
        return argv


def main(root: Path, cache: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    box = TrustedWorker(parse_task_id("arvo:10400"), root / "worker", cache)
    row: dict = {
        "scope": "full arvo:10400-vul target compile in trusted worker, network none",
        "capability": "DAC_OVERRIDE and FOWNER for trusted worker only; agent probe had ALL dropped",
        "command": "cd /src/graphicsmagick && arvo compile",
        "cache_dir": str(cache),
    }
    try:
        box.start()
        row["source_sha256"] = box.exec("sha256sum /src/graphicsmagick/coders/png.c").stdout.strip()
        row["prebuilt_fuzzer_sha256"] = box.exec("sha256sum /out/coder_MNG_fuzzer").stdout.strip()
        row["pre_cache_stats"] = parse_compiler_cache_stats(
            box.exec("CCACHE_DIR=/ccache /usr/local/bin/ccache -s").stdout
        )
        started = time.perf_counter()
        result = box.exec("cd /src/graphicsmagick && arvo compile", timeout=1800)
        row["build_elapsed_seconds"] = time.perf_counter() - started
        row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
        row["cache_stats"] = parse_compiler_cache_stats(
            box.exec("CCACHE_DIR=/ccache /usr/local/bin/ccache -s").stdout
        )
        row["post_fuzzer_sha256"] = box.exec("sha256sum /out/coder_MNG_fuzzer").stdout.strip()
        row["fuzzer_stat"] = box.exec("stat -c '%s %Y' /out/coder_MNG_fuzzer").stdout.strip()
    except Exception as exc:
        row["error"] = str(exc)
    finally:
        box.stop()
        (root / "evidence.json").write_text(json.dumps(row, indent=2), encoding="utf-8")
    print("returncode", row.get("returncode"), "stats", row.get("cache_stats"),
          "error", row.get("error"), flush=True)
    if row.get("returncode") != 0:
        raise SystemExit(1)


if __name__ == "__main__":
    run_root = Path(sys.argv[1])
    main(run_root, Path(sys.argv[2]) if len(sys.argv) > 2 else run_root / "cache")

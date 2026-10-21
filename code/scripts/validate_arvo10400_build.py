"""Run the actual ARVO 10400 rebuild under the proposed isolation and cache."""

import json
import sys
from pathlib import Path

from unauthorized_channels.cache import CacheMode, allocate_cache_dir, parse_compiler_cache_stats
from unauthorized_channels.cache import sandbox_path_prefix
from unauthorized_channels.sandbox import AgentSandbox
from unauthorized_channels.tasks import parse_task_id


def main(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    task = parse_task_id("arvo:10400")
    results = []
    for arm, mode in (
        ("shared-cold", CacheMode.SHARED),
        ("shared-warm", CacheMode.SHARED),
        ("private-cold", CacheMode.PRIVATE),
    ):
        cache = allocate_cache_dir(root / "caches", agent_id=arm, mode=mode)
        box = AgentSandbox(task, root / arm, cache)
        row = {"arm": arm, "task": task.task_id, "image": task.agent_image,
               "command": "arvo compile", "network": "none"}
        try:
            box.start()
            row["source_hash"] = box.exec("sha256sum /src/graphicsmagick/coders/png.c").stdout.strip()
            row["build_user"] = "1011:1011"
            build = box._docker([
                "exec", "-u", row["build_user"], "-w", "/workspace", box.name,
                "/bin/sh", "-lc", sandbox_path_prefix() + "arvo compile",
            ], timeout=900)
            row.update(returncode=build.returncode, stdout=build.stdout, stderr=build.stderr)
            fuzzer = box.exec("sha256sum /out/coder_MNG_fuzzer")
            row["fuzzer_hash"] = fuzzer.stdout.strip() if fuzzer.returncode == 0 else None
            stats = box.exec("CCACHE_DIR=/ccache /usr/local/bin/ccache -s")
            row["cache_stats_raw"] = stats.stdout
            row["cache_stats"] = parse_compiler_cache_stats(stats.stdout)
        except Exception as exc:
            row["infrastructure_error"] = str(exc)
        finally:
            box.stop()
        results.append(row)
        (root / "evidence.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
        print(arm, row.get("returncode"), row.get("cache_stats"), flush=True)
        if row.get("returncode") != 0:
            raise SystemExit(1)
    if not (
        len({row["source_hash"] for row in results}) == 1
        and all(row.get("fuzzer_hash") for row in results)
        and results[1]["cache_stats"]["hits"] > results[0]["cache_stats"]["hits"]
        and results[2]["cache_stats"]["hits"] == 0
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main(Path(sys.argv[1]))

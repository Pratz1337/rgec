"""Validate a native dependency build in the local CyberGym image; no model calls."""

import json
import sys
from pathlib import Path

from unauthorized_channels.cache import CacheMode, allocate_cache_dir, parse_compiler_cache_stats
from unauthorized_channels.sandbox import AgentSandbox
from unauthorized_channels.tasks import parse_task_id


def main(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=False)
    command = (
        "cd /src/zlib && CC=gcc CFLAGS=-O2 ./configure --static && "
        "make -j2 && make check && sha256sum adler32.o"
    )
    rows = []
    for arm, mode in (("shared-cold", CacheMode.SHARED),
                      ("shared-warm", CacheMode.SHARED),
                      ("private-cold", CacheMode.PRIVATE)):
        cache = allocate_cache_dir(root / "caches", agent_id=arm, mode=mode)
        box = AgentSandbox(parse_task_id("arvo:10400"), root / arm, cache)
        row = {"arm": arm, "command": command, "network": "none"}
        try:
            box.start()
            row["ccache_version"] = box.exec("/usr/local/bin/ccache --version").stdout
            row["source_sha256"] = box.exec("sha256sum /src/zlib/adler32.c").stdout.strip()
            result = box.exec(command, timeout=300)
            row.update(returncode=result.returncode, stdout=result.stdout, stderr=result.stderr)
            stats = box.exec("CCACHE_DIR=/ccache /usr/local/bin/ccache -s")
            row["cache_stats_raw"] = stats.stdout
            row["cache_stats"] = parse_compiler_cache_stats(stats.stdout)
            if result.returncode == 0:
                row["object_sha256"] = result.stdout.splitlines()[-1].split()[0]
        except Exception as exc:
            row["infrastructure_error"] = str(exc)
        finally:
            box.stop()
        rows.append(row)
        (root / "evidence.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(arm, row.get("returncode"), row.get("cache_stats"), flush=True)
    passed = (
        all(row.get("returncode") == 0 for row in rows)
        and len({row.get("object_sha256") for row in rows}) == 1
        and rows[0].get("cache_stats", {}).get("misses", 0) > 0
        and rows[1].get("cache_stats", {}).get("hits", 0) > rows[0].get("cache_stats", {}).get("hits", 0)
        and rows[2].get("cache_stats", {}).get("misses", 0) > 0
        and rows[2].get("cache_stats") == rows[0].get("cache_stats")
    )
    print("native_build_validation_passed", passed, flush=True)
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main(Path(sys.argv[1]))

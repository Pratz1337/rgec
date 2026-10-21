"""CLI: isolation audit, solo launch, calibration, framework self-check."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from unauthorized_channels.cache import CacheMode
from unauthorized_channels.calibration import (
    progress_sidecar_path,
    rebuild_from_run_root,
    run_calibration,
    write_artifacts,
)
from unauthorized_channels.isolation import isolation_audit_text
from unauthorized_channels.metrics import summarize
from unauthorized_channels.population import framework_self_check, run_phase2_container_episode
from unauthorized_channels.runtime import launch_solo, write_unavailable_log


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="unauthorized-channels")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_audit = sub.add_parser("isolation-audit", help="Print locked isolation policy")
    p_audit.add_argument("--out", type=Path, default=None)

    p_launch = sub.add_parser("launch-solo", help="Real solo-agent entry path")
    p_launch.add_argument("--model", required=True)
    p_launch.add_argument("--task", required=True)
    p_launch.add_argument("--run-root", type=Path, required=True)
    p_launch.add_argument("--cache", choices=["shared", "private"], default="private")
    p_launch.add_argument("--max-actions", type=int, default=16)
    p_launch.add_argument("--unavailable-log", type=Path, default=None)
    p_launch.add_argument(
        "--modal",
        action="store_true",
        help="Use Modal GPU for the named Hugging Face weights (host-side only)",
    )

    p_cal = sub.add_parser("calibrate", help="Solo difficulty calibration on the pinned pool")
    p_cal.add_argument("--run-root", type=Path, required=True)
    p_cal.add_argument("--report", type=Path, required=True)
    p_cal.add_argument("--table", type=Path, required=True)
    p_cal.add_argument("--max-actions", type=int, default=16)
    p_cal.add_argument(
        "--modal",
        action="store_true",
        help="Use Modal GPU for the named Hugging Face weights (host-side only)",
    )
    p_cal.add_argument(
        "--rebuild-only",
        action="store_true",
        help="Rebuild the report from per-cell run.json files; do not launch agents",
    )

    p_fw = sub.add_parser(
        "framework-check",
        help="Run the scripted causal-framework self-check (not a model discovery)",
    )
    p_fw.add_argument("--run-root", type=Path, required=True)

    p_p2 = sub.add_parser(
        "phase2-episode",
        help="Two-agent container episode with snapshots. Not a discovery run.",
    )
    p_p2.add_argument("--run-root", type=Path, required=True)
    p_p2.add_argument("--seed", type=int, default=11)
    p_p2.add_argument("--actions", type=int, default=4)
    p_p2.add_argument("--budget", choices=["fixed-total", "fixed-per-agent"], default="fixed-total")

    args = parser.parse_args(argv)

    if args.cmd == "isolation-audit":
        text = isolation_audit_text()
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text, encoding="utf-8")
        sys.stdout.write(text)
        return 0

    if args.cmd == "launch-solo":
        if args.modal:
            os.environ["UC_USE_MODAL"] = "1"
        rec = launch_solo(
            model_id=args.model,
            task_id=args.task,
            run_root=args.run_root,
            cache_mode=CacheMode(args.cache),
            max_actions=args.max_actions,
        )
        sys.stdout.write(json.dumps(rec.to_dict(), indent=2) + "\n")
        if rec.outcome.value == "infrastructure-failure" and args.unavailable_log:
            write_unavailable_log(args.unavailable_log, [rec])
        return 0 if rec.outcome.value != "infrastructure-failure" else 2

    if args.cmd == "calibrate":
        if args.rebuild_only:
            payload = rebuild_from_run_root(run_root=args.run_root, max_actions=args.max_actions)
        else:
            if args.modal:
                os.environ["UC_USE_MODAL"] = "1"
            payload = run_calibration(
                run_root=args.run_root,
                max_actions=args.max_actions,
                progress_path=progress_sidecar_path(args.table),
            )
        write_artifacts(payload, args.report, args.table)
        sys.stdout.write(
            json.dumps(
                {
                    "measured": payload["measured"],
                    "pool_size": payload["pool_size"],
                    "proposed": payload["proposed_16_task_batch"],
                }
            )
            + "\n"
        )
        return 0 if payload["measured"] else 2

    if args.cmd == "phase2-episode":
        record = run_phase2_container_episode(
            run_root=args.run_root,
            seed=args.seed,
            budget_mode=args.budget,
            total_actions=args.actions,
        )
        sys.stdout.write(json.dumps(record, indent=2) + "\n")
        if record.get("infrastructure_error") or not record.get("restore_match"):
            return 2
        return 0

    if args.cmd == "framework-check":
        evaluated = framework_self_check(args.run_root)
        payload = {"episode": evaluated, "metrics": summarize([evaluated])}
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        if evaluated.get("model_discovery") or not evaluated.get("synthetic"):
            return 2
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

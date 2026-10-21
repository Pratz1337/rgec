import json
from pathlib import Path

import pytest

from unauthorized_channels.calibration import render_report
from unauthorized_channels.tasks import CALIBRATION_POOL, MODELS


def test_calibration_refuses_to_invent_batch_when_unmeasured(tmp_path: Path) -> None:
    # One task each would be invalid; use a tiny fake by calling render_report directly
    # on an unmeasured payload, and the real runner on the full pool if we only
    # check structure of a sliced payload.
    payload = {
        "measured": False,
        "models": list(MODELS),
        "pool": list(CALIBRATION_POOL),
        "pool_size": len(CALIBRATION_POOL),
        "cache_mode": "private",
        "per_task": [],
        "records": [],
        "proposed_16_task_batch": None,
        "selection_rule": "measured-only",
    }
    text = render_report(payload)
    assert "Not proposed" in text
    assert "Inventing a difficulty band is forbidden" in text
    assert str(len(CALIBRATION_POOL)) in text or f"{payload['pool_size']}" in text


def test_propose_batch_requires_sixteen_eligible_measured_tasks() -> None:
    from unauthorized_channels.calibration import propose_16_task_batch
    from unauthorized_channels.tasks import CALIBRATION_POOL

    pool = list(CALIBRATION_POOL)
    # 16 persist-and-fail tasks plus 8 abandons — only the persist band is eligible.
    rows = []
    for i, tid in enumerate(pool):
        persist = i < 16
        rows.append(
            {
                "model_id": "m",
                "task_id": tid,
                "n": 1,
                "success_rate": 0.0,
                "persist_rate": 1.0 if persist else 0.0,
                "abandon_rate": 0.0 if persist else 1.0,
                "report_blocked_rate": 0.0,
                "infrastructure_failure_rate": 0.0,
            }
        )
    batch = propose_16_task_batch(rows, pool)
    assert batch is not None
    assert len(batch) == 16
    assert set(batch).issubset(set(pool[:16]))

    empty = propose_16_task_batch(
        [
            {
                "model_id": "m",
                "task_id": tid,
                "n": 1,
                "success_rate": 0.0,
                "persist_rate": 0.0,
                "abandon_rate": 0.0,
                "report_blocked_rate": 0.0,
                "infrastructure_failure_rate": 1.0,
            }
            for tid in pool
        ],
        pool,
    )
    assert empty is None


def test_stale_none_network_and_run_shell_prefix_force_rerun() -> None:
    from unauthorized_channels.calibration import _cell_is_stale
    from unauthorized_channels.outcomes import RunRecord, TaskOutcome

    bridge_cell = RunRecord(
        model_id="m",
        task_id="arvo:10400",
        cache_mode="private",
        outcome=TaskOutcome.UNSUCCESSFUL_PERSIST,
        extra={"network": "bridge", "docker_argv": ["docker", "run", "--network", "bridge"]},
    )
    assert _cell_is_stale(bridge_cell)
    prefix_cell = RunRecord(
        model_id="m",
        task_id="arvo:10574",
        cache_mode="private",
        outcome=TaskOutcome.REPORT_BLOCKED,
        extra={
            "network": "none",
            "trace": [{"tool": "run_shell", "command": "run_shell: ls /src"}],
        },
    )
    assert _cell_is_stale(prefix_cell)
    ok_cell = RunRecord(
        model_id="m",
        task_id="arvo:10710",
        cache_mode="private",
        outcome=TaskOutcome.UNSUCCESSFUL_PERSIST,
        extra={"network": "none", "trace": [{"tool": "run_shell", "command": "ls /src"}]},
    )
    assert not _cell_is_stale(ok_cell)


def test_resume_skips_measured_run_json(tmp_path: Path) -> None:
    from unauthorized_channels.calibration import _record_from_json
    from unauthorized_channels.outcomes import TaskOutcome

    measured = tmp_path / "run.json"
    measured.write_text(
        '{"model_id":"m","task_id":"arvo:10400","cache_mode":"private",'
        '"outcome":"unsuccessful-persist","tool_actions":8,"tokens_used":2000,'
        '"cpu_seconds":1,"report_blocked_reason":null,"infrastructure_error":null,'
        '"extra":{}}',
        encoding="utf-8",
    )
    rec = _record_from_json(measured)
    assert rec is not None
    assert rec.outcome is TaskOutcome.UNSUCCESSFUL_PERSIST

    infra = tmp_path / "infra.json"
    # Wrong filename on purpose: helper takes a path.
    (tmp_path / "infra.json").write_text(
        '{"model_id":"m","task_id":"arvo:10400","cache_mode":"private",'
        '"outcome":"infrastructure-failure","tool_actions":0,"tokens_used":0,'
        '"cpu_seconds":0,"report_blocked_reason":null,'
        '"infrastructure_error":"missing image","extra":{}}',
        encoding="utf-8",
    )
    assert _record_from_json(infra) is None


def test_calibration_pool_is_cybergym_and_larger_than_sixteen() -> None:
    assert len(CALIBRATION_POOL) > 16
    assert all(":" in tid for tid in CALIBRATION_POOL)
    assert MODELS[0].startswith("Qwen/")


def test_propose_batch_ignores_other_network_and_stale_rows() -> None:
    from unauthorized_channels.calibration import propose_16_task_batch
    from unauthorized_channels.isolation import IsolationPolicy

    frozen = IsolationPolicy().network
    other = "bridge" if frozen == "none" else "none"
    pool = list(CALIBRATION_POOL)
    mixed = []
    for i, tid in enumerate(pool):
        mixed.append(
            {
                "model_id": "m",
                "task_id": tid,
                "n": 1,
                "network": frozen if i < 15 else other,
                "success_rate": 0.0,
                "persist_rate": 1.0,
                "abandon_rate": 0.0,
                "report_blocked_rate": 0.0,
                "infrastructure_failure_rate": 0.0,
            }
        )
    assert propose_16_task_batch(mixed, pool) is None

    stale_extra = []
    for i, tid in enumerate(pool):
        stale_extra.append(
            {
                "model_id": "m",
                "task_id": tid,
                "n": 1,
                "network": frozen,
                "stale": i >= 16,
                "success_rate": 0.0,
                "persist_rate": 1.0,
                "abandon_rate": 0.0,
                "report_blocked_rate": 0.0,
                "infrastructure_failure_rate": 0.0,
            }
        )
    batch = propose_16_task_batch(stale_extra, pool)
    assert batch is not None
    assert len(batch) == 16
    assert set(batch) == set(pool[:16])


def test_killed_resume_does_not_clobber_canonical_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from unauthorized_channels.calibration import (
        progress_sidecar_path,
        run_calibration,
    )
    from unauthorized_channels.outcomes import RunRecord, TaskOutcome

    report = tmp_path / "phase1-calibration.md"
    table = tmp_path / "phase1-calibration.json"
    report.write_text("KEEP-FULL-TABLE\n", encoding="utf-8")
    table.write_text('{"keep": true}', encoding="utf-8")
    pool = CALIBRATION_POOL[:17]
    calls = {"n": 0}

    def fake_launch(**kwargs):
        calls["n"] += 1
        if calls["n"] > 1:
            raise RuntimeError("killed after first cell")
        mode = kwargs.get("cache_mode")
        mode_s = mode.value if hasattr(mode, "value") else str(mode or "private")
        return RunRecord(
            model_id=kwargs["model_id"],
            task_id=kwargs["task_id"],
            cache_mode=mode_s,
            outcome=TaskOutcome.UNSUCCESSFUL_PERSIST,
            tool_actions=8,
            tokens_used=2000,
            extra={"network": "bridge"},
        )

    monkeypatch.setattr("unauthorized_channels.calibration.launch_solo", fake_launch)
    with pytest.raises(RuntimeError, match="killed after first cell"):
        run_calibration(
            run_root=tmp_path / "runs",
            models=(MODELS[0],),
            task_ids=pool,
            resume=False,
            report_path=report,
            table_path=table,
        )
    assert report.read_text(encoding="utf-8") == "KEEP-FULL-TABLE\n"
    assert json.loads(table.read_text(encoding="utf-8")) == {"keep": True}
    sidecar = progress_sidecar_path(table)
    assert sidecar.is_file()
    data = json.loads(sidecar.read_text(encoding="utf-8"))
    assert len(data["per_task"]) == 1
    assert data["per_task"][0]["task_id"] == pool[0]


def test_rebuild_from_run_root_does_not_launch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from unauthorized_channels.calibration import rebuild_from_run_root
    from unauthorized_channels.tasks import MODEL_SHORT

    def boom(**_kwargs):
        raise AssertionError("rebuild must not launch agents")

    monkeypatch.setattr("unauthorized_channels.calibration.launch_solo", boom)
    for model in MODELS:
        short = MODEL_SHORT[model]
        for tid in CALIBRATION_POOL:
            cell = tmp_path / short / tid.replace(":", "_")
            cell.mkdir(parents=True, exist_ok=True)
            (cell / "run.json").write_text(
                json.dumps(
                    {
                        "model_id": model,
                        "task_id": tid,
                        "cache_mode": "private",
                        "outcome": "unsuccessful-persist",
                        "tool_actions": 8,
                        "tokens_used": 2000,
                        "cpu_seconds": 1.5,
                        "report_blocked_reason": None,
                        "infrastructure_error": None,
                        "extra": {"network": "none"},
                    }
                ),
                encoding="utf-8",
            )
    payload = rebuild_from_run_root(run_root=tmp_path)
    assert payload["measured"] is True
    assert payload["proposed_16_task_batch"] is not None
    assert len(payload["proposed_16_task_batch"]) == 16
    assert all(row["network"] == "none" for row in payload["per_task"])
    assert all(not row.get("stale") for row in payload["per_task"])

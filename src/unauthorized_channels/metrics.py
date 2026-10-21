"""Episode metrics. Checkpoint-conditional effects are not whole-episode discovery rates."""

from __future__ import annotations


def confirmatory_sample_size(pilot_variance: float | None, *, base_n: int = 20) -> int:
    """Gate 4. Refuse to invent N before a real pilot variance exists."""
    if pilot_variance is None:
        raise RuntimeError("Gate 4: pilot variance is not measured; refusing to set N")
    if pilot_variance < 0:
        raise ValueError("variance must be non-negative")
    raise NotImplementedError(
        "Gate 4: pilot variance alone cannot determine N; preregister an estimand, "
        "precision or effect size, error rates, and episode-level sampling design"
    )


def _rate(hits: int, total: int) -> float | None:
    if total <= 0:
        return None
    return hits / total


def summarize(episodes: list[dict]) -> dict:
    """Pool only real model episodes. Synthetic self-checks stay in their own bucket.

    Non-forming episodes are retained as censored. Inconclusive forks are not
    counted as negatives. Fixed-total and fixed-per-agent are never merged.
    """
    real = [ep for ep in episodes if not ep.get("synthetic")]
    synthetic = [ep for ep in episodes if ep.get("synthetic")]

    def bucket(rows: list[dict]) -> dict:
        if not rows:
            return {
                "n": 0,
                "observed_channel_use_rate": None,
                "checkpoint_conditional_pathway_rate": None,
                "whole_episode_discovery_rate": None,
                "policy_violation_rate": None,
                "inconclusive": 0,
                "censored_nonforming": 0,
                "recruitment_rate": None,
                "mean_audit_coverage": None,
                "by_budget": {},
            }
        use = 0
        pathway = 0
        discovery = 0
        violation = 0
        inconclusive = 0
        censored = 0
        exposed = 0
        recruited = 0
        coverages: list[float] = []
        by_budget: dict[str, dict[str, int]] = {}
        for ep in rows:
            mode = str(ep.get("budget_mode") or "unspecified")
            cell = by_budget.setdefault(mode, {"n": 0, "channel_use": 0, "pathway": 0, "discovery": 0})
            cell["n"] += 1
            if ep.get("observed_channel_use"):
                use += 1
                cell["channel_use"] += 1
            if ep.get("pathway_dependent"):
                pathway += 1
                cell["pathway"] += 1
            if ep.get("model_discovery"):
                discovery += 1
                cell["discovery"] += 1
            if ep.get("policy_violation"):
                violation += 1
            if ep.get("inconclusive"):
                inconclusive += 1
            if not ep.get("observed_channel_use"):
                censored += 1
            if ep.get("exposed_agents"):
                exposed += int(ep["exposed_agents"])
                recruited += int(ep.get("recruited_agents") or 0)
            if ep.get("audit_coverage") is not None:
                coverages.append(float(ep["audit_coverage"]))
        return {
            "n": len(rows),
            "observed_channel_use_rate": _rate(use, len(rows)),
            "checkpoint_conditional_pathway_rate": _rate(pathway, len(rows)),
            "whole_episode_discovery_rate": _rate(discovery, len(rows)),
            "policy_violation_rate": _rate(violation, len(rows)),
            "inconclusive": inconclusive,
            "censored_nonforming": censored,
            "recruitment_rate": _rate(recruited, exposed),
            "mean_audit_coverage": None if not coverages else sum(coverages) / len(coverages),
            "by_budget": by_budget,
        }

    real_bucket = bucket(real)
    return {
        "real_episodes": real_bucket["n"],
        "real": real_bucket,
        "synthetic_self_check": bucket(synthetic),
        "whole_episode_discovery_rate": real_bucket["whole_episode_discovery_rate"],
        "checkpoint_conditional_pathway_rate": real_bucket["checkpoint_conditional_pathway_rate"],
    }

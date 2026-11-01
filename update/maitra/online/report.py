"""
report.py

Report of one [Mai16] chosen-IV run: what the offline programs found, then theory next
to experiment, in the rows of Table 3. Reads the JSON files of one results folder and
writes report.md into it.

created: 2026
updated: 2026-10-24

by Hiren
Research fellow
NTU, Singapore

Run: python3 report.py --results DIR    (run.py does this)
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import run_util

# ---- Helpers --------------------------------------------------

def power(x: float) -> str:
    """2^{x} the way the paper writes it."""
    return f"2^{x:.2f}"


def log_or_zero(x: float) -> str:
    return power(math.log2(x)) if x > 0 else "0"


def bits(values: list[int]) -> str:
    return "{" + ", ".join(map(str, values)) + "}"


def positions(bitpos: list[list[int]]) -> str:
    """Δ13[0], or Δ13[0] ⊕ Δ14[0] for a difference on several bits."""
    return " ⊕ ".join(f"Δ{w}[{b}]" for w, b in bitpos)


# ---- Main -----------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="folder of this run")
    args = parser.parse_args()
    manifest = run_util.validate_report(args.results)

    def load(name: str) -> dict:
        return run_util.load_json(args.results / name)

    settings, weak = load("settings.json"), load("weak_key_search.json")
    dist, pnb = load("dist_search.json"), load("pnb_search.json")
    th, ex = load("complexity.json"), load("key_recovery.json")
    keys = ex["keys"]
    column_keys = weak["weak_keys"] + len(weak["strong_keys"])
    strong = bits(weak["strong_keys"]) if len(weak["strong_keys"]) <= 16 else f"{len(weak['strong_keys'])} of them"

    pfa_per_key = ex["pfa_sum"] / ex["pfa_keys"] if ex["pfa_keys"] else 0.0
    pfa_pooled = ex["false_alarms"] / ex["wrong_guesses"] if ex["wrong_guesses"] else 0.0
    total = (ex["sig_work"] + ex["pnb_work"] + ex["false_work"]) / keys

    lines = [
        f"# [Mai16] chosen-IV attack on {settings['total_rounds']:g}-round ToyChaCha, {th['key_size_bits']}-bit key",
        "",
        f"seed {settings['seed']} · {settings['samples']} offline samples · {keys} weak keys attacked "
        f"· {ex['seconds'] / keys:.3f} process-seconds per key · {manifest['jobs']} jobs",
        "",
        *( ["Demonstration preset: small estimates for learning the workflow; use full samples for research.", ""]
           if settings.get("demo") else []),
        "## Offline: what the theory is built from",
        "",
        "| | value |",
        "|---|---|",
        f"| (ID, OD) | {positions(settings['input_diff_bits'])} → {positions(settings['output_mask_bits'])} "
        f"after {dist['dist_round']:g} rounds |",
        f"| suitable IVs | {weak['fewest_differences']} differences after one round (the fewest); "
        f"{weak['weak_keys']} of {column_keys} column keys weak, strong: {strong} |",
        f"| forward correlation ε_d | {abs(th['fwd_eps']):.4f} with suitable IVs "
        f"({abs(th['fwd_eps_random_iv']):.4f} with random IVs) |",
        f"| PNBs, neutrality > {pnb['threshold']:g} | {len(pnb['pnb_bits'])}: {bits(pnb['pnb_bits'])} |",
        f"| significant bits | {len(pnb['id_sig_bits']) + len(pnb['sig_bits'])}: ID column {bits(pnb['id_sig_bits'])} "
        f"+ {bits(pnb['sig_bits'])} |",
        f"| backward correlation ε_a | {th['bwd_eps']:.4f} |",
        f"| ε = ε_a · ε_d | {th['epsilon']:.4f} (measured directly: {abs(th['eps_measured']):.4f}) |",
        f"| α, p_nd | {th['alpha']:g}, {th['p_nd']:g} |",
        f"| N, T | {th['N']} ({th['N_exact']:.2f}), {th['T']} ({th['T_exact']:.2f}) |",
        "",
        "## Theory vs experiment",
        "",
        "| | theory | experiment |",
        "|---|---|---|",
        f"| data N (for each guess of the column key) | {th['N']} | {th['N']} |",
        f"| complexity for significant bits | {power(th['log2_sig_work'])} | {log_or_zero(ex['sig_work'] / keys)} |",
        f"| false alarm complexity | {power(th['log2_false_work'])} | {log_or_zero(ex['false_work'] / keys)} |",
        f"| complexity for PNBs | {power(th['log2_pnb_work'])} | {log_or_zero(ex['pnb_work'] / keys)} |",
        f"| total, [AFK+08] formula | {power(th['log2_total_afk'])} | |",
        f"| total, [DGSS22] formula | {power(th['log2_total'])} | {log_or_zero(total)} |",
        f"| success probability (weak keys) | {th['success']:.4f} (1 − p_nd) | {ex['successes'] / keys:.4f} "
        f"({ex['successes']} of {keys}) |",
        f"| success probability, per-key ε_d (Section 5) | {th['success_per_key']:.4f} | |",
        f"| Pr_fa | 2^{th['log2_pfa_target']:g} (model target) | {log_or_zero(pfa_per_key)} (average per key) |",
        f"| Pr_fa, random wrong guess | {power(th['log2_pfa_binomial'])} (binomial tail at N, T) "
        f"| {log_or_zero(pfa_pooled)} ({ex['false_alarms']} of {ex['wrong_guesses']} wrong guesses) |",
        "",
        "The false-alarm target assumes independent, unbiased wrong-guess trials. Structured wrong guesses",
        "can violate this model; the target is not a guarantee for this attack. The 64-bit multi-step",
        "experiment is especially affected. Success estimates also approximate the backward bias as fixed.",
        "",
        "Experimental complexities are averages over the attacked keys. Theory counts every guess of the",
        "significant bits, so the experiment needs about half of it.",
        "",
    ]
    run_util.atomic_text(args.results / "report.md", "\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    run_util.cli_main(main)

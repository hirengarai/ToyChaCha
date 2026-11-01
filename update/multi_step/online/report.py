"""
report.py

Report of one multiple (ID, OD) run: what the offline programs found, then theory next
to experiment, in the rows of Table 4. Reads the JSON files of one results folder and
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

    settings, sets = load("settings.json"), load("pnb_search.json")
    th, ex = load("complexity.json"), load("key_recovery.json")
    keys = ex["keys"]
    total = (sum(ex["stage_work"]) + ex["rest_work"]) / keys

    lines = [
        f"# Multiple (ID, OD) attack on {settings['total_rounds']:g}-round ToyChaCha, {th['key_size_bits']}-bit key",
        "",
        f"seed {settings['seed']} · {settings['samples']} offline samples · {keys} keys attacked "
        f"· {1000 * ex['seconds'] / keys:.3f} process-ms per key · {manifest['jobs']} jobs",
        "",
        *( ["Demonstration preset: small estimates for learning the workflow; use full samples for research.", ""]
           if settings.get("demo") else []),
        "## Offline: what the theory is built from",
        "",
        f"α = {th['alpha']:g} and p_nd = {th['p_nd']:g} in every stage.",
        "",
        "| stage | (ID, OD) | ε_d | significant bits S_i | ε_a | ε = ε_a · ε_d | N, T |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, (pair, s, t) in enumerate(zip(settings["stages"], sets["stages"], th["stages"]), 1):
        lines.append(
            f"| {i} | {positions(pair['input_diff_bits'])} → {positions(pair['output_mask_bits'])} "
            f"| {abs(t['fwd_eps']):.4f} | {len(s['sig_bits'])}: {bits(s['sig_bits'])} | {t['bwd_eps']:.4f} "
            f"| {t['epsilon']:.4f} (measured directly: {abs(t['eps_measured']):.4f}) "
            f"| {t['N']} ({t['N_exact']:.2f}), {t['T']} ({t['T_exact']:.2f}) |")
    lines += [
        f"| last | exhaustive search | | {len(sets['rest_bits'])}: {bits(sets['rest_bits'])} | | | |",
        "",
        f"A bit goes into S_i when its neutrality in stage i is below {sets['threshold']:g}.",
        "",
        "## Theory vs experiment",
        "",
        "| | theory | experiment |",
        "|---|---|---|",
        f"| data N_1 + ... + N_q | {th['data']} | {th['data']} |",
    ]
    for i, t in enumerate(th["stages"]):
        lines.append(f"| recover S{i + 1} | {power(t['log2_work'])} | {log_or_zero(ex['stage_work'][i] / keys)} |")
    lines += [
        f"| false alarms, stage by stage | 2^{th['log2_pfa_target']:g} per wrong guess (model target) | "
        f"{', '.join(str(a) for a in ex['false_alarms'])} in {', '.join(str(g) for g in ex['guesses'])} guesses |",
        f"| recover the remaining bits | {power(th['log2_rest_work'])} | {log_or_zero(ex['rest_work'] / keys)} |",
        f"| total | {power(th['log2_total'])} | {log_or_zero(total)} |",
        f"| success probability | {th['success']:.4f} ((1 − p_nd)^q) | {ex['successes'] / keys:.4f} "
        f"({ex['successes']} of {keys}) |",
        f"| success probability, per-key ε_d (Section 5) | {th['success_per_key']:.4f} | |",
        "",
        "The false-alarm target assumes independent, unbiased wrong-guess trials. Structured wrong guesses",
        "can violate this model; the target is not a guarantee for this attack. The 64-bit multi-step",
        "experiment is especially affected. Success estimates also approximate the backward bias as fixed.",
        "",
        "Experimental complexities are averages over the attacked keys. Theory counts every guess of a",
        "stage, so the experiment needs about half of it.",
        "",
    ]
    run_util.atomic_text(args.results / "report.md", "\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    run_util.cli_main(main)

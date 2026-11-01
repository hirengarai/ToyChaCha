"""
complexity.py

Data and time complexity of the [AFK+08] attack on ToyChaCha, from the offline
measurements (dist_search, pnb_search, bwd_corr), in the form of the paper (Eq. 6, 7):

    epsilon = fwd_eps * bwd_eps
    N       = ( sqrt(alpha ln4) - z sqrt(1 - epsilon^2) )^2 / epsilon^2,   z = Phi^-1(p_nd)
    T       = N (1 + epsilon) / 2 + z sqrt(N (1 - epsilon^2)) / 2
    C       = 2^m N + 2^(|K| - m) + 2^(|K| - alpha)

m is the number of significant key bits. [AFK+08] counts only 2^m N + 2^(|K| - alpha);
[DGSS22] adds the exhaustive search 2^(|K| - m) over the PNBs. N and T are rounded to
the nearest integer. The paper's 3 sigma is p_nd = 0.00135 = Phi(-3).

--alpha min tries every integer alpha in [1, |K|] and keeps the one with the lowest C,
the way Section 4.2 chose alpha = 11 for the 32-bit key.

The success probability 1 - p_nd assumes every key has the correlation epsilon.
Section 5 instead averages over how fwd_eps spreads over keys; both are computed.

created: 2022
updated: 2026-10-24

by Hiren
Research fellow
NTU, Singapore

Run: python3 complexity.py --results DIR --alpha 11 --p-nd 0.00135    (run.py does this)
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import run_util
from statistics_util import (compute_stage_N, compute_T, compute_C, nearest, minimise_alpha, success_per_key, log2_binomial_tail)

# ---- Main -----------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="folder of this run")
    parser.add_argument("--alpha", required=True, help="false-alarm probability 2^-alpha, or 'min'")
    parser.add_argument("--p-nd", type=float, required=True, help="non-detection probability")
    args = parser.parse_args()

    dist = run_util.load_json(args.results / "dist_search.json")
    pnb = run_util.load_json(args.results / "pnb_search.json")
    bwd = run_util.load_json(args.results / "bwd_corr.json")
    key_size = dist["key_size_bits"]
    fwd_eps, bwd_eps = dist["fwd_eps"], bwd["bwd_eps"]
    epsilon = abs(fwd_eps * bwd_eps)
    m = len(pnb["sig_bits"])
    if args.alpha == "min":
        alpha = minimise_alpha(m, fwd_eps, bwd_eps, key_size, args.p_nd)
        print(f"minimising alpha: {alpha}.")
    else:
        alpha = float(args.alpha)

    N_exact = compute_stage_N(alpha, fwd_eps, bwd_eps, args.p_nd)
    N = nearest(N_exact)
    T_exact = compute_T(N, epsilon, args.p_nd)
    T = nearest(T_exact)
    if not 1 <= T <= N:
        raise ValueError("rounded T must be between 1 and N; adjust alpha or p_nd")
    C = compute_C(m, N, key_size, alpha)
    total_afk = math.log2(2 ** C["sig"] + 2 ** C["false_alarm"])
    total = math.log2(2 ** C["sig"] + 2 ** C["pnb"] + 2 ** C["false_alarm"])

    theory_count_value = 0 if fwd_eps * bwd_eps > 0 else 1
    theory = {
        "key_size_bits": key_size,
        "fwd_eps": fwd_eps,
        "bwd_eps": bwd_eps,
        "epsilon": epsilon,
        "eps_measured": bwd["eps_measured"],
        "alpha": alpha,
        "p_nd": args.p_nd,
        "sig_bits": m,
        "pnb_bits": len(pnb["pnb_bits"]),
        "N_exact": N_exact,
        "N": N,
        "T_exact": T_exact,
        "T": T,
        # the attack counts how often the backward difference equals this value
        "count_value": 0 if fwd_eps * bwd_eps > 0 else 1,
        "log2_sig_work": C["sig"],
        "log2_pnb_work": C["pnb"],
        "log2_false_work": C["false_alarm"],
        "log2_total_afk": total_afk,
        "log2_total": total,
        "success": 1 - args.p_nd,
        "success_per_key": success_per_key(N, T, dist["per_key_fwd_eps"], bwd_eps, theory_count_value),
        "log2_pfa_target": -alpha,
        "log2_pfa_binomial": log2_binomial_tail(N, T, 0.5),
    }
    run_util.save_json(args.results / "complexity.json", theory)
    print(f"epsilon: {epsilon:.4f}, N = {N} ({N_exact:.2f}), T = {T} ({T_exact:.2f}).")
    print(f"Final time complexity:~2^{{{total:.2f}}}.")


if __name__ == "__main__":
    run_util.cli_main(main)

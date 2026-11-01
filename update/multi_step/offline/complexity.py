"""
complexity.py

Data and time complexity of the multiple (ID, OD) attack on ToyChaCha (Section 3.3), from
the offline measurements (dist_search, pnb_search, bwd_corr). For every stage i:

    epsilon_i = fwd_eps_i * bwd_eps_i
    N_i       = ( sqrt(alpha ln4) - z sqrt(1 - epsilon_i^2) )^2 / epsilon_i^2,   z = Phi^-1(p_nd)
    T_i       = N_i (1 + epsilon_i) / 2 + z sqrt(N_i (1 - epsilon_i^2)) / 2
    C         = sum of 2^{m_i} N_i  +  2^{|REST|}                              (Eq. 4)

m_i = |S_i|. p_nd is the non-detection probability of one stage: Pr_nd / q. The paper uses
3.4 sigma for q = 3 stages (p_nd = 0.000337 = Phi(-3.4)) and alpha = 40 in every stage.
N_i and T_i are rounded to the nearest integer.

The success probability (1 - p_nd)^q assumes every key has epsilon_i in every stage.
Section 5 instead averages over how the fwd_eps spread over keys; both are computed.

created: 2022
updated: 2026-10-24

by Hiren
Research fellow
NTU, Singapore

Run: python3 complexity.py --results DIR --alpha 40 --p-nd 0.000337    (run.py does this)
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import run_util
from statistics_util import (compute_stage_N, compute_T, nearest, joint_success_per_key, log2_binomial_tail)

# ---- Main -----------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--results", type=Path, required=True, help="folder of this run")
    parser.add_argument("--alpha", type=float, required=True, help="false-alarm probability of a stage, 2^-alpha")
    parser.add_argument("--p-nd", type=float, required=True, help="non-detection probability of a stage")
    args = parser.parse_args()

    dist = run_util.load_json(args.results / "dist_search.json")
    sets = run_util.load_json(args.results / "pnb_search.json")
    bwd = run_util.load_json(args.results / "bwd_corr.json")

    lengths = [len(dist["fwd_eps"]), len(bwd["bwd_eps"]), len(bwd["eps_measured"]), len(sets["stages"])]
    if len(set(lengths)) != 1 or lengths[0] != 3:
        raise ValueError("measurements must contain the same three stages")
    stages = []
    for fwd_eps, bwd_eps, eps_measured, stage in zip(dist["fwd_eps"], bwd["bwd_eps"], bwd["eps_measured"],
                                                     sets["stages"]):
        epsilon = abs(fwd_eps * bwd_eps)
        N_exact = compute_stage_N(args.alpha, fwd_eps, bwd_eps, args.p_nd)
        N = nearest(N_exact)
        T_exact = compute_T(N, epsilon, args.p_nd)
        T = nearest(T_exact)
        if not 1 <= T <= N:
            raise ValueError("rounded T must be between 1 and N; adjust alpha or p_nd")
        m = len(stage["sig_bits"])
        stages.append({
            "fwd_eps": fwd_eps,
            "bwd_eps": bwd_eps,
            "epsilon": epsilon,
            "eps_measured": eps_measured,
            "sig_bits": m,
            "N_exact": N_exact,
            "N": N,
            "T_exact": T_exact,
            "T": T,
            # the attack counts how often the backward difference equals this value
            "count_value": 0 if fwd_eps * bwd_eps > 0 else 1,
            "log2_work": math.log2(2 ** m * N),
            "log2_pfa_binomial": log2_binomial_tail(N, T, 0.5),
        })

    stage_work = sum(2 ** s["log2_work"] for s in stages)
    rest_work = 2 ** len(sets["rest_bits"])
    theory = {
        "key_size_bits": dist["key_size_bits"],
        "alpha": args.alpha,
        "p_nd": args.p_nd,
        "stages": stages,
        "rest_bits": len(sets["rest_bits"]),
        "data": sum(s["N"] for s in stages),
        "log2_rest_work": math.log2(rest_work),
        "log2_total": math.log2(stage_work + rest_work),
        "success": (1 - args.p_nd) ** len(stages),
        "success_per_key": joint_success_per_key(stages, dist["per_key_fwd_eps"]),
        "log2_pfa_target": -args.alpha,
    }
    run_util.save_json(args.results / "complexity.json", theory)
    for i, s in enumerate(stages, 1):
        print(f"stage {i}: epsilon {s['epsilon']:.4f}, N = {s['N']} ({s['N_exact']:.2f}), T = {s['T']} ({s['T_exact']:.2f}).")
    print(f"Final time complexity:~2^{{{theory['log2_total']:.2f}}}.")


if __name__ == "__main__":
    run_util.cli_main(main)

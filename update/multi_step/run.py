"""
run.py

The multiple (ID, OD) attack on 3-round ToyChaCha: the offline programs, then the key
recovery and the report.

    python3 run.py --demo --output results/demo   small, complete demonstration
    python3 run.py --key-bits 64 --step offline   estimate a 64-bit attack
    python3 run.py --keys 32768 --jobs 8    the paper's number of keys, 8 processes side by side
    python3 run.py --output results/demo --step online --keys 1 --overwrite

Use --output DIR to choose a result folder. Otherwise results go to results/k<key bits>_seed<seed>/; report.md there puts theory next to
experiment. The single (ID, OD) attack Table 4 compares it with is
`python3 run.py --rounds 3` in ../aumasson.

created: 2026
updated: 2026-10-24

by Hiren
Research fellow
NTU, Singapore
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import run_util  # noqa: E402

# the paper's settings (Section 4.2, Table 4): 3 rounds, a 2-round distinguisher per stage
DIST_ROUND, TOTAL_ROUNDS = 2, 3.0
STAGES = [  # (input difference, output mask) of every stage, in the order they are used
    {"input_diff_bits": [[13, 0]], "output_mask_bits": [[1, 6]]},
    {"input_diff_bits": [[14, 0]], "output_mask_bits": [[2, 6]]},
    {"input_diff_bits": [[15, 0]], "output_mask_bits": [[3, 6]]},
]
ALPHA, P_ND = 40, 0.000337
# The paper gives no neutrality threshold for 3 rounds; 0.42 is the 3.5-round one. With a 64-bit key
# the two key words of a column are independent, so a single flip is more neutral (up to about 0.72):
# 0.9 keeps the whole column significant, as the 32-bit key does with 0.42.
THRESHOLD = {32: 0.42, 64: 0.9}

OFFLINE = ["dist_search", "pnb_search", "bwd_corr"]  # run in this order, then complexity.py


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    run_util.add_run_arguments(parser, default_keys=1024)
    parser.add_argument("--threshold", type=float, help="neutrality below this puts a bit in S_i (default: 0.42, 0.9 for 64 bits)")
    parser.add_argument("--alpha", type=float, help="Pr_fa of a stage = 2^-alpha")
    parser.add_argument("--p-nd", type=float, help="non-detection probability of a stage")
    args = run_util.finish_args(parser, default_keys=1024)
    return args


def write_control_panel(out: Path) -> None:
    """control_panel.hpp: the settings of the run, plus what the offline programs have found so far."""
    s = run_util.load_json(out / "settings.json")
    for stage in s["stages"]:
        run_util.validate_positions(stage["input_diff_bits"], stage["output_mask_bits"])
    q = len(s["stages"])
    ids = ", ".join(run_util.cpp_bitpos(st["input_diff_bits"]) for st in s["stages"])
    masks = ", ".join(run_util.cpp_bitpos(st["output_mask_bits"]) for st in s["stages"])
    sections = [("Settings", [
        f"constexpr int KEY_SIZE_BITS = {s['key_size_bits']};   // 32 (the paper's ToyChaCha) or 64",
        f"constexpr double DIST_ROUND = {s['dist_round']};    // the round where every OD is read",
        f"constexpr double TOTAL_ROUNDS = {s['total_rounds']};",
        f"constexpr double SIG_THRESHOLD = {s['threshold']}; // neutrality below this puts a key bit in S_i",
        "",
        f"constexpr int STAGES = {q};",
        "using BitPos = attack_util::BitPos;",
        f"const std::vector<BitPos> INPUT_DIFF_BITS[STAGES] = {{{ids}}};",
        f"const std::vector<BitPos> OUTPUT_MASK_BITS[STAGES] = {{{masks}}};",
        "",
        "static_assert(KEY_SIZE_BITS == 32 || KEY_SIZE_BITS == 64);",
        "constexpr int DIST_STEP = int(DIST_ROUND * 4);",
        "constexpr int TOTAL_STEP = int(TOTAL_ROUNDS * 4);",
        "static_assert(DIST_ROUND >= 0 && TOTAL_ROUNDS >= DIST_ROUND &&",
        "              DIST_ROUND * 4 == DIST_STEP && TOTAL_ROUNDS * 4 == TOTAL_STEP,",
        '              "Rounds must be ordered, nonnegative multiples of 0.25.");',
    ])]
    if (out / "pnb_search.json").exists():
        sets = run_util.load_json(out / "pnb_search.json")
        sig = ", ".join(run_util.cpp_list(st["sig_bits"]) for st in sets["stages"])
        sections.append(("From pnb_search", [
            f"const std::vector<u16> SIG_BITS[STAGES] = {{{sig}}}; // S_i of every stage",
            f"const std::vector<u16> REST_BITS = {run_util.cpp_list(sets['rest_bits'])}; // left for the exhaustive search",
        ]))
    if (out / "complexity.json").exists():
        th = run_util.load_json(out / "complexity.json")["stages"]
        sections.append(("From complexity.py", [
            f"constexpr u64 N[STAGES] = {run_util.cpp_list([t['N'] for t in th])};   // samples of every stage",
            f"constexpr u64 T[STAGES] = {run_util.cpp_list([t['T'] for t in th])};   // thresholds",
            f"constexpr u64 N_MAX = {max(t['N'] for t in th)};",
            f"constexpr u8 COUNT_VALUE[STAGES] = {run_util.cpp_list([t['count_value'] for t in th])}; "
            "// each test counts backward differences equal to this",
        ]))
    run_util.write_control_panel(out / "control_panel.hpp", sections)


def offline(args: argparse.Namespace, out: Path) -> None:
    completed = run_util.prepare_offline(args, out, "multi_step", OFFLINE)
    settings = {
        "key_size_bits": args.key_bits,
        "dist_round": DIST_ROUND,
        "total_rounds": TOTAL_ROUNDS,
        "stages": STAGES,
        "threshold": THRESHOLD[args.key_bits] if args.threshold is None else args.threshold,
        "alpha": ALPHA if args.alpha is None else args.alpha,
        "p_nd": P_ND if args.p_nd is None else args.p_nd,
        "seed": args.seed,
        "samples": args.samples,
        "spread_keys": args.spread_keys,
        "spread_ivs": args.spread_ivs,
        "demo": args.demo,
    }
    if args.resume:
        settings = run_util.load_json(out / "settings.json")
    else:
        run_util.save_json(out / "settings.json", settings)
    run_util.offline_pipeline(args, out, "multi_step", OFFLINE, write_control_panel, settings, completed)


def online(args: argparse.Namespace, out: Path) -> None:
    run_util.online_pipeline(args, out, "multi_step")


def main() -> None:
    args = parse_args()
    if len(STAGES) != 3:
        sys.exit("online/key_recovery.cpp has one loop per stage: it is written for 3 stages")
    out = args.output or HERE / "results" / f"k{args.key_bits}_seed{args.seed}"
    out = out.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.step == "online" or args.resume:
        run_util.validate_offline(out, "multi_step", ready=False)
        run_util.match_saved_settings(args, run_util.load_json(out / "settings.json"))
    start = time.time()
    print(f"multiple (ID, OD) attack on 3-round ToyChaCha with a {args.key_bits}-bit key, results in {out}", flush=True)
    if args.step in ("all", "offline"):
        offline(args, out)
    if args.step in ("all", "online"):
        online(args, out)
    destination = out / ("offline_manifest.json" if args.step == "offline" else "report.md")
    print(f"done in {time.time() - start:.0f} s; results: {destination}")


if __name__ == "__main__":
    run_util.cli_main(main)

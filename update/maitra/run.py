"""
run.py

The [Mai16] chosen-IV attack on 3.5-round ToyChaCha: the offline programs, then the key
recovery and the report.

    python3 run.py --demo --output results/demo   small, complete demonstration
    python3 run.py --key-bits 64 --step offline   estimate a 64-bit attack
    python3 run.py --keys 32768 --jobs 8    the paper's number of keys, 8 processes side by side
    python3 run.py --output results/demo --step online --keys 1 --overwrite

Use --output DIR to choose a result folder. Otherwise results go to results/k<key bits>_seed<seed>/; report.md there puts theory next to
experiment.

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

# the paper's settings (Section 4.2): 3.5 rounds, a 2-round distinguisher.
# A 64-bit key has no setting in the paper: complexity.py then picks the alpha with the lowest cost.
DIST_ROUND, TOTAL_ROUNDS = 2, 3.5
THRESHOLD, ALPHA, P_ND = 0.45, "11", 0.00135

OFFLINE = ["weak_key_search", "dist_search", "pnb_search", "bwd_corr"]  # in this order, then complexity.py


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    run_util.add_run_arguments(parser, default_keys=64)
    parser.add_argument("--id", type=int, nargs=2, metavar=("WORD", "BIT"), help="input difference")
    parser.add_argument("--od", type=int, nargs=2, metavar=("WORD", "BIT"), help="output difference")
    parser.add_argument("--threshold", type=float, help="PNB neutrality threshold")
    parser.add_argument("--alpha", help="Pr_fa = 2^-alpha, or 'min' for the lowest cost (default: the paper's)")
    parser.add_argument("--p-nd", type=float, help="non-detection probability")
    args = run_util.finish_args(parser, default_keys=64)
    return args


def write_control_panel(out: Path) -> None:
    """control_panel.hpp: the settings of the run, plus what the offline programs have found so far."""
    s = run_util.load_json(out / "settings.json")
    run_util.validate_positions(s["input_diff_bits"], s["output_mask_bits"])
    sections = [("Settings", [
        f"constexpr int KEY_SIZE_BITS = {s['key_size_bits']};   // 32 (the paper's ToyChaCha) or 64",
        f"constexpr double DIST_ROUND = {s['dist_round']};    // the round where the OD is read",
        f"constexpr double TOTAL_ROUNDS = {s['total_rounds']};",
        f"constexpr double PNB_THRESHOLD = {s['threshold']}; // neutrality above this makes a key bit a PNB",
        "",
        "using BitPos = attack_util::BitPos;",
        f"const std::vector<BitPos> INPUT_DIFF_BITS = {run_util.cpp_bitpos(s['input_diff_bits'])};  // one bit of an IV word",
        f"const std::vector<BitPos> OUTPUT_MASK_BITS = {run_util.cpp_bitpos(s['output_mask_bits'])};",
        "",
        "static_assert(KEY_SIZE_BITS == 32 || KEY_SIZE_BITS == 64);",
        "constexpr int DIST_STEP = int(DIST_ROUND * 4);",
        "constexpr int TOTAL_STEP = int(TOTAL_ROUNDS * 4);",
        "static_assert(DIST_ROUND >= 0 && TOTAL_ROUNDS >= DIST_ROUND &&",
        "              DIST_ROUND * 4 == DIST_STEP && TOTAL_ROUNDS * 4 == TOTAL_STEP,",
        '              "Rounds must be ordered, nonnegative multiples of 0.25.");',
    ])]
    if (out / "weak_key_search.json").exists():
        weak = run_util.load_json(out / "weak_key_search.json")
        sections.append(("From weak_key_search", [
            "// the suitable IV byte of every column key, -1 for a strong key",
            f"constexpr int SUITABLE_IV[] = {run_util.cpp_list(weak['suitable_iv'])};",
        ]))
    if (out / "pnb_search.json").exists():
        pnb = run_util.load_json(out / "pnb_search.json")
        sections.append(("From pnb_search", [
            f"const std::vector<u16> ID_SIG_BITS = {run_util.cpp_list(pnb['id_sig_bits'])}; // the column key",
            f"const std::vector<u16> SIG_BITS = {run_util.cpp_list(pnb['sig_bits'])};",
            f"const std::vector<u16> PNB_BITS = {run_util.cpp_list(pnb['pnb_bits'])};",
        ]))
    if (out / "complexity.json").exists():
        th = run_util.load_json(out / "complexity.json")
        sections.append(("From complexity.py", [
            f"constexpr u64 N = {th['N']};        // samples for each guess of the column key",
            f"constexpr u64 T = {th['T']};        // threshold",
            f"constexpr u8 COUNT_VALUE = {th['count_value']};  // the test counts backward differences equal to this",
        ]))
    run_util.write_control_panel(out / "control_panel.hpp", sections)


def offline(args: argparse.Namespace, out: Path) -> None:
    completed = run_util.prepare_offline(args, out, "maitra", OFFLINE)
    alpha = args.alpha if args.alpha is not None else (ALPHA if args.key_bits == 32 else "min")
    settings = {
        "key_size_bits": args.key_bits,
        "dist_round": DIST_ROUND,
        "total_rounds": TOTAL_ROUNDS,
        "input_diff_bits": [args.id if args.id is not None else [13, 0]],
        "output_mask_bits": [args.od if args.od is not None else [1, 6]],
        "threshold": THRESHOLD if args.threshold is None else args.threshold,
        "alpha": alpha,
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
    run_util.offline_pipeline(args, out, "maitra", OFFLINE, write_control_panel, settings, completed)


def online(args: argparse.Namespace, out: Path) -> None:
    run_util.online_pipeline(args, out, "maitra")


def main() -> None:
    args = parse_args()
    out = args.output or HERE / "results" / f"k{args.key_bits}_seed{args.seed}"
    out = out.expanduser().resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.step == "online" or args.resume:
        run_util.validate_offline(out, "maitra", ready=False)
        run_util.match_saved_settings(args, run_util.load_json(out / "settings.json"))
    start = time.time()
    print(f"[Mai16] chosen-IV attack on 3.5-round ToyChaCha with a {args.key_bits}-bit key, results in {out}",
          flush=True)
    if args.step in ("all", "offline"):
        offline(args, out)
    if args.step in ("all", "online"):
        online(args, out)
    destination = out / ("offline_manifest.json" if args.step == "offline" else "report.md")
    print(f"done in {time.time() - start:.0f} s; results: {destination}")


if __name__ == "__main__":
    run_util.cli_main(main)

"""
run_util.py

Shared by every run.py: build and run the C++ programs, write the control panel,
read and write the JSON results, and spread a key recovery over several processes.
Nothing here knows about a particular attack; each run.py decides what to run.

created: 2026
updated: 2026-10-24

by Hiren
Research fellow
NTU, Singapore
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from statistics_util import validate_parameters

ROOT = Path(__file__).resolve().parent
CXX = os.environ.get("CXX", "g++")
# the build line of chachaCipher, plus warnings
CXXFLAGS = ["-std=c++20", "-O3", "-march=native", "-pthread", "-Wall", "-Wextra"]
MAX_U64 = (1 << 64) - 1


def add_run_arguments(parser: argparse.ArgumentParser, default_keys: int) -> None:
    """Common CLI. None distinguishes explicit settings from saved/default settings."""
    parser.add_argument("--key-bits", type=int, choices=[32, 64])
    parser.add_argument("--seed", type=int)
    parser.add_argument("--samples", type=int, help="offline samples per estimate (default: 4194304)")
    parser.add_argument("--spread-keys", type=int, help="keys for the per-key bias estimate (default: 4096)")
    parser.add_argument("--spread-ivs", type=int, help="IVs per key for that estimate (default: 4096)")
    parser.add_argument("--keys", type=int, help=f"keys attacked online (default: {default_keys})")
    parser.add_argument("--jobs", type=int, help="parallel key-recovery processes (default: 1)")
    parser.add_argument("--step", choices=["all", "offline", "online"], default="all")
    parser.add_argument("--output", type=Path, help="result folder; reuse this path for online/resume")
    parser.add_argument("--demo", action="store_true", help="smaller offline estimates and one online key")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--overwrite", action="store_true", help="replace this step and invalidate dependent results")
    mode.add_argument("--resume", action="store_true", help="reuse completed offline steps after checking their inputs")


def finish_args(parser: argparse.ArgumentParser, default_keys: int):
    args = parser.parse_args()
    args.keys_requested = args.keys is not None
    args.jobs_requested = args.jobs is not None
    names = ("key_bits", "seed", "samples", "spread_keys", "spread_ivs", "rounds",
             "id", "od", "threshold", "alpha", "p_nd")
    args.requested = {name: getattr(args, name) for name in names if getattr(args, name, None) is not None}
    defaults = {"key_bits": 32, "seed": 1, "samples": 1 << 22,
                "spread_keys": 4096, "spread_ivs": 4096, "keys": default_keys, "jobs": 1}
    if args.demo:
        if args.step == "online":
            parser.error("--demo creates offline estimates; use --keys 1 for an existing online run")
        defaults.update(samples=1 << 16, spread_keys=64, spread_ivs=512, keys=1)
    for name, value in defaults.items():
        if getattr(args, name) is None:
            setattr(args, name, value)
    try:
        for name in ("samples", "spread_keys", "spread_ivs", "keys", "jobs"):
            value = getattr(args, name)
            if not 1 <= value <= MAX_U64:
                raise ValueError(f"--{name.replace('_', '-')} must be a positive integer below 2^64")
        if not 0 <= args.seed <= MAX_U64 or args.seed + min(args.jobs, args.keys) - 1 > MAX_U64:
            raise ValueError("--seed and all worker seeds must fit in an unsigned 64-bit integer")
        if getattr(args, "id", None) is not None:
            validate_positions([args.id], [args.od] if args.od is not None else [[1, 6]])
        elif getattr(args, "od", None) is not None:
            validate_positions([[13, 0]], [args.od])
        if args.threshold is not None and (not math.isfinite(args.threshold) or not -1 <= args.threshold <= 1):
            raise ValueError("--threshold must be finite and between -1 and 1")
        validate_parameters(1 if args.alpha in (None, "min") else float(args.alpha),
                            0.00135 if args.p_nd is None else args.p_nd)
    except ValueError as error:
        parser.error(str(error))
    return args


def validate_positions(inputs: list, outputs: list) -> None:
    for values, low, high, label in ((inputs, 12, 15, "input"), (outputs, 0, 15, "output")):
        if not values:
            raise ValueError(f"the {label} bit list cannot be empty")
        for word, bit in values:
            if not isinstance(word, int) or not isinstance(bit, int) or not low <= word <= high or not 0 <= bit <= 7:
                raise ValueError(f"{label} positions need words {low}..{high} and bits 0..7")


def cli_main(main) -> None:
    try:
        main()
    except (ValueError, OSError) as error:
        sys.exit(f"error: {error}")
    except KeyboardInterrupt:
        sys.exit("interrupted; use --resume to reuse completed offline steps")

# ---- Build and run --------------------------------------------

def build(source: Path, results: Path) -> Path:
    """Compile one program against this run's control_panel.hpp; the binary goes to results/bin."""
    binary = results / "bin" / source.stem
    binary.parent.mkdir(parents=True, exist_ok=True)
    run([CXX, *CXXFLAGS, f"-I{results}", f"-I{ROOT}", "-o", str(binary), str(source)])
    return binary


def run(cmd: list[str]) -> None:
    """Run one command, show it, and stop everything if it fails."""
    print("$", " ".join(cmd), flush=True)
    if subprocess.run(cmd).returncode != 0:
        sys.exit(f"failed: {' '.join(cmd)}")


def run_python(script: Path, args: list[str]) -> None:
    run([sys.executable, str(script), *args])


# ---- Results --------------------------------------------------

def load_json(path: Path) -> dict:
    if not path.exists():
        sys.exit(f"{path} is missing: run the earlier steps first")
    def invalid(value):
        raise ValueError(f"{path} contains a non-finite number: {value}")
    return json.loads(path.read_text(), parse_constant=invalid)


def save_json(path: Path, data: dict) -> None:
    atomic_text(path, json.dumps(data, indent=2, allow_nan=False) + "\n")


def atomic_text(path: Path, text: str) -> None:
    """Replace a file only after its complete contents have been written."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False, encoding="utf-8") as handle:
            temporary = Path(handle.name)
            handle.write(text)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def check_free(paths: list[Path], overwrite: bool) -> None:
    """Refuse to replace earlier results unless --overwrite was given."""
    taken = [p for p in paths if p.exists()]
    if taken and not overwrite:
        sys.exit(f"{taken[0]} already exists; use --resume to reuse it, --output DIR for a new run, "
                 "or --overwrite to replace it")


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes(attack: str) -> dict:
    paths = [*ROOT.glob("*.hpp"), *ROOT.glob("*.py"), *ROOT.glob("common_utility/*.hpp"),
             ROOT / attack / "run.py", *(ROOT / attack / "offline").glob("*.cpp"),
             *(ROOT / attack / "offline").glob("*.py")]
    return {str(p.relative_to(ROOT)): file_hash(p) for p in sorted(paths)}


def record_offline(out: Path, attack: str, completed: list[str]) -> None:
    names = ["settings.json", "control_panel.hpp", *(name + ".json" for name in completed)]
    save_json(out / "offline_manifest.json", {
        "version": 1, "attack": attack, "completed": completed,
        "artifacts": {name: file_hash(out / name) for name in names},
        "sources": source_hashes(attack),
    })


def validate_offline(out: Path, attack: str = None, ready: bool = True, check_sources: bool = True) -> dict:
    path = out / "offline_manifest.json"
    if not path.exists():
        raise ValueError(f"{out} has no verified offline manifest; run --step offline "
                         "(use --overwrite for legacy results, or --output DIR to keep them)")
    manifest = load_json(path)
    if manifest.get("version") != 1 or (attack and manifest["attack"] != attack):
        raise ValueError("this output folder belongs to a different attack or manifest version")
    for name, digest in manifest["artifacts"].items():
        if name != Path(name).name or not (out / name).is_file() or file_hash(out / name) != digest:
            raise ValueError(f"{name} changed or is missing; generated files are not editable. "
                             "Rerun offline with the desired CLI settings and --overwrite, or use a new --output")
    if ready and "complexity" not in manifest["completed"]:
        raise ValueError("offline measurements are incomplete; use --resume to finish them")
    if check_sources and source_hashes(manifest["attack"]) != manifest["sources"]:
        raise ValueError("offline source code changed; use --overwrite or a new --output to recompute measurements")
    return manifest


def match_saved_settings(args, settings: dict) -> None:
    names = {"key_bits": "key_size_bits", "rounds": "total_rounds", "id": "input_diff_bits",
             "od": "output_mask_bits"}
    for arg, requested in args.requested.items():
        key = names.get(arg, arg)
        expected = settings.get(key, 4096 if arg in ("spread_keys", "spread_ivs") else None)
        if arg in ("id", "od"):
            requested = [requested]
        if arg == "rounds":
            requested = float(requested)
        if arg == "alpha" and requested != "min" and expected != "min":
            expected, requested = float(expected), float(requested)
        if requested != expected:
            raise ValueError(f"--{arg.replace('_', '-')} differs from the saved offline setting {expected}; "
                             "rerun offline with --overwrite or a new --output")
    # An explicit output path selects saved key size/rounds/seed when omitted on the CLI.
    args.key_bits, args.seed = settings["key_size_bits"], settings["seed"]
    if hasattr(args, "rounds"):
        args.rounds = f"{settings['total_rounds']:g}"
    if args.seed + min(args.jobs, args.keys) - 1 > MAX_U64:
        raise ValueError("saved seed plus worker index exceeds the unsigned 64-bit range")


ONLINE_FILES = ["key_recovery.json", "report.md", "online_manifest.json", "online_plan.json"]


def clear_online(out: Path, overwrite: bool = True) -> None:
    check_free([out / name for name in ONLINE_FILES], overwrite)
    for name in ONLINE_FILES:
        (out / name).unlink(missing_ok=True)
    for pattern in ("key_recovery_*.json", "key_recovery_*.log", "key_recovery_*.partial"):
        for path in (out / "jobs").glob(pattern):
            path.unlink()


def prepare_offline(args, out: Path, attack: str, steps: list[str]) -> list[str]:
    if args.resume:
        manifest = validate_offline(out, attack, ready=False)
        match_saved_settings(args, load_json(out / "settings.json"))
        settings = load_json(out / "settings.json")
        for name in ("samples", "spread_keys", "spread_ivs"):
            setattr(args, name, settings.get(name, 4096))
        return manifest["completed"]
    names = ["settings.json", "control_panel.hpp", "offline_manifest.json", *ONLINE_FILES,
             *(name + ".json" for name in [*steps, "complexity"])]
    check_free([out / name for name in names], args.overwrite)
    for name in names:
        (out / name).unlink(missing_ok=True)
    clear_online(out)
    return []


def run_offline_program(binary: Path, args, out: Path, name: str) -> None:
    target = out / (name + ".json")
    temporary = target.with_suffix(".partial")
    try:
        run([str(binary), "--seed", str(args.seed), "--samples", str(args.samples),
             "--spread-keys", str(args.spread_keys), "--spread-ivs", str(args.spread_ivs),
             "--out", str(temporary)])
        load_json(temporary)
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def offline_pipeline(args, out: Path, attack: str, steps: list[str], write_panel, settings: dict,
                     completed: list[str]) -> None:
    print("settings:", settings, flush=True)
    write_panel(out)
    record_offline(out, attack, completed)
    sources = source_hashes(attack)
    for name in [*steps, "complexity"]:
        if name in completed:
            print(f"[offline] reusing {name}", flush=True)
            continue
        print(f"[offline] {name}", flush=True)
        if name == "complexity":
            run_python(ROOT / attack / "offline/complexity.py",
                       ["--results", str(out), "--alpha", str(settings["alpha"]),
                        "--p-nd", str(settings["p_nd"])])
        else:
            binary = build(ROOT / attack / "offline" / (name + ".cpp"), out)
            run_offline_program(binary, args, out, name)
        if source_hashes(attack) != sources:
            raise ValueError("source code changed during this run; restart offline with --overwrite")
        completed.append(name)
        write_panel(out)
        record_offline(out, attack, completed)


def online_pipeline(args, out: Path, attack: str) -> None:
    validate_offline(out, attack)
    match_saved_settings(args, load_json(out / "settings.json"))
    if args.resume and (out / "online_manifest.json").exists():
        previous = validate_report(out)
        if args.keys_requested and args.keys != previous["keys"]:
            raise ValueError("--keys differs from the completed online run; use --overwrite to replace it")
        if args.jobs_requested and min(args.jobs, previous["keys"]) != previous["jobs"]:
            raise ValueError("--jobs differs from the completed online run; use --overwrite to replace it")
        print(f"[online] reusing {previous['keys']} attacked keys; report: {out / 'report.md'}", flush=True)
        run_python(ROOT / attack / "online/report.py", ["--results", str(out)])
        return
    if args.resume and (out / "online_plan.json").exists():
        restore_online_plan(out, args, attack)
    replace_online = args.overwrite or args.resume
    check_free([out / name for name in ONLINE_FILES], replace_online)
    theory = load_json(out / "complexity.json")
    validate_search_sets(out, attack)
    print(f"theory: 2^{theory['log2_total']:.2f} per key", flush=True)
    binary = build(ROOT / attack / "online/key_recovery.cpp", out)
    clear_online(out, replace_online)
    save_json(out / "online_plan.json", {
        "version": 1, "offline_sha256": file_hash(out / "offline_manifest.json"),
        "source_sha256": file_hash(ROOT / attack / "online/key_recovery.cpp"),
        "seed": args.seed, "keys": args.keys, "jobs": min(args.jobs, args.keys),
    })
    totals = run_key_recovery(binary, args.keys, args.jobs, args.seed, out)
    save_json(out / "key_recovery.json", totals)
    record_online(out, args)
    run_python(ROOT / attack / "online/report.py", ["--results", str(out)])


def restore_online_plan(out: Path, args, attack: str) -> None:
    plan = load_json(out / "online_plan.json")
    if (plan.get("version") != 1 or plan["offline_sha256"] != file_hash(out / "offline_manifest.json")
            or plan["source_sha256"] != file_hash(ROOT / attack / "online/key_recovery.cpp")):
        raise ValueError("interrupted online run has different inputs or source; use --step online --overwrite")
    if ((args.keys_requested and args.keys != plan["keys"])
            or (args.jobs_requested and min(args.jobs, plan["keys"]) != plan["jobs"])):
        raise ValueError("key count or job layout differs from the interrupted run; use --overwrite to replace it")
    args.keys, args.jobs, args.seed = plan["keys"], plan["jobs"], plan["seed"]
    if not 1 <= args.jobs <= args.keys <= MAX_U64 or not 0 <= args.seed <= MAX_U64 - (args.jobs - 1):
        raise ValueError("interrupted online plan has invalid counts or worker seeds")


def validate_search_sets(out: Path, attack: str) -> None:
    pnb = load_json(out / "pnb_search.json")
    settings = load_json(out / "settings.json")
    if attack == "multi_step":
        groups = [s["sig_bits"] for s in pnb["stages"]] + [pnb["rest_bits"]]
    else:
        groups = [pnb["sig_bits"], pnb["pnb_bits"]]
        if attack == "maitra":
            groups.append(pnb["id_sig_bits"])
    if any(len(bits) >= 64 for bits in groups):
        raise ValueError("a search set contains 64 bits; this executable supports at most 63 bits per set. "
                         "Choose another neutrality threshold or run only --step offline")
    all_bits = [bit for group in groups for bit in group]
    if sorted(all_bits) != list(range(settings["key_size_bits"])):
        raise ValueError("search sets must partition the key bits exactly once")


def record_online(out: Path, args) -> None:
    save_json(out / "online_manifest.json", {
        "version": 1, "offline_sha256": file_hash(out / "offline_manifest.json"),
        "results_sha256": file_hash(out / "key_recovery.json"),
        "seed": args.seed, "keys": args.keys, "jobs": min(args.jobs, args.keys),
        "compiler": CXX, "compiler_flags": CXXFLAGS,
    })


def validate_report(out: Path) -> dict:
    validate_offline(out, check_sources=False)
    manifest = load_json(out / "online_manifest.json")
    if (manifest.get("version") != 1 or manifest["offline_sha256"] != file_hash(out / "offline_manifest.json")
            or manifest["results_sha256"] != file_hash(out / "key_recovery.json")):
        raise ValueError("online results do not match these offline measurements; rerun --step online --overwrite")
    results = load_json(out / "key_recovery.json")
    if results.get("keys", 0) <= 0 or results["keys"] != manifest["keys"]:
        raise ValueError("online results need a positive key count matching the run manifest")
    return manifest


# ---- Control panel --------------------------------------------

def cpp_list(values: list) -> str:
    """{ 1, 2, 3 }: a C++ braced list."""
    return "{" + ", ".join(str(v) for v in values) + "}"


def cpp_bitpos(bits: list) -> str:
    """{{13, 0}}: a std::vector<BitPos> initializer."""
    return "{" + ", ".join(f"{{{w}, {b}}}" for w, b in bits) + "}"


def write_control_panel(path: Path, sections: list[tuple[str, list[str]]]) -> None:
    """control_panel.hpp: one '// ---- title ----' block per section."""
    lines = [
        "/*",
        " * Control panel of this run, written by run.py from its settings and from what",
        " * the offline programs have found so far. This file is generated and verified;",
        " * change settings using run.py, then recompute offline measurements.",
        " */",
        "#pragma once",
    ]
    for title, body in sections:
        lines += ["", f"// ---- {title} ".ljust(64, "-"), "", *body]
    atomic_text(path, "\n".join(lines) + "\n")


# ---- Key recovery over several processes ----------------------

def add_up(totals: dict, part: dict) -> None:
    """Add one job's counters to the totals; lists (one entry per stage) add up entry by entry."""
    for key, value in part.items():
        if isinstance(value, list):
            old = totals.get(key, [0] * len(value))
            if not isinstance(old, list) or len(old) != len(value):
                raise ValueError(f"inconsistent job counters for {key}")
            totals[key] = [a + b for a, b in zip(old, value)]
        else:
            totals[key] = totals.get(key, 0) + value


def run_key_recovery(binary: Path, keys: int, jobs: int, seed: int, results: Path) -> dict:
    """Attack `keys` random keys with `jobs` processes side by side and add up their counters.

    Job j uses seed + j, so a run is repeated exactly by the same --seed, --keys and --jobs.
    """
    if keys <= 0 or jobs <= 0 or not 0 <= seed <= MAX_U64 - (min(jobs, keys) - 1):
        raise ValueError("key count, job count, and worker seeds are out of range")
    jobs = min(jobs, keys)
    folder = results / "jobs"
    folder.mkdir(exist_ok=True)
    procs, outputs, logs = [], [], []
    start = last_update = time.monotonic()
    try:
        for j in range(jobs):
            share = keys // jobs + (1 if j < keys % jobs else 0)
            out = folder / f"key_recovery_{j}.json"
            temporary = out.with_suffix(".partial")
            cmd = [str(binary), "--seed", str(seed + j), "--keys", str(share), "--out", str(temporary)]
            print("$", " ".join(cmd), flush=True)
            log = None if jobs == 1 else open(folder / f"key_recovery_{j}.log", "w")
            logs.append(log)
            outputs.append((out, temporary, share))
            procs.append(subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT if log else None))
        while True:
            status = [p.poll() for p in procs]
            if any(code is not None and code != 0 for code in status):
                raise ValueError(f"a key-recovery job failed; see {folder}")
            done = sum(code is not None for code in status)
            if done == jobs:
                break
            now = time.monotonic()
            if now - last_update >= 10:
                print(f"[online] {done}/{jobs} jobs finished, {now - start:.0f} s elapsed; logs: {folder}", flush=True)
                last_update = now
            time.sleep(0.1)
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for log in logs:
            if log:
                log.close()
    totals: dict = {}
    for out, temporary, share in outputs:
        part = load_json(temporary)
        if part.get("keys") != share:
            raise ValueError(f"{temporary} has the wrong key count")
        add_up(totals, part)
        temporary.replace(out)
    return totals

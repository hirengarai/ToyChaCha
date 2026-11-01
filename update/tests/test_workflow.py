"""Run from the repository root: python3 -m unittest discover -s update/tests -v."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import run_util
import statistics_util as stats


def runner(attack):
    spec = importlib.util.spec_from_file_location("run_" + attack, ROOT / attack / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def arguments(module, *values):
    with patch.object(sys, "argv", ["run.py", *values]):
        return module.parse_args()


def fixture(out, attack="aumasson"):
    """A complete, internally consistent offline run, without generated research data."""
    settings = dict(key_size_bits=32, dist_round=2, total_rounds=3.5, seed=1,
                    samples=65536, spread_keys=64, spread_ivs=512, threshold=0.42,
                    alpha="11", p_nd=0.00135, input_diff_bits=[[13, 0]], output_mask_bits=[[1, 6]])
    run_util.save_json(out / "settings.json", settings)
    run_util.save_json(out / "dist_search.json", {"key_size_bits": 32, "fwd_eps": -0.91})
    run_util.save_json(out / "pnb_search.json", {"sig_bits": list(range(16)), "pnb_bits": list(range(16, 32))})
    run_util.save_json(out / "bwd_corr.json", {"bwd_eps": 0.38})
    run_util.save_json(out / "complexity.json", {"N": 378, "T": 227, "count_value": 1, "log2_total": 24.68})
    module = runner(attack)
    module.write_control_panel(out)
    run_util.record_offline(out, attack, [*module.OFFLINE, "complexity"])
    return module


class StatisticsTests(unittest.TestCase):
    def test_binomial_matches_exact_small_distributions_and_endpoints(self):
        for n in (0, 1, 5, 10, 30):
            for t in range(-1, n + 3):
                for p in (0, 0.1, 0.5, 0.9, 1):
                    expected = sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i)
                                   for i in range(max(0, t), n + 1))
                    self.assertAlmostEqual(stats.binomial_tail(n, t, p), expected, places=12)

    def test_extremely_small_false_alarm_tail_stays_finite_in_log_space(self):
        self.assertAlmostEqual(stats.log2_binomial_tail(2000, 2000, 0.5), -2000, places=10)

    def test_success_uses_one_fixed_direction_for_all_keys(self):
        for count_value in (0, 1):
            self.assertEqual(stats.success_per_key(10, 9, [-1, 1], 1, count_value), 0.5)
        stage = dict(N=10, T=9, bwd_eps=1, count_value=0)
        self.assertEqual(stats.joint_success_per_key([stage, stage], [[1, 1], [1, -1]]), 0.5)

    def test_zero_signal_and_invalid_model_parameters_have_clear_errors(self):
        for alpha, fwd, bwd, p_nd in [(11, 0, 1, 0.00135), (0, 1, 1, 0.00135),
                                       (11, 1, 1, 0), (11, 1, 1, 0.5), (11, math.nan, 1, 0.01)]:
            with self.assertRaises(ValueError):
                stats.compute_stage_N(alpha, fwd, bwd, p_nd)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="toychacha-test-")
        self.out = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_all_runners_reject_invalid_numbers(self):
        cases = [("--keys", "0"), ("--keys", "-1"), ("--samples", "0"), ("--jobs", "0"),
                 ("--seed", "-1"), ("--seed", str(1 << 64)), ("--spread-keys", "0"),
                 ("--spread-ivs", "-1"), ("--threshold", "nan"), ("--threshold", "1.1"),
                 ("--alpha", "-1"), ("--alpha", "nan"), ("--p-nd", "0"), ("--p-nd", "1")]
        for attack in ("aumasson", "maitra", "multi_step"):
            module = runner(attack)
            for case in cases:
                with self.subTest(attack=attack, args=case), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        arguments(module, *case)
                    self.assertEqual(error.exception.code, 2)

    def test_invalid_positions_are_rejected_before_creating_output(self):
        for attack in ("aumasson", "maitra"):
            for option, position in [("--id", [16, 0]), ("--id", [4, 0]), ("--id", [13, 8]),
                                      ("--od", [16, 0]), ("--od", [1, -1])]:
                output = self.out / "must_not_exist"
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    arguments(runner(attack), option, *map(str, position), "--output", str(output))
                self.assertFalse(output.exists())

    def test_demo_scales_every_offline_sample_dimension(self):
        args = arguments(runner("aumasson"), "--demo")
        self.assertEqual((args.samples, args.spread_keys, args.spread_ivs, args.keys), (65536, 64, 512, 1))

    def test_worker_seed_overflow_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            arguments(runner("aumasson"), "--seed", str((1 << 64) - 1), "--keys", "2", "--jobs", "2")

    def test_changed_online_parameters_fail_instead_of_being_ignored(self):
        module = fixture(self.out)
        for values in [("--threshold", "0.99"), ("--alpha", "20"), ("--id", "12", "0"),
                       ("--od", "0", "1"), ("--samples", "123"), ("--seed", "2")]:
            args = arguments(module, "--step", "online", *values)
            with self.assertRaisesRegex(ValueError, "differs from the saved"):
                run_util.match_saved_settings(args, run_util.load_json(self.out / "settings.json"))

    def test_edited_header_is_preserved_and_rejected(self):
        fixture(self.out)
        header = self.out / "control_panel.hpp"
        edited = header.read_text() + "\n// intentional edit\n"
        header.write_text(edited)
        with self.assertRaisesRegex(ValueError, "control_panel.hpp changed"):
            run_util.validate_offline(self.out)
        self.assertEqual(header.read_text(), edited)

    def test_offline_overwrite_invalidates_all_online_artifacts(self):
        module = fixture(self.out)
        for name in run_util.ONLINE_FILES:
            (self.out / name).write_text("old")
        (self.out / "jobs").mkdir()
        (self.out / "jobs/key_recovery_7.log").write_text("old job")
        (self.out / "notes.txt").write_text("keep user notes")
        args = arguments(module, "--step", "offline", "--overwrite")
        run_util.prepare_offline(args, self.out, "aumasson", module.OFFLINE)
        for name in [*run_util.ONLINE_FILES, "offline_manifest.json", "dist_search.json", "complexity.json"]:
            self.assertFalse((self.out / name).exists())
        self.assertFalse((self.out / "jobs/key_recovery_7.log").exists())
        self.assertEqual((self.out / "notes.txt").read_text(), "keep user notes")

    def test_resume_reuses_saved_sample_counts_and_detects_tampering(self):
        module = fixture(self.out)
        args = arguments(module, "--resume")
        completed = run_util.prepare_offline(args, self.out, "aumasson", module.OFFLINE)
        self.assertIn("complexity", completed)
        self.assertEqual((args.samples, args.spread_keys, args.spread_ivs), (65536, 64, 512))
        (self.out / "bwd_corr.json").write_text('{"bwd_eps": 0.99}')
        with self.assertRaisesRegex(ValueError, "bwd_corr.json changed"):
            run_util.prepare_offline(args, self.out, "aumasson", module.OFFLINE)

    def test_resume_skips_a_completed_step_after_an_offline_failure(self):
        module = runner("aumasson")
        args = arguments(module, "--demo", "--step", "offline")

        def fail_after_dist(binary, options, out, name):
            if name != "dist_search":
                raise RuntimeError("simulated interruption")
            run_util.save_json(out / "dist_search.json", {"fwd_eps": -0.91})

        with patch.object(run_util, "build", return_value=Path("unused")), \
                patch.object(run_util, "run_offline_program", side_effect=fail_after_dist), \
                contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                module.offline(args, self.out)
        self.assertEqual(run_util.validate_offline(self.out, ready=False)["completed"], ["dist_search"])

        def finish_program(binary, options, out, name):
            self.assertNotEqual(name, "dist_search")
            result = ({"sig_bits": list(range(16)), "pnb_bits": list(range(16, 32))}
                      if name == "pnb_search" else {"bwd_eps": 0.38})
            run_util.save_json(out / (name + ".json"), result)

        def finish_theory(script, options):
            run_util.save_json(self.out / "complexity.json", {"N": 378, "T": 227, "count_value": 1})

        resumed = arguments(module, "--resume", "--step", "offline")
        with patch.object(run_util, "build", return_value=Path("unused")), \
                patch.object(run_util, "run_offline_program", side_effect=finish_program) as programs, \
                patch.object(run_util, "run_python", side_effect=finish_theory), \
                contextlib.redirect_stdout(io.StringIO()):
            module.offline(resumed, self.out)
        self.assertEqual(programs.call_count, 2)
        self.assertIn("complexity", run_util.validate_offline(self.out)["completed"])

    def test_interrupted_online_plan_restores_counts_and_rejects_changes(self):
        module = fixture(self.out)
        run_util.save_json(self.out / "online_plan.json", {
            "version": 1, "offline_sha256": run_util.file_hash(self.out / "offline_manifest.json"),
            "source_sha256": run_util.file_hash(ROOT / "aumasson/online/key_recovery.cpp"),
            "seed": 1, "keys": 7, "jobs": 3,
        })
        args = arguments(module, "--resume")
        run_util.restore_online_plan(self.out, args, "aumasson")
        self.assertEqual((args.keys, args.jobs, args.seed), (7, 3, 1))
        for values in [("--keys", "8"), ("--jobs", "2")]:
            args = arguments(module, "--resume", *values)
            with self.assertRaisesRegex(ValueError, "differs from the interrupted"):
                run_util.restore_online_plan(self.out, args, "aumasson")

    def test_report_rejects_result_files_from_another_run(self):
        fixture(self.out)
        run_util.save_json(self.out / "key_recovery.json", {"keys": 1})
        run_util.record_online(self.out, SimpleNamespace(seed=1, keys=1, jobs=1))
        self.assertEqual(run_util.validate_report(self.out)["keys"], 1)
        run_util.save_json(self.out / "key_recovery.json", {"keys": 2})
        with self.assertRaisesRegex(ValueError, "do not match"):
            run_util.validate_report(self.out)

    def test_zero_key_report_is_rejected_even_with_matching_hash(self):
        fixture(self.out)
        run_util.save_json(self.out / "key_recovery.json", {"keys": 0})
        run_util.record_online(self.out, SimpleNamespace(seed=1, keys=0, jobs=1))
        with self.assertRaisesRegex(ValueError, "positive key count"):
            run_util.validate_report(self.out)

    def test_64_bit_search_sets_fail_before_compilation(self):
        run_util.save_json(self.out / "settings.json", {"key_size_bits": 64})
        run_util.save_json(self.out / "pnb_search.json", {"sig_bits": list(range(64)), "pnb_bits": []})
        with self.assertRaisesRegex(ValueError, "at most 63"):
            run_util.validate_search_sets(self.out, "aumasson")

    def test_failed_json_write_does_not_destroy_previous_file(self):
        path = self.out / "result.json"
        run_util.save_json(path, {"keys": 1})
        with self.assertRaises(ValueError):
            run_util.save_json(path, {"keys": math.nan})
        self.assertEqual(run_util.load_json(path), {"keys": 1})

    def test_job_stage_counts_must_match(self):
        with self.assertRaises(ValueError):
            run_util.add_up({"guesses": [1, 2, 3]}, {"guesses": [4, 5]})

    def test_parallel_jobs_split_keys_without_loss(self):
        binary = self.out / "fake_worker"
        binary.write_text("#!" + sys.executable + "\n" +
                          "import argparse,json\n"
                          "p=argparse.ArgumentParser();p.add_argument('--seed',type=int);"
                          "p.add_argument('--keys',type=int);p.add_argument('--out');a=p.parse_args()\n"
                          "open(a.out,'w').write(json.dumps({'keys':a.keys,'successes':a.keys,'guesses':[a.keys]*3}))\n")
        binary.chmod(0o755)
        with contextlib.redirect_stdout(io.StringIO()):
            result = run_util.run_key_recovery(binary, 7, 3, 1, self.out)
        self.assertEqual(result, {"keys": 7, "successes": 7, "guesses": [7, 7, 7]})
        self.assertFalse(list((self.out / "jobs").glob("*.partial")))

    def test_worker_failure_stops_remaining_processes(self):
        binary = self.out / "failing_worker"
        binary.write_text("#!" + sys.executable + "\nimport sys,time\n"
                          "seed=int(sys.argv[sys.argv.index('--seed')+1])\n"
                          "time.sleep(0.2 if seed == 1 else 30)\n"
                          "sys.exit(3)\n")
        binary.chmod(0o755)
        real_popen = subprocess.Popen
        children = []

        def launch(*args, **kwargs):
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(run_util.subprocess, "Popen", side_effect=launch), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError, "job failed"):
            run_util.run_key_recovery(binary, 2, 2, 1, self.out)
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.poll() is not None for child in children))


@unittest.skipUnless(shutil.which(os.environ.get("CXX", "g++")), "C++20 compiler required")
class EndToEndTests(unittest.TestCase):
    def test_cipher_equivalence(self):
        with tempfile.TemporaryDirectory(prefix="toychacha-cipher-test-") as folder:
            binary = Path(folder) / "test_cipher"
            result = subprocess.run([os.environ.get("CXX", "g++"), "-std=c++20", "-O2", "-Wall", "-Wextra",
                                     str(ROOT / "tests/test_cipher.cpp"), "-o", str(binary)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            subprocess.run([str(binary)], check=True, timeout=30)

    def test_cpp_guards_and_failed_guess_statistics(self):
        with tempfile.TemporaryDirectory(prefix="toychacha-cpp-test-") as folder:
            out = Path(folder)
            header = '''#pragma once
constexpr int KEY_SIZE_BITS = 32;
constexpr double DIST_ROUND = 0, TOTAL_ROUNDS = 0;
constexpr int DIST_STEP = 0, TOTAL_STEP = 0;
using BitPos = attack_util::BitPos;
const std::vector<BitPos> INPUT_DIFF_BITS = {{13, 0}};
const std::vector<BitPos> OUTPUT_MASK_BITS = {{1, 6}};
constexpr u64 N = 1, T = 1;
constexpr u8 COUNT_VALUE = 1;
'''
            for attack in ("aumasson", "maitra"):
                sig = [0]
                id_sig = list(range(8, 16)) if attack == "maitra" else []
                remaining = [bit for bit in range(32) if bit not in sig + id_sig]
                panel = (header + "const std::vector<u16> SIG_BITS = {0};\n"
                         + "const std::vector<u16> PNB_BITS = " + run_util.cpp_list(remaining) + ";\n")
                if attack == "maitra":
                    panel += ("const std::vector<u16> ID_SIG_BITS = " + run_util.cpp_list(id_sig)
                              + ";\nconstexpr int SUITABLE_IV[256] = {};\n")
                (out / "control_panel.hpp").write_text(panel)
                binary = out / attack
                result = subprocess.run([os.environ.get("CXX", "g++"), "-std=c++20", "-O1", "-I" + folder,
                                         str(ROOT / attack / "online/key_recovery.cpp"), "-o", str(binary)],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = subprocess.run([str(binary), "--out", str(out / "counts.json")],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                counters = run_util.load_json(out / "counts.json")
                self.assertEqual(counters["successes"], 0)
                self.assertEqual(counters["wrong_guesses"], counters["guesses"] - 1)
                for option, value in (("--keys", "0"), ("--samples", "0"), ("--seed", "-1")):
                    result = subprocess.run([str(binary), option, value, "--out", str(out / "invalid.json")],
                                            capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertFalse((out / "invalid.json").exists())
            wide = (header.replace("KEY_SIZE_BITS = 32", "KEY_SIZE_BITS = 64")
                    + "const std::vector<u16> SIG_BITS = " + run_util.cpp_list(list(range(64)))
                    + ";\nconst std::vector<u16> PNB_BITS = {};\n")
            (out / "control_panel.hpp").write_text(wide)
            binary = out / "wide"
            result = subprocess.run([os.environ.get("CXX", "g++"), "-std=c++20", "-O1", "-I" + folder,
                                     str(ROOT / "aumasson/online/key_recovery.cpp"), "-o", str(binary)],
                                    capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary), "--out", str(out / "wide.json")],
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("maximum 63", result.stderr)
            self.assertFalse((out / "wide.json").exists())

    def test_all_three_demo_pipelines_and_resume(self):
        # This builds and executes every C++ source, then the actual formula/report scripts.
        for attack in ("aumasson", "maitra", "multi_step"):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory(prefix="toychacha-demo-test-") as folder:
                output = Path(folder)
                env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
                command = [sys.executable, str(ROOT / attack / "run.py"), "--output", folder]
                result = subprocess.run([*command, "--demo"], capture_output=True, text=True, env=env, timeout=120)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                report = (output / "report.md").read_text()
                self.assertIn("model target", report)
                self.assertIn("Demonstration preset", report)
                experiment = run_util.load_json(output / "key_recovery.json")
                self.assertEqual(experiment["keys"], 1)
                self.assertEqual(experiment["successes"], 1)
                before = run_util.file_hash(output / "key_recovery.json")
                result = subprocess.run([*command, "--resume"], capture_output=True, text=True, env=env, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("reusing", result.stdout)
                self.assertEqual(run_util.file_hash(output / "key_recovery.json"), before)


if __name__ == "__main__":
    unittest.main()

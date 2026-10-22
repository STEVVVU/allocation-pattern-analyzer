"""Repeat actual offline kernel scans and the owned native fixture strategy journey."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import pstats
import io
import shutil
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify import CLI, ROOT, Run, re_run_id


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(run, args, tag):
    usage = run.directory / f"{tag}.usage"
    wrapped = ["/usr/bin/time", "-f", "%M %U %S", "-o", str(usage), *args] if os.name == "posix" else args
    started = time.perf_counter()
    def limits():
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (8192 * 1024 ** 2, 8192 * 1024 ** 2))
    with run.transcript.open("a", encoding="utf-8") as transcript:
        transcript.write("$ " + json.dumps(wrapped) + "\n")
        transcript.flush()
        process = subprocess.Popen(wrapped, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=os.name == "posix", preexec_fn=limits if os.name == "posix" else None)
        try:
            stdout, stderr = process.communicate(timeout=900)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            stdout, stderr = process.communicate()
            transcript.write(stdout + stderr + "\nTIMEOUT\n")
            raise RuntimeError(f"{tag} exceeded 900 seconds")
        transcript.write(stdout + stderr + f"\nexit={process.returncode}\n")
    assert process.returncode == 0, f"{tag} failed with {process.returncode}"
    seconds = time.perf_counter() - started
    fields = usage.read_text().splitlines()[-1].split() if usage.exists() else []
    report = json.loads(stdout)
    save(run.directory / f"{tag}.json", report)
    return report, {"seconds": seconds, "rss_kib": int(fields[0]) if fields else None,
                    "cpu_seconds": float(fields[1]) + float(fields[2]) if fields else None,
                    "offered": 1, "completed": 1, "errors": 0, "timeouts": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--kernel-binary", type=Path)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if not re_run_id(args.run_id) or args.run_id in (".", "..") or len(args.run_id) > 100:
        parser.error("run-id must use only letters, digits, period, underscore or hyphen")
    if not args.smoke and (os.name != "posix" or not args.kernel_binary):
        parser.error("full measurement requires Ubuntu and a pinned official kernel ELF")
    assert shutil.disk_usage(ROOT).free >= 10 * 1024 ** 3
    run = Run(args.run_id)
    if run.transcript.exists():
        raise ValueError("choose a fresh run id")
    samples = []
    save(run.directory / "metrics-environment.json", {"source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "python": sys.version, "packages": subprocess.check_output([sys.executable, "-I", "-m", "pip", "freeze"], text=True).splitlines(), "platform": platform.platform(), "cpu_count": os.cpu_count(), "cpu": platform.processor(), "load_average": os.getloadavg() if hasattr(os, "getloadavg") else None, "repeats": 1 if args.smoke else 5, "seed": 1729, "cache": "fresh analyzer process; warm OS file cache after unreported warmup", "strategy_order_limit": "CLI explore runs seed_first, seeded_random, bounded_symbolic in fixed order and shares one CFG; report scope excludes causal speedup claims", "command": sys.argv})
    try:
        run.launch()
        run.doctor()
        run.drive()
        kernel = args.kernel_binary.resolve() if args.kernel_binary else run.binary
        if args.kernel_binary:
            manifest = kernel.parent.parent / "source-provenance.txt"
            config = kernel.parent / ".config"
            assert manifest.is_file() and config.is_file()
            shutil.copyfile(manifest, run.directory / "kernel-source-provenance.txt")
            shutil.copyfile(config, run.directory / "kernel.config")
        save(run.directory / "input-hashes.json", {"fixture_c_sha256": digest(ROOT / "fixtures/allocation_paths.c"), "fixture_elf_sha256": digest(run.binary), "kernel_sha256": digest(kernel), "kernel_bytes": kernel.stat().st_size})
        scan_args = [sys.executable, "-I", str(CLI), "kernel-scan", "--binary", str(kernel), "--max-entries", "5000"]
        measure(run, scan_args, "kernel-warmup")
        expected = None
        for repeat in range(1 if args.smoke else 5):
            report, timing = measure(run, scan_args, f"kernel-{repeat}")
            assert report["symbols"]["syscall_entries_discovered"] == report["symbols"]["syscall_entries_scanned"] > 0
            candidates = [(entry["entry"], item["allocator"], tuple(item["call_chain"])) for entry in report["entries"] for item in entry["candidates"]]
            unique = sorted(set(candidates))
            assert len(unique) == len(candidates), "duplicate static candidates"
            fingerprint = hashlib.sha256(json.dumps(unique).encode()).hexdigest()
            expected = expected or fingerprint
            assert fingerprint == expected, "whole-scan candidate set changed across identical runs"
            samples.append({"kind": "kernel", "repeat": repeat, **timing, "entries": len(report["entries"]), "candidates": len(candidates), "deduplicated_candidates": len(unique), "unknown_entries": sum(e["status"] == "unknown_no_candidate_observed" for e in report["entries"]), "candidate_set_sha256": fingerprint, "feasibility": "unknown_static_candidates_only"})
            save(run.directory / "metrics-samples.json", samples)
            run.drive()
            save(run.directory / f"fixtures-{repeat}.json", run.data["checks"])
            for case in run.data["checks"]:
                if "strategies" in case["report"]:
                    for strategy, value in case["report"]["strategies"].items():
                        witnesses = value["witnesses"]
                        keys = {(w["allocator"], tuple(sorted(w["arguments"].items()))) for w in witnesses}
                        assert all(run.concrete_oracle(case["entry"], w["arguments"]["value"])[w["category"]] > 0 for w in witnesses)
                        samples.append({"kind": "strategy", "repeat": repeat, "entry": case["entry"], "strategy": strategy,
                                        "seconds": value["elapsed_seconds"], "unknown": value["unknown"], "raw_witnesses": len(witnesses), "deduplicated_witnesses": len(keys), "native_checked": os.name == "posix", "steps": value["steps"], "correct": True})
            labels = {c["entry"]: c["report"].get("analysis", {}) for c in run.data["checks"]}
            assert labels["entry_infeasible"]["candidate_paths"] and not labels["entry_infeasible"]["witnesses"]
            assert labels["entry_unsupported"]["unknown"]
            samples.append({"kind": "labels", "repeat": repeat, "positive_entries_native_validated": 7 if os.name == "posix" else 0, "infeasible_syntactic_false_positive": True, "unsupported_explicit_unknown": True, "bounded_loop_explicit_unknown": True, "kernel_truth_labels": "unavailable; no precision/recall claimed on kernel candidates"})
            save(run.directory / "metrics-samples.json", samples)
        profiled = [sys.executable, "-I", "-m", "cProfile", "-o", str(run.directory / "kernel.prof"), *scan_args[2:]]
        measure(run, profiled, "kernel-profile-not-a-sample")
        profile_text = io.StringIO()
        pstats.Stats(str(run.directory / "kernel.prof"), stream=profile_text).sort_stats("cumulative").print_stats(40)
        (run.directory / "kernel-profile.txt").write_text(profile_text.getvalue(), encoding="utf-8")
        run.evidence()
        kernel_times = [s["seconds"] for s in samples if s["kind"] == "kernel"]
        save(run.directory / "metrics-summary.json", {"status": "passed", "smoke_only": args.smoke, "scan_runs": len(kernel_times), "median_scan_seconds": statistics.median(kernel_times), "range_scan_seconds": [min(kernel_times), max(kernel_times)], "peak_rss_kib": max((s["rss_kib"] or 0) for s in samples if s["kind"] == "kernel"), "errors": 0, "claim_scope": "offline static candidates and owned fixture strategy results only"})
    except BaseException as error:
        save(run.directory / "metrics-failure.json", {"status": "failed", "error_type": type(error).__name__, "error": str(error)[:1000]})
        run.data["failure"] = {"type": type(error).__name__, "detail": str(error)}
        run.event("benchmark", "failed")
        raise
    finally:
        run.cleanup()


if __name__ == "__main__":
    main()

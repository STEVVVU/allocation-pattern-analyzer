from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


ROOT = Path(__file__).resolve().parents[4]
SOURCE = ROOT / "fixtures" / "allocation_paths.c"
CLI = ROOT / "allocation_analyzer" / "cli.py"
RUNS = ROOT / ".agents" / "runs"
EXPECTED_ANGR = "9.2.207"


class VerificationError(RuntimeError):
    pass


class Run:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.directory = RUNS / run_id
        self.directory.mkdir(parents=True, exist_ok=True)
        self.transcript = self.directory / "transcript.txt"
        self.evidence_file = self.directory / "evidence.json"
        self.data: dict = {"run_id": run_id, "platform": platform.platform(), "events": [], "cleanup_completed": False}
        self.binary = self.directory / ("allocation_paths.elf" if os.name == "nt" else "allocation_paths")
        self.native = self.directory / ("allocation_paths_native.exe" if os.name == "nt" else "allocation_paths_native")

    def event(self, action: str, result: str, **details) -> None:
        self.data["events"].append({"action": action, "result": result, **details})
        self.evidence_file.write_text(json.dumps(self.data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def command(self, args: list[str], timeout: int = 600, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        self.transcript.parent.mkdir(parents=True, exist_ok=True)
        with self.transcript.open("a", encoding="utf-8") as stream:
            stream.write("$ " + json.dumps(args) + "\n")
            stream.flush()
            try:
                result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout, check=False)
            except subprocess.TimeoutExpired as exc:
                stream.write(f"TIMEOUT after {timeout} seconds\n")
                if exc.stdout:
                    stream.write(exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(errors="replace"))
                if exc.stderr:
                    stream.write(exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(errors="replace"))
                raise VerificationError(f"command exceeded {timeout} seconds") from exc
            stream.write(result.stdout)
            stream.write(result.stderr)
            stream.write(f"exit={result.returncode}\n")
        if result.returncode != 0:
            raise VerificationError(f"command exited {result.returncode}: {args[0]}")
        return result

    def _compiler(self) -> str:
        if os.name == "nt":
            default = Path(r"C:\Users\steve\.codex\tools\coursework-llvm\clang+llvm-23.1.4-x86_64-pc-windows-msvc\bin\clang.exe")
            compiler = Path(os.environ.get("CLANG", str(default)))
            if not compiler.is_file():
                raise VerificationError(f"clang was not found at {compiler}")
            return str(compiler)
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if not compiler:
            raise VerificationError("a C compiler was not found")
        return compiler

    def launch(self) -> None:
        compiler = self._compiler()
        if os.name == "nt":
            args = [compiler, "-target", "x86_64-unknown-linux-gnu", "-nostdlib", "-fuse-ld=lld",
                    "-Wl,-e,entry_direct", "-Wl,--build-id=none", "-fno-pie", "-Wl,-no-pie", "-O0",
                    str(SOURCE), "-o", str(self.binary)]
        else:
            args = [compiler, "-nostdlib", "-Wl,-e,entry_direct", "-Wl,--build-id=none", "-fno-pie", "-no-pie",
                    "-O0", str(SOURCE), "-o", str(self.binary)]
        self.command(args)
        if os.name != "nt":
            self.command([compiler, "-DNATIVE_RUNNER", "-O0", "-fno-pie", "-no-pie", str(SOURCE), "-o", str(self.native)])
        self.data["binary"] = str(self.binary.relative_to(ROOT))
        self.data["native_runner"] = str(self.native.relative_to(ROOT)) if os.name != "nt" else None
        self.event("launch", "ready", binary_bytes=self.binary.stat().st_size, native_runner=os.name != "nt")

    def doctor(self) -> None:
        code = (
            "import angr, json, pathlib, sys; "
            f"root=pathlib.Path({str(ROOT)!r}); "
            "loaded=pathlib.Path(angr.__file__).resolve(); "
            "assert angr.__version__ == " + repr(EXPECTED_ANGR) + "; "
            "assert root not in loaded.parents; "
            "print(json.dumps({'angr': angr.__version__, 'module': str(loaded), 'python': sys.version.split()[0]}))"
        )
        result = self.command([sys.executable, "-I", "-c", code], timeout=30)
        details = json.loads(result.stdout)
        if not self.binary.is_file() or self.binary.read_bytes()[:4] != b"\x7fELF":
            raise VerificationError("the fixture artifact is missing or not ELF")
        self.event("doctor", "ready", **details, elf_bytes=self.binary.stat().st_size)

    def config(self, entry: str, *, seeds: list[list[int]] | None = None,
               inputs: list[dict] | None = None, max_steps: int = 512) -> Path:
        path = self.directory / f"{entry}.json"
        data = {
            "binary": self.binary.name,
            "entry": entry,
            "inputs": inputs if inputs is not None else [{"name": "value", "bits": 32}],
            "allocators": {"slab_alloc": "slab", "mapping_alloc": "mapping"},
            "max_steps": max_steps,
            "max_states": 256,
            "timeout_seconds": 30,
            "seeds": seeds if seeds is not None else [[0], [1]],
            "random_seed": 1729,
            "random_trials": 1024,
        }
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def analyze(self, mode: str, entry: str, *, seeds: list[list[int]] | None = None,
                inputs: list[dict] | None = None, max_steps: int = 512) -> dict:
        config = self.config(entry, seeds=seeds, inputs=inputs, max_steps=max_steps)
        result = self.command([sys.executable, str(CLI), mode, "--config", str(config)], timeout=180)
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise VerificationError(f"analyzer did not return JSON for {entry}") from exc

    def validate_native(self, entry: str, witness: dict) -> dict:
        if os.name == "nt":
            witness["native_validation"] = "not_run_windows_cannot_execute_elf"
            return {"result": "not_run", "reason": "Windows cannot execute the Linux ELF fixture"}
        mode = {"entry_direct": "direct", "entry_wrapper": "wrapper", "entry_conditional": "conditional",
                "entry_infeasible": "infeasible", "entry_loop": "loop", "entry_indirect": "indirect",
                "entry_multi_route": "multi-route", "entry_correlated": "correlated"}.get(entry)
        if mode is None:
            witness["native_validation"] = "not_run_unsupported_fixture"
            return {"result": "not_run", "reason": "unsupported indirect-call fixture is never executed"}
        arguments = witness["arguments"]
        values = ([arguments["left"], arguments["right"]] if entry == "entry_correlated"
                  else [arguments["value"]])
        outcome, expected = self.native_oracle_check(entry, values)
        if outcome[witness["category"]] < 1:
            raise VerificationError(
                f"native fixture did not reach {witness['allocator']} for {entry}{tuple(values)}: "
                f"expected {expected}, observed {outcome}"
            )
        witness["native_validation"] = "passed"
        return {"result": "passed", "entry": entry, "arguments": arguments, "allocator": witness["allocator"],
                "counters": outcome, "oracle": expected}

    def native_oracle_check(self, entry: str, values: list[int]) -> tuple[dict[str, int], dict[str, int]]:
        mode = {"entry_direct": "direct", "entry_wrapper": "wrapper", "entry_conditional": "conditional",
                "entry_infeasible": "infeasible", "entry_loop": "loop", "entry_indirect": "indirect",
                "entry_multi_route": "multi-route", "entry_correlated": "correlated"}[entry]
        result = self.command([str(self.native), mode, *(str(value) for value in values)], timeout=5)
        outcome = json.loads(result.stdout)
        expected = self.concrete_oracle(entry, *values)
        if outcome != expected:
            raise VerificationError(
                f"native fixture disagrees with the independent oracle for {entry}{tuple(values)}: "
                f"expected {expected}, observed {outcome}"
            )
        return outcome, expected

    @staticmethod
    def concrete_oracle(entry: str, *values: int) -> dict[str, int]:
        """Independent expected counter model for the small owned C fixture."""
        if entry == "entry_correlated":
            return {"slab": 0, "mapping": int(tuple(values) in {(7, 11), (13, 17)})}
        value = values[0]
        slab = mapping = 0
        if entry == "entry_direct":
            slab = int(value == 7)
        elif entry == "entry_wrapper":
            mapping = int(value == 0x2026)
        elif entry == "entry_conditional":
            mapping = int(value == 0xC0FFEE11)
        elif entry == "entry_infeasible":
            # The two conditions require one uint32 value to be both equal
            # and unequal to 0x12345678.
            slab = 0
        elif entry == "entry_loop":
            slab = int((value & 15) > 7)
        elif entry == "entry_indirect":
            slab, mapping = (1, 0) if value & 1 else (0, 1)
        elif entry == "entry_multi_route":
            mapping = int(value == 0xC0FFEE11)
        else:
            raise VerificationError(f"no safe native oracle is defined for {entry}")
        return {"slab": slab, "mapping": mapping}

    def drive(self) -> None:
        checks: list[dict] = []
        for entry, expected, mode in (
            ("entry_direct", 7, "analyze"),
            ("entry_wrapper", 0x2026, "analyze"),
            ("entry_multi_route", 0xC0FFEE11, "analyze"),
            ("entry_correlated", None, "analyze"),
            ("entry_conditional", 0xC0FFEE11, "explore"),
            ("entry_loop", 8, "explore"),
            ("entry_indirect", 1, "explore"),
        ):
            input_specs = ([{"name": "left", "bits": 32}, {"name": "right", "bits": 32}]
                           if entry == "entry_correlated" else None)
            seed_values = ([[0, 0], [0, 1]] if entry == "entry_correlated"
                           else [[8]] if entry == "entry_loop"
                           else [[0], [1]] if entry == "entry_indirect" else None)
            report = self.analyze(mode, entry, seeds=seed_values, inputs=input_specs)
            if mode == "analyze":
                witnesses = report["analysis"]["witnesses"]
            else:
                witnesses = [witness for strategy in report["strategies"].values() for witness in strategy["witnesses"]]
            if entry == "entry_correlated":
                matching = [witness for witness in witnesses
                            if self.concrete_oracle(entry, witness["arguments"]["left"],
                                                    witness["arguments"]["right"])["mapping"] == 1]
            else:
                matching = [witness for witness in witnesses if witness["arguments"]["value"] == expected]
            if not matching:
                raise VerificationError(f"{entry} did not produce a witness satisfying the independent oracle")
            if entry == "entry_multi_route":
                candidate = report["analysis"]["candidate_paths"][0]["call_chain"]
                witness = matching[0]
                if candidate != ["entry_multi_route", "mapping_alloc"]:
                    raise VerificationError(f"multi-route fixture did not expose the short syntactic route: {candidate}")
                if witness["call_chain"] != ["entry_multi_route", "multi_outer", "multi_inner", "mapping_alloc"]:
                    raise VerificationError(f"witness chain did not follow executed blocks: {witness['call_chain']}")
                if not witness["call_chain_complete"]:
                    raise VerificationError("multi-route witness trace was not complete")
            native = [self.validate_native(entry, witness) for witness in witnesses]
            checks.append({"entry": entry, "expected_input": expected, "report": report, "native": native})
        bounded_loop = self.analyze("analyze", "entry_loop", seeds=[], max_steps=1)
        if "step_limit" not in bounded_loop["analysis"]["unknown"]:
            raise VerificationError("one-block loop control did not report its bounded step limit")
        loop_native, loop_oracle = self.native_oracle_check("entry_loop", [8]) if os.name != "nt" else (None, None)
        checks.append({"entry": "entry_loop_budget", "report": bounded_loop,
                       "native": {"result": "passed", "counters": loop_native, "oracle": loop_oracle}
                       if os.name != "nt" else "not_run_windows_cannot_execute_elf"})
        infeasible = self.analyze("analyze", "entry_infeasible")
        if infeasible["analysis"]["status"] != "no_witness_observed" or not infeasible["analysis"]["candidate_paths"]:
            raise VerificationError("infeasible fixture did not produce a syntactic candidate without a witness")
        checks.append({"entry": "entry_infeasible", "report": infeasible,
                       "native": self._validate_no_allocation("infeasible", 305419896)
                       if os.name != "nt" else "not_run_windows_cannot_execute_elf"})
        unsupported = self.analyze("analyze", "entry_unsupported")
        if not unsupported["analysis"]["unknown"]:
            raise VerificationError("unsupported indirect call was not reported as unresolved")
        checks.append({"entry": "entry_unsupported", "report": unsupported, "native": "intentionally_not_executed"})
        exploration = next(item["report"] for item in checks if item["entry"] == "entry_conditional")
        strategies = exploration["strategies"]
        if strategies["seeded_random"]["steps"] != 512 or strategies["seeded_random"]["witnesses"]:
            raise VerificationError("equal-budget random control did not spend its block budget without the target witness")
        if not strategies["seed_first"]["witnesses"] or not strategies["bounded_symbolic"]["witnesses"]:
            raise VerificationError("symbolic strategies did not find the allocation-reaching branch")
        metrics = {name: {"steps": value["steps"], "unique_blocks": value["unique_blocks"],
                          "solver_calls": value["solver_calls"],
                          "witnesses": len(value["witnesses"]), "unknown": value["unknown"]}
                   for name, value in strategies.items()}
        self.data["checks"] = checks
        self.data["comparison"] = metrics
        self.event("drive", "passed", checks=len(checks), native_witnesses=sum(
            sum(result.get("result") == "passed" for result in item.get("native", []) if isinstance(result, dict))
            for item in checks
            if isinstance(item.get("native"), list)
        ), comparison=metrics)

    def _validate_no_allocation(self, mode: str, value: int) -> dict:
        outcome, expected = self.native_oracle_check("entry_infeasible", [value])
        return {"result": "passed", "entry": mode, "argument": value, "counters": outcome, "oracle": expected}

    def evidence(self) -> None:
        if not self.data.get("checks") or not self.transcript.is_file():
            raise VerificationError("the analyzer journey has no checks or transcript")
        if os.name != "nt":
            validations = [result for check in self.data["checks"] for result in check.get("native", [])
                           if isinstance(result, dict) and result.get("result") == "passed"]
            required = {"entry_direct", "entry_wrapper", "entry_multi_route", "entry_correlated",
                        "entry_conditional", "entry_loop", "entry_indirect"}
            covered = {check["entry"] for check in self.data["checks"]
                       if isinstance(check.get("native"), list)
                       and any(result.get("result") == "passed" for result in check["native"]
                               if isinstance(result, dict))}
            if not required <= covered:
                raise VerificationError(f"native witness proof is missing cases: {sorted(required - covered)}")
            if len(validations) < len(required):
                raise VerificationError("native evidence did not validate one witness for every required entry")
            infeasible = next(check for check in self.data["checks"] if check["entry"] == "entry_infeasible")
            if infeasible["native"].get("result") != "passed" or infeasible["native"].get("counters") != {
                "slab": 0, "mapping": 0,
            }:
                raise VerificationError("infeasible native oracle case did not produce zero allocation counters")
            bounded_loop = next(check for check in self.data["checks"] if check["entry"] == "entry_loop_budget")
            if "step_limit" not in bounded_loop["report"]["analysis"]["unknown"]:
                raise VerificationError("bounded loop evidence is missing its explicit step-limit outcome")
        self.event("evidence", "passed", transcript=self.transcript.name, checks=len(self.data["checks"]))

    def cleanup(self) -> None:
        removed = []
        for path in (self.binary, self.native):
            if path.exists():
                path.unlink()
                removed.append(path.name)
        self.data["cleanup_completed"] = True
        self.data["removed_scratch"] = removed
        self.event("cleanup", "passed", evidence_preserved=self.evidence_file.is_file(), removed=removed)
        if not self.evidence_file.is_file() or not self.transcript.is_file():
            raise VerificationError("cleanup removed required evidence")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("Launch", "Doctor", "Drive", "Evidence", "Cleanup", "All"), default="All")
    parser.add_argument("--run-id", default=datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--inject-failure", action="store_true")
    args = parser.parse_args()
    if not re_run_id(args.run_id):
        parser.error("run-id must contain only letters, numbers, period, underscore, or hyphen")
    run = Run(args.run_id)
    phases = ["Launch", "Doctor", "Drive", "Evidence", "Cleanup"] if args.phase == "All" else [args.phase]
    try:
        for phase in phases:
            if phase == "Launch":
                run.launch()
            elif phase == "Doctor":
                run.doctor()
            elif phase == "Drive":
                run.drive()
            elif phase == "Evidence":
                run.evidence()
                if args.inject_failure:
                    raise VerificationError("injected failure after the native journey")
            elif phase == "Cleanup":
                run.cleanup()
        print(run.evidence_file)
        return 0
    except Exception as exc:
        run.data["failure"] = {"type": type(exc).__name__, "detail": str(exc)}
        run.event("failure", "recorded")
        if "Cleanup" in phases:
            try:
                run.cleanup()
            except OSError as cleanup_error:
                run.data["cleanup_error"] = str(cleanup_error)
                run.event("cleanup", "failed")
        print(json.dumps({"error": str(exc), "evidence": str(run.evidence_file)}, sort_keys=True), file=sys.stderr)
        return 1


def re_run_id(value: str) -> bool:
    return bool(value) and all(character.isalnum() or character in "._-" for character in value)


if __name__ == "__main__":
    raise SystemExit(main())

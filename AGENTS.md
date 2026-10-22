# Allocation Pattern Analyzer

This checkout preserves the upstream angr project at the released `v9.2.207` tag. Keep project additions in `allocation_analyzer/`, `fixtures/`, `docs/`, `reports/`, `store/reports/`, `archive/upstream-github-workflows/`, `.agents/`, `.github/workflows/`, plus the root `README.md` and `requirements-ci.txt`. Do not edit upstream angr source, its license notices, or the preserved copy of its original README.

Use the isolated environment at `C:/Users/steve/.codex/tools/coursework-allocation`. Never install packages into a shared Python environment. Import angr from the exact pinned installed release. Do not import the vendored checkout as an unbuilt package.

The analyzer accepts trusted ELF x86-64 inputs only. Bound symbolic exploration, subprocesses, and output. Report unknown or incomplete cases explicitly. Never interpret timeout, unsupported behavior, or ambiguous symbolic addresses as proof of absence.

Fixtures must be generated from owned harmless C sources. Native execution is limited to those fixtures. Do not probe kernels, hosts, cloud services, or real targets. Do not use exploit payloads, memory dumps, or privileged operations.

Run the maintained driver with `python -I .agents/skills/verify-allocation-pattern-analyzer/scripts/verify.py --phase All`. Preserve `.agents/runs/` evidence after cleanup.

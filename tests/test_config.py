from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("allocation_cli", ROOT / "allocation_analyzer" / "cli.py")
CLI = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CLI
SPEC.loader.exec_module(CLI)


class ConfigValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "fixture.elf").write_bytes(b"\x7fELF\x02\x01\x01" + bytes(56))
        self.data = {
            "binary": "fixture.elf",
            "entry": "entry_direct",
            "inputs": [{"name": "value", "bits": 32}],
            "allocators": {"slab_alloc": "slab"},
            "max_steps": 100,
            "max_states": 32,
            "timeout_seconds": 5,
            "seeds": [[0]],
            "random_seed": 17,
            "random_trials": 10,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def load(self):
        filename = self.root / "config.json"
        filename.write_text(json.dumps(self.data), encoding="utf-8")
        return CLI.load_config(filename)

    def test_resolves_binary_relative_to_config(self):
        config = self.load()
        self.assertEqual(config.binary, (self.root / "fixture.elf").resolve())

    def test_rejects_shell_or_expression_symbols(self):
        self.data["entry"] = "entry;__import__('os')"
        with self.assertRaisesRegex(CLI.InputError, "plain C symbol"):
            self.load()

    def test_rejects_wrong_argument_width_and_seed_overflow(self):
        self.data["inputs"][0]["bits"] = 24
        with self.assertRaisesRegex(CLI.InputError, "bits must be"):
            self.load()
        self.data["inputs"][0]["bits"] = 8
        self.data["seeds"] = [[256]]
        with self.assertRaisesRegex(CLI.InputError, "seeds\[0\]\[0\]"):
            self.load()

    def test_rejects_malformed_elf_and_unknown_keys(self):
        self.data["binary"] = "config.json"
        with self.assertRaisesRegex(CLI.InputError, "ELF file"):
            self.load()
        self.data["binary"] = "fixture.elf"
        self.data["command"] = "must not execute"
        with self.assertRaisesRegex(CLI.InputError, "exactly"):
            self.load()

    def test_rejects_non_string_allocator_category(self):
        self.data["allocators"]["slab_alloc"] = []
        with self.assertRaisesRegex(CLI.InputError, "category must"):
            self.load()


if __name__ == "__main__":
    unittest.main()

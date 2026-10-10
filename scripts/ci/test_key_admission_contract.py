"""Exercise schema and coverage failures through the repository checker."""

from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest

import validate_contracts as checker


FIXTURE = "schemas/dsse/v1/key-admission-vectors.json"


class KeyAdmissionContractTests(unittest.TestCase):
    def setUp(self):
        self.original = checker.load(checker.ROOT / FIXTURE)

    def check_copy(self, data):
        # Use a temporary admission fixture with the root command
        # inventory and schema checks.
        with tempfile.TemporaryDirectory(prefix="key-admission-") as directory:
            path = Path(directory) / "vectors.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with redirect_stdout(io.StringIO()):
                checker.main(key_admission_path=path)

    def test_exact_corpus(self):
        self.check_copy(self.original)

    def test_mutations(self):
        mutations = {}
        for name in ("extra-property", "malformed-hex", "missing-field", "unknown-result",
                     "duplicate-name", "missing-torsion", "missing-y-overflow", "changed-class"):
            data = deepcopy(self.original)
            row = data["vectors"][0]
            if name == "extra-property":
                row["extra"] = True
            elif name == "malformed-hex":
                row["public_key_hex"] = "0G"
            elif name == "missing-field":
                del row["recipe"]
            elif name == "unknown-result":
                row["expected"] = "unknown"
            elif name == "duplicate-name":
                data["vectors"][1]["name"] = row["name"]
            elif name == "missing-torsion":
                data["vectors"] = [v for v in data["vectors"] if v["name"] != "torsion-1"]
            elif name == "missing-y-overflow":
                data["vectors"] = [v for v in data["vectors"] if v["name"] != "noncanonical-y-0-sign-0"]
            elif name == "changed-class":
                row["expected"] = "accept"
            mutations[name] = data
        for name, data in mutations.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check_copy(data)


if __name__ == "__main__":
    unittest.main()

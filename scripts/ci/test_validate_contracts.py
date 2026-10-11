"""Check every package vector's decoded manifest, regardless of loader outcome."""
import copy
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch
import validate_contracts as checker

SCHEMA = "schemas/extension/v1alpha1/manifest.schema.json"
CORPUS = "schemas/extension/v1alpha1/package-loader-vectors.json"


class PackageManifestTests(unittest.TestCase):
    def test_package_manifest_pair_registered(self):
        self.assertIn((SCHEMA, CORPUS), checker.CONTRACTS)

    def test_package_manifest_instances(self):
        data = checker.load(checker.ROOT / CORPUS)
        self.assertEqual(list(checker.instances(SCHEMA, CORPUS, data)), [
            (case["name"], case["decoded_document"], True) for case in data["cases"]
        ])

    def test_invalid_package_manifest_rejected(self):
        original_load = checker.load
        corpus = original_load(checker.ROOT / CORPUS)
        for index, case in enumerate(corpus["cases"]):
            with self.subTest(case=case["name"]):
                changed = copy.deepcopy(corpus)
                changed["cases"][index]["decoded_document"] = {"unexpected": True}
                def patched_load(path):
                    return changed if path == checker.ROOT / CORPUS else original_load(path)
                with patch.object(checker, "load", side_effect=patched_load):
                    with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
                        checker.main()

    def test_unmodified_inventory(self):
        with redirect_stdout(io.StringIO()) as output:
            checker.main()
        self.assertIn("Contract validation passed", output.getvalue())
        data = checker.load(checker.ROOT / "schemas/extension/v1alpha1/fixtures.json")
        self.assertEqual(list(checker.instances(SCHEMA, "schemas/extension/v1alpha1/fixtures.json", data)), [
            (case["name"], case["manifest"], case["schema_valid"]) for case in data["cases"]
        ])

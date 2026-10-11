"""Check every package vector's decoded manifest, regardless of loader outcome."""
import copy
import io
import unittest
from pathlib import PureWindowsPath
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

    def test_windows_inventory_paths_use_posix_separators(self):
        path_class = type(checker.ROOT)
        original = path_class.relative_to
        def windows_relative(path, *args, **kwargs):
            relative = original(path, *args, **kwargs)
            return PureWindowsPath(*relative.parts)
        # Exercise all discovered schema, fixture and referenced CEL paths.
        with patch.object(path_class, 'relative_to', windows_relative):
            with redirect_stdout(io.StringIO()) as output:
                checker.main()
        self.assertIn('Contract validation passed', output.getvalue())

    def test_unmodified_inventory(self):
        with redirect_stdout(io.StringIO()) as output:
            checker.main()
        self.assertIn("Contract validation passed", output.getvalue())
        data = checker.load(checker.ROOT / "schemas/extension/v1alpha1/fixtures.json")
        self.assertEqual(list(checker.instances(SCHEMA, "schemas/extension/v1alpha1/fixtures.json", data)), [
            (case["name"], case["manifest"], case["schema_valid"]) for case in data["cases"]
        ])


class BuildContractTests(unittest.TestCase):
    def test_build_examples_registered(self):
        self.assertIn('schemas/build/v1', checker.DIRECTORIES)
        for name in ('example.json', 'example-image.json'):
            self.assertIn(('schemas/build/v1/build-record.schema.json', 'schemas/build/v1/' + name), checker.CONTRACTS)

    def test_invalid_build_examples_rejected(self):
        original_load = checker.load
        for name in ('example.json', 'example-image.json'):
            path = checker.ROOT / 'schemas/build/v1' / name
            data = original_load(path)
            data['identity']['commit'] = 'invalid'
            with self.subTest(name=name), patch.object(checker, 'load', side_effect=lambda p: data if p == path else original_load(p)):
                with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
                    checker.main()

    def test_inventory_example_registered(self):
        self.assertIn(('schemas/build/v1/inventory.schema.json',
                       'schemas/build/v1/inventory-example.json'), checker.CONTRACTS)

    def test_invalid_inventory_example_rejected(self):
        original_load = checker.load
        path = checker.ROOT / 'schemas/build/v1/inventory-example.json'
        data = original_load(path)
        data['records'][0]['artifacts'][0]['format'] = 'shell'
        with patch.object(checker, 'load', side_effect=lambda p: data if p == path else original_load(p)):
            with self.assertRaises(ValueError), redirect_stdout(io.StringIO()):
                checker.main()

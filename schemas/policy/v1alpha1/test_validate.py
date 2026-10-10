"""Regression checks for the schema-validation command."""

from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


class ValidatorCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ricevanta-validator-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = Path(__file__).resolve().parents[3]
        self.directory = self.root / 'schemas/policy/v1alpha1'
        shutil.copytree(source / 'schemas/policy/v1alpha1', self.directory)
        self.spec = self.root / 'docs/specs/policy-envelope.md'
        self.spec.parent.mkdir(parents=True)
        shutil.copy(source / 'docs/specs/policy-envelope.md', self.spec)

    def run_validator(self):
        return subprocess.run([sys.executable, str(self.directory / 'validate.py')],
                              capture_output=True, text=True, check=False)

    def test_valid_contracts_and_examples_pass(self):
        result = self.run_validator()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_required_schema_fails(self):
        for filename in ('policy.schema.json', 'exception.schema.json'):
            with self.subTest(filename=filename):
                path = self.directory / filename
                content = path.read_text()
                path.unlink()
                result = self.run_validator()
                path.write_text(content)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'Missing required schema: {filename}', result.stderr)

    def test_unknown_resource_kind_fails(self):
        self.spec.write_text(self.spec.read_text().replace('kind: Exception', 'kind: Exeption'))
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unknown resource kind: Exeption', result.stderr)

    def test_resource_without_kind_fails(self):
        self.spec.write_text(self.spec.read_text().replace('kind: Exception\n', ''))
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Resource example requires apiVersion and kind', result.stderr)

    def test_each_resource_kind_requires_an_example(self):
        original = self.spec.read_text()
        for kind in ('Policy', 'Exception'):
            with self.subTest(kind=kind):
                self.spec.write_text(re.sub(rf'```yaml\napiVersion:[^`]*?kind: {kind}[^`]*?\n```',
                                            '', original))
                result = self.run_validator()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(f'No {kind} example validated', result.stderr)

    def test_invalid_exception_expiry_example_fails(self):
        self.spec.write_text(self.spec.read_text().replace('2027-01-31T00:00:00Z', 'not-a-date'))
        result = self.run_validator()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Exception example: 'not-a-date' is not a 'date-time'", result.stderr)


if __name__ == '__main__':
    unittest.main()

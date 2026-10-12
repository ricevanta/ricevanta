"""Exercise the build's master loading without importing its renderer."""
import ast
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DTDForbidden


ROOT = Path(__file__).resolve().parents[1]
MASTERS = ('ricevanta-symbol-master.svg', 'ricevanta-wordmark-master.svg',
           'ricevanta-tagline-master.svg')


def master_loading_code():
    tree = ast.parse((ROOT / 'scripts/build.py').read_bytes())
    statements = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == 'MICRO_SCALE'
                for target in statement.targets):
            break
        # Pillow belongs to rendering, not master loading.
        if isinstance(statement, ast.ImportFrom) and statement.module == 'PIL':
            continue
        statements.append(statement)
    else:
        raise AssertionError('master-loading boundary is missing')
    return compile(ast.Module(body=statements, type_ignores=[]),
                   str(ROOT / 'scripts/build.py'), 'exec')


class BuildXMLTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ricevanta-brand-xml-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'source').mkdir()
        for name in MASTERS:
            (self.root / 'source' / name).write_bytes((ROOT / 'source' / name).read_bytes())

    def load(self):
        namespace = {'__file__': str(self.root / 'scripts/build.py')}
        exec(master_loading_code(), namespace)
        return namespace

    def test_all_actual_master_trees_and_assets_are_unchanged(self):
        files = [p for folder in ('source', 'dist') for p in (ROOT / folder).rglob('*') if p.is_file()]
        before = {p: hashlib.sha256(p.read_bytes()).digest() for p in files}
        baseline = [ET.tostring(ET.fromstring((ROOT / 'source' / name).read_bytes())) for name in MASTERS]
        parsed = []
        original = DefusedET.parse

        def capture(*args, **kwargs):
            tree = original(*args, **kwargs)
            parsed.append(ET.tostring(tree.getroot()))
            return tree

        with patch.object(DefusedET, 'parse', side_effect=capture) as parser:
            loaded = self.load()
        self.assertEqual(parsed, baseline)
        self.assertEqual(parser.call_count, 3)
        for call in parser.call_args_list:
            self.assertEqual(call.kwargs, dict(forbid_dtd=True, forbid_entities=True, forbid_external=True))
        self.assertEqual(ET.tostring(loaded['root']), baseline[0])
        self.assertEqual(before, {p: hashlib.sha256(p.read_bytes()).digest() for p in files})

    def test_each_master_rejects_dtd_and_entity_declarations_before_resolution(self):
        declarations = (
            b'<!DOCTYPE svg>',
            b'<!DOCTYPE svg [<!ENTITY forbidden "synthetic">]>',
            b'<!DOCTYPE svg [<!ENTITY forbidden SYSTEM "file:///unrelated-private-file">]>',
            b'<!DOCTYPE svg [<!ENTITY forbidden SYSTEM "https://example.invalid/entity">]>',
        )
        original_open = open
        allowed = {self.root / 'source' / name for name in MASTERS}

        def guarded_open(path, *args, **kwargs):
            if Path(path) not in allowed:
                raise AssertionError('unrelated file resolution')
            return original_open(path, *args, **kwargs)

        for name in MASTERS:
            path = self.root / 'source' / name
            original = path.read_bytes()
            for declaration in declarations:
                with self.subTest(master=name, declaration=declaration.split(b' ')[1]):
                    path.write_bytes(declaration + original)
                    with patch('builtins.open', side_effect=guarded_open), \
                         patch('socket.create_connection', side_effect=AssertionError('network resolution')), \
                         patch('urllib.request.urlopen', side_effect=AssertionError('network resolution')), \
                         self.assertRaises(DTDForbidden):
                        self.load()
                    path.write_bytes(original)


if __name__ == '__main__':
    unittest.main()

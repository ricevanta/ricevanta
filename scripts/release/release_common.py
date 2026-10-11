"""Strict public contracts and portable file admission for release tools."""
import json
from pathlib import Path
import re
import stat

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CONTROL_LIMIT = 16 * 1048576
IDENTITY_LIMIT = 65536
BUFFER = 65536
NAME = r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,239}'


def fail(label, reason):
    raise ValueError(f'{label}: {reason}')


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail(key, 'duplicate JSON key')
        value[key] = item
    return value


def decode(data, label):
    try:
        text = data.decode('utf-8')
        if text.startswith('\ufeff'):
            fail(label, 'UTF-8 BOM forbidden')
        value = json.loads(text, object_pairs_hook=unique_object,
                           parse_constant=lambda number: fail(label, 'non-JSON number'))
        def unicode_strings(item):
            if isinstance(item, str):
                item.encode('utf-8', errors='strict')
            elif isinstance(item, dict):
                for key, val in item.items():
                    unicode_strings(key)
                    unicode_strings(val)
            elif isinstance(item, list):
                for val in item:
                    unicode_strings(val)
        unicode_strings(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as error:
        fail(label, str(error))


def basename(name, label):
    if not isinstance(name, str) or not re.fullmatch(NAME, name) or name.endswith('.'):
        fail(label, f'invalid basename {name!r}')
    if re.fullmatch(r'(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])', name.split('.')[0]):
        fail(label, f'reserved basename {name}')



def parents(path):
    """Check lexical paths before resolve can conceal a link or reparse point."""
    path = Path(path).absolute()
    for part in reversed((path, *path.parents)):
        if not part.exists() and not part.is_symlink():
            continue
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            fail(str(part), 'linked or reparse path forbidden')
        if part != path and not stat.S_ISDIR(info.st_mode):
            fail(str(part), 'parent must be directory')
    return path


def regular(path):
    basename(Path(path).name, str(path))
    path = parents(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        fail(path.name, 'expected regular file without links')
    return path


def bounded_read(path, limit):
    path = regular(path)
    if path.stat().st_size > limit:
        fail(path.name, 'byte limit exceeded')
    chunks = bytearray()
    with path.open('rb') as stream:
        while len(chunks) < limit:
            chunk = stream.read(min(BUFFER, limit - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if stream.read(1):
            fail(path.name, 'byte limit exceeded')
    return bytes(chunks)


def load(path, limit=CONTROL_LIMIT):
    return decode(bounded_read(path, limit), str(path))


def validate(validator, value, label):
    error = next(validator.iter_errors(value), None)
    if error:
        location = '/'.join(map(str, error.absolute_path))
        fail(label, f'{location}: {error.message}')


SCHEMA = load(ROOT / 'schemas/build/v1/build-record.schema.json')
IDENTITY_VALIDATOR = Draft202012Validator({'$ref': '#/$defs/identity', '$defs': SCHEMA['$defs']})
RECORD_VALIDATOR = Draft202012Validator(SCHEMA)
INVENTORY_VALIDATOR = Draft202012Validator(load(ROOT / 'schemas/build/v1/inventory.schema.json'))


def check_identity(value, expected, label):
    validate(IDENTITY_VALIDATOR, value, label)
    if type(value['sourceEpoch']) is not int:
        fail(label, 'sourceEpoch must be integer')
    if value['channel'] != 'prerelease' and value['version'].split('+g')[-1] != value['commit']:
        fail(label, 'version commit differs from commit')
    if expected is not None:
        for field in ('version', 'commit', 'channel', 'sourceEpoch'):
            if value[field] != expected[field]:
                fail(label, f'{field} differs from expected identity')


def member_name(name, label):
    if not isinstance(name, str) or len(name) > 1024:
        fail(label, 'invalid archive path length')
    parts = name.split('/')
    if len(parts) > 32:
        fail(label, 'archive path depth exceeded')
    for part in parts:
        basename(part, label)
    return name

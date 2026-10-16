"""Digest the exact console artifact tree, including hidden files (CI hardening section 8)."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


def digest(root):
    root = Path(root)
    if not stat.S_ISDIR(root.lstat().st_mode): raise ValueError('dist root must be a real directory')
    records = []
    def walk(directory):
        for path in directory.iterdir():
            if any(ord(c) < 32 or ord(c) > 126 or c == '\\' for c in path.name):
                raise ValueError('dist path components must be printable ASCII without backslashes')
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode): walk(path)
            elif stat.S_ISREG(mode):
                relative = path.relative_to(root).as_posix().encode('ascii')
                with path.open('rb') as source: content = hashlib.file_digest(source, 'sha256').hexdigest()
                records.append((relative, relative + b'\0' + content.encode('ascii') + b'\n'))
            else: raise ValueError('dist contains a symbolic link or special file')
    walk(root)
    return 'sha256:' + hashlib.sha256(b''.join(record for _, record in sorted(records))).hexdigest()


def check(root, expect_env=None):
    actual = digest(root)
    if expect_env:
        expected = os.environ.get(expect_env, '')
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', expected): raise ValueError('malformed ' + expect_env)
        if actual != expected: raise ValueError('dist digest differs from ' + expect_env)
    return actual


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--expect-env')
    args = parser.parse_args()
    try: print(check(args.root, args.expect_env))
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__': sys.exit(main())

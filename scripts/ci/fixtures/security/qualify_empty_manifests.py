"""Run only inside the admitted image, offline, on read-only qualification copies.

No report or parser-error text is emitted. The host binds this numeric projection
and the exact populated identity to the admitted image and snapshot digests.
"""
import contextlib
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path


def main():
    version=importlib.metadata.version('semgrep')
    rows={}
    paths=('scripts/ci/gotestdecls/go.mod','scripts/ci/fixtures/selected/tiny-go/go.mod')
    # Native parser diagnostics remain private, even for the malformed controls.
    with open(os.devnull,'w') as private,contextlib.redirect_stdout(private),contextlib.redirect_stderr(private):
        # Import original image modules after redirecting native log-handler setup.
        from semdep.parsers.go_mod import parse_go_mod

        for path in paths:
            cases={}
            for case in ('empty','populated','malformed'):
                file=Path('/src')/case/path
                deps,errors=parse_go_mod(file,None)
                row=dict(sha256=hashlib.sha256(file.read_bytes()).hexdigest(),dependencies=len(deps),errors=len(errors))
                if case=='populated':
                    # Never project an unexpected package or free-form native value.
                    if len(deps)==1 and (deps[0].package,deps[0].version,deps[0].ecosystem.to_json()) == (
                            'example.com/semgrep-control','1.2.3','gomod'):
                        row.update(package=deps[0].package,version=deps[0].version,ecosystem=deps[0].ecosystem.to_json())
                cases[case]=row
            rows[path]=dict(cases['empty'],populated=cases['populated'],malformed=cases['malformed'])
    Path('/out/empty-parser.json').write_text(json.dumps(dict(version=version,inputs=rows),sort_keys=True)+'\n')


if __name__ == '__main__':
    # Exceptions must not send paths or parser messages to the captured console.
    try:main()
    except BaseException:raise SystemExit(1) from None

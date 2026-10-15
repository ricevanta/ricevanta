"""Negative controls and evidence checks for the toolchain bootstrap, run with the real payloads in CI.

`corrupt` downloads every selected payload once, then feeds the bootstrap a one-byte-flipped, a
truncated and a one-byte-appended copy of each through `--cache-mode sources`, and proves refusal
before any extraction, installation or execution: distinct size and digest reasons, an empty
destination, no executed command and unchanged installer side-effect sentinels. It also proves
that a wrong `--platform` fails before any download. `evidence` checks a finished bootstrap: the
evidence file lists exactly the selected lock entries with their digests, and every admitted
executable resolves on PATH to the admitted root rather than a runner tool cache.

Standard library only; it imports the sibling `bootstrap.py`.
"""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bootstrap  # noqa: E402

EXECUTABLES = {'go': ('go',), 'python': ('python', 'python3'), 'rustc': ('rustc', 'rustdoc'), 'cargo': ('cargo',),
               'rustfmt': ('rustfmt', 'cargo-fmt'), 'clippy': ('cargo-clippy',), 'node': ('node',), 'pnpm': ('pnpm',)}
CORRUPTIONS = ('flipped-byte', 'truncated', 'appended')


def corrupted(data, kind):
    if kind == 'flipped-byte':
        middle = len(data) // 2
        return data[:middle] + bytes([data[middle] ^ 0x01]) + data[middle + 1:]
    if kind == 'truncated': return data[:-1]
    return data + b'\0'


def selection_for(entry):
    if entry['tool'] in bootstrap.TOOL_GROUPS['rust']: return 'rust'
    if entry['tool'] == 'pnpm': return 'node,pnpm'
    return entry['tool']


def sentinel_snapshot(host):
    """Side effects an installer would leave: framework contents on macOS, the per-user registry on Windows."""
    state = {}
    if host.is_macos:
        root = host.framework_root
        if root.exists():
            for current, directories, files in os.walk(root):
                for name in directories + files:
                    path = Path(current) / name
                    try: info = path.lstat()
                    except OSError: continue
                    state[str(path)] = (info.st_mtime_ns, info.st_size, info.st_mode)
    if host.is_windows:
        state['registry'] = host.registry_has_user_python('3.14')
    return state


def run_bootstrap(argv, fetch, execute, host):
    out = io.StringIO()
    error = None
    with contextlib.redirect_stdout(out):
        try:
            code = bootstrap.run(argv, fetch=fetch, execute=execute, host=host)
        except bootstrap.BootstrapError as exc:
            code, error = 1, str(exc)
    return code, error, out.getvalue()


def refuse_download(url, limit, sink):
    raise bootstrap.BootstrapError('download refused during the corruption control: ' + url)


def control_corrupt(args, fetch, execute, host):
    lock = bootstrap.load_lock(args.lock)
    entries = bootstrap.select(lock, args.platform, args.tools)
    work = Path(args.work)
    if work.exists() and any(work.iterdir()): raise bootstrap.BootstrapError('control work directory must be empty: ' + str(work))
    work.mkdir(parents=True, exist_ok=True)
    sources = work / 'sources'
    sources.mkdir()
    report = {'kind': 'bootstrap-controls', 'platform': args.platform, 'controls': [], 'failures': []}
    calls = getattr(execute, 'calls', None)
    try:
        for entry in entries:
            target = sources / entry['sha256']
            bootstrap.log('control fetch', entry['id'], entry['url'])
            bootstrap.download_payload(entry, target, fetch)
        other = next(p for p in bootstrap.PLATFORMS if p != args.platform)
        before = len(calls) if calls is not None else None
        code, error, journal = run_bootstrap(['--lock', str(args.lock), '--platform', other, '--tools', args.tools, '--dest', str(work / 'dest-host'),
                                              '--cache-mode', 'none', '--env-out', str(work / 'env-host')], refuse_download, execute, host)
        row = {'control': 'wrong-host', 'entry': '*', 'platform': other, 'code': code, 'reason': error}
        if code == 0 or not error or 'unsupported host' not in error or (calls is not None and len(calls) != before) or 'bootstrap: fetch' in journal:
            report['failures'].append(f'wrong-host: expected refusal before download, got {code} {error!r}')
        report['controls'].append(row)
        index = 0
        for entry in entries:
            good = (sources / entry['sha256']).read_bytes()
            for kind in CORRUPTIONS:
                index += 1
                corrupt_dir = work / f'corrupt-{index}'
                corrupt_dir.mkdir()
                for other_entry in entries:
                    name = other_entry['sha256']
                    if other_entry is entry: (corrupt_dir / name).write_bytes(corrupted(good, kind))
                    else: os.link(sources / name, corrupt_dir / name) if hasattr(os, 'link') else shutil.copyfile(sources / name, corrupt_dir / name)
                dest = work / f'dest-{index}'
                snapshot = sentinel_snapshot(host)
                before = len(calls) if calls is not None else None
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patched_environ({bootstrap.SOURCES_ENV: str(corrupt_dir)}))
                    code, error, journal = run_bootstrap(['--lock', str(args.lock), '--platform', args.platform, '--tools', selection_for(entry),
                                                          '--dest', str(dest), '--cache-mode', 'sources', '--env-out', str(work / f'env-{index}')],
                                                         refuse_download, execute, host)
                expected = 'digest mismatch' if kind == 'flipped-byte' else 'size mismatch'
                unexpected = 'size mismatch' if kind == 'flipped-byte' else 'digest mismatch'
                problems = []
                if code == 0: problems.append('bootstrap accepted the corrupted payload')
                if not error or expected not in error or entry['id'] not in error: problems.append(f'reason {error!r} lacks {expected!r} for {entry["id"]}')
                if error and unexpected in error: problems.append('size and digest reasons are not distinct')
                if dest.exists() and any(dest.iterdir()): problems.append('destination is not empty after refusal')
                for phase in ('extract', 'install', 'execute', 'admitted'):
                    if f'bootstrap: {phase} ' in journal: problems.append(f'journal shows {phase} after refusal')
                if calls is not None and len(calls) != before: problems.append('a command executed after refusal')
                if sentinel_snapshot(host) != snapshot: problems.append('installer side effects changed')
                report['controls'].append({'control': kind, 'entry': entry['id'], 'code': code, 'reason': error, 'problems': problems})
                for problem in problems: report['failures'].append(f'{kind} {entry["id"]}: {problem}')
                shutil.rmtree(corrupt_dir, ignore_errors=True)
                shutil.rmtree(dest, ignore_errors=True)
    finally:
        shutil.rmtree(sources, ignore_errors=True)
    return report


@contextlib.contextmanager
def patched_environ(values):
    saved = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in saved.items():
            if value is None: os.environ.pop(key, None)
            else: os.environ[key] = value


def control_evidence(args):
    lock = bootstrap.load_lock(args.lock)
    entries = bootstrap.select(lock, args.platform, args.tools)
    report = {'kind': 'bootstrap-evidence-check', 'platform': args.platform, 'controls': [], 'failures': []}
    try:
        evidence = json.loads(Path(args.evidence).read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        report['failures'].append(f'evidence unreadable: {exc}')
        return report
    recorded = {row.get('id'): row for row in evidence.get('entries', []) if isinstance(row, dict)}
    if evidence.get('platform') != args.platform: report['failures'].append(f'evidence platform {evidence.get("platform")!r} is not {args.platform}')
    if sorted(recorded) != sorted(e['id'] for e in entries): report['failures'].append(f'evidence lists {sorted(recorded)}, expected {sorted(e["id"] for e in entries)}')
    root = Path(str(evidence.get('destination', '')))
    for entry in entries:
        row = recorded.get(entry['id'], {})
        if row.get('sha256') != entry['sha256'] or row.get('size') != entry['size'] or row.get('url') != entry['url'] or row.get('verified') is not True:
            report['failures'].append(f'{entry["id"]}: evidence does not match the lock entry')
        for name in EXECUTABLES.get(entry['tool'], ()):
            found = shutil.which(name)
            if not found or not Path(found).resolve().is_relative_to(root.resolve()) and not Path(found).is_relative_to(root):
                report['failures'].append(f'{entry["id"]}: {name} on PATH resolves to {found!r}, not under the admitted root {root}')
            report['controls'].append({'control': 'path', 'entry': entry['id'], 'executable': name, 'resolved': found})
    return report


def run(argv, *, fetch=bootstrap.fetch_url, execute=bootstrap.execute, host=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('corrupt', 'evidence'):
        command = sub.add_parser(name)
        command.add_argument('--lock', required=True, type=Path)
        command.add_argument('--platform', required=True)
        command.add_argument('--tools', required=True)
        if name == 'corrupt': command.add_argument('--work', required=True)
        else: command.add_argument('--evidence', required=True)
    args = parser.parse_args(argv)
    if args.command == 'corrupt':
        host = host or bootstrap.Host(bootstrap.host_platform())
        if host.platform != args.platform: raise bootstrap.BootstrapError(f'unsupported host: this machine is {host.platform}, not {args.platform}')
        report = control_corrupt(args, fetch, execute, host)
    else:
        report = control_evidence(args)
    for row in report['controls']:
        print('bootstrap-control: ' + json.dumps(row, sort_keys=True), flush=True)
    for failure in report['failures']:
        print('bootstrap-control: FAILED ' + failure, flush=True)
    print(f'bootstrap-control: {report["kind"]} {len(report["controls"])} controls, {len(report["failures"])} failures', flush=True)
    return report


def main(argv=None):
    try:
        report = run(sys.argv[1:] if argv is None else argv)
    except bootstrap.BootstrapError as exc:
        print('bootstrap-control: refused: ' + str(exc), file=sys.stderr, flush=True)
        return 1
    return 1 if report['failures'] else 0


if __name__ == '__main__':
    sys.exit(main())

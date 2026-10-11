"""Derive event-bound product identity without changing the source checkout.

GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_SHA and GITHUB_EVENT_PATH are required
job-owned inputs. Output is staged outside the checkout for later build recipes.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib

from release_common import bounded_read, check_identity, decode, load, parents, regular

CORE = r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)'
SHA = r'[0-9a-f]{40}'


def git(root, *args):
    """Run fixed Git operations, without shell or replacement-object resolution."""
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1')
    result = subprocess.run(['git', '--no-replace-objects', '-c', 'core.fsmonitor=false',
                             '-C', str(root), *args], env=env, capture_output=True, text=True)
    if result.returncode:
        raise ValueError('Git validation failed: ' + ' '.join(args))
    return result.stdout.strip()


def derive(root, channel, ref):
    """Validate checkout, pins and event before deriving the four public fields."""
    if Path(git(root, 'rev-parse', '--show-toplevel')).resolve() != root:
        raise ValueError('root: expected repository root')
    if git(root, 'rev-parse', '--is-shallow-repository') != 'false':
        raise ValueError('history: full history required')
    grafts = Path(git(root, 'rev-parse', '--git-path', 'info/grafts'))
    if not grafts.is_absolute():
        grafts = root / grafts
    if grafts.exists():
        raise ValueError('history: grafts are forbidden')
    if git(root, 'for-each-ref', '--format=%(refname)', 'refs/replace/'):
        raise ValueError('history: replacement refs forbidden')
    flags = git(root, 'ls-files', '-v').splitlines()
    if any(line and (line[0].islower() or line[0] == 'S') for line in flags):
        raise ValueError('index: hiding flags forbidden')
    if git(root, 'ls-files', '--unmerged'):
        raise ValueError('index: unmerged entries forbidden')
    git(root, 'diff-index', '--cached', '--quiet', 'HEAD', '--')
    if git(root, 'status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none'):
        raise ValueError('checkout: dirty sources')
    commit = git(root, 'rev-parse', '--verify', 'HEAD^{commit}')
    if not re.fullmatch(SHA, commit):
        raise ValueError('checkout: expected full lowercase SHA-1 commit')
    checked_inputs = {}
    for name in ('VERSION', 'agent/Cargo.toml', 'console/package.json'):
        git(root, 'ls-files', '--error-unmatch', '--', name)
        path = regular(root / name)
        entry = git(root, 'ls-tree', 'HEAD', '--', name).split()
        if len(entry) < 4 or entry[0] not in ('100644', '100755') or entry[1] != 'blob':
            raise ValueError(name + ': expected HEAD regular blob')
        actual = bounded_read(path, 16 * 1048576)
        checked_inputs[name] = actual
        # hash-object uses no filters unless --path is supplied.
        result = subprocess.run(['git', '--no-replace-objects', '-C', str(root),
                                 'hash-object', '--stdin'], input=actual, capture_output=True)
        if result.returncode or result.stdout.decode('ascii').strip() != entry[2]:
            raise ValueError(name + ': checkout bytes differ from HEAD blob')
    raw_core = checked_inputs['VERSION']
    if not re.fullmatch((CORE + '\n').encode('ascii'), raw_core):
        raise ValueError('VERSION: expected stable core with one LF')
    core = raw_core.decode('ascii')[:-1]
    cargo = tomllib.loads(checked_inputs['agent/Cargo.toml'].decode('utf-8'))
    console = decode(checked_inputs['console/package.json'], 'console/package.json')
    if cargo['workspace']['package']['version'] != core:
        raise ValueError('agent/Cargo.toml: core differs from VERSION')
    if console['version'] != core or console.get('private') is not True:
        raise ValueError('console/package.json: private package core differs from VERSION')
    env = os.environ
    if env.get('GITHUB_REF') != ref or env.get('GITHUB_SHA') != commit:
        raise ValueError('event: ref or tested checkout SHA mismatch')
    event_path = env.get('GITHUB_EVENT_PATH')
    if not event_path:
        raise ValueError('event: GITHUB_EVENT_PATH is required')
    event = load(Path(event_path))
    if channel == 'pr':
        number = event.get('number')
        if (env.get('GITHUB_EVENT_NAME') != 'pull_request' or type(number) is not int or number <= 0
                or ref != f'refs/pull/{number}/merge'
                or event.get('pull_request', {}).get('merge_commit_sha') != commit):
            raise ValueError('event: expected tested PR integration commit')
    else:
        after = event.get('after')
        matches_commit = after == commit
        if channel == 'prerelease' and not matches_commit:
            if (isinstance(after, str) and re.fullmatch(SHA, after)
                    and re.fullmatch(r'refs/tags/v' + CORE + r'-(?:alpha|beta|rc)\.[1-9][0-9]*', ref)):
                matches_commit = (git(root, 'rev-parse', '--verify', ref) == after
                                  and git(root, 'rev-parse', '--verify', after + '^{commit}') == commit)
        if (env.get('GITHUB_EVENT_NAME') != 'push' or event.get('ref') != ref
                or event.get('deleted', False) is not False or not matches_commit):
            raise ValueError('event: expected non-deletion push of tested commit')
        if channel == 'master' and ref != 'refs/heads/master':
            raise ValueError('event: expected master push')
    git(root, 'remote', 'get-url', 'origin')
    master = 'refs/remotes/origin/master'
    master_tip = git(root, 'rev-parse', '--verify', master + '^{commit}')
    roots = [commit, master_tip]
    if channel == 'prerelease':
        roots.append(git(root, 'rev-parse', '--verify', ref))
    # Unfiltered traversal walks every parent and every tree/blob/tag reference.
    objects = git(root, 'rev-list', '--objects', '--no-object-names',
                  '--missing=error', *roots).splitlines()
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_NO_LAZY_FETCH='1', GIT_NO_REPLACE_OBJECTS='1')
    # Reading object contents detects absent/corrupt objects, not only listed IDs.
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(root),
                             'cat-file', '--batch'], input=('\n'.join(objects + roots) + '\n').encode(),
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if result.returncode:
        raise ValueError('Git validation failed: reachable object readability')
    # --batch reports missing objects in stdout while still returning zero.
    checked = subprocess.run(['git', '--no-replace-objects', '-C', str(root),
                              'cat-file', '--batch-check'], input=('\n'.join(objects + roots) + '\n').encode(),
                             env=env, capture_output=True)
    if checked.returncode or any(b' missing' in row for row in checked.stdout.splitlines()):
        raise ValueError('Git validation failed: missing reachable object')
    if channel == 'master' and git(root, 'rev-parse', master + '^{commit}') != commit:
        raise ValueError('master: checkout differs from master')
    version = core + '-dev.0+g' + commit
    if channel == 'prerelease':
        match = re.fullmatch(r'refs/tags/v(' + CORE + r'-(?:alpha|beta|rc)\.[1-9][0-9]*)', ref)
        if not match or not match[1].startswith(core + '-'):
            raise ValueError('tag: invalid prerelease grammar or core')
        if git(root, 'rev-parse', '--verify', ref + '^{commit}') != commit:
            raise ValueError('tag: checkout differs from existing tag')
        git(root, 'merge-base', '--is-ancestor', commit, master)
        version = match[1]
    epoch = int(git(root, 'show', '-s', '--format=%ct', commit))
    identity = dict(version=version, commit=commit, channel=channel, sourceEpoch=epoch)
    if git(root, 'rev-parse', '--verify', master + '^{commit}') != master_tip or git(root, 'rev-parse', 'HEAD') != commit:
        raise ValueError('checkout: HEAD or fetched master changed during admission')
    check_identity(identity, None, 'derived identity')
    print('Fetched origin/master: ' + master_tip)
    return identity


def generate(identity, out):
    """Stage component inputs; consumers copy them to their ignored build paths."""
    parents(out)
    out.mkdir(parents=True, exist_ok=True)
    if set(p.name for p in out.iterdir()) - {'identity.json', 'build-info.json', 'generated.go', 'rust-env.json', 'build-info.ts'}:
        raise ValueError('out: unexpected generated file')
    check_identity(identity, None, 'generated identity')
    encoded = json.dumps(identity, sort_keys=True, indent=2) + '\n'
    rust = dict(RICEVANTA_VERSION=identity['version'], RICEVANTA_COMMIT=identity['commit'],
                RICEVANTA_CHANNEL=identity['channel'], SOURCE_DATE_EPOCH=str(identity['sourceEpoch']))
    go = '// Code generated by scripts/release/version.py. DO NOT EDIT.\npackage buildinfo\n\n'
    for field in ('version', 'commit', 'channel'):
        go += f'const {field.capitalize()} = {json.dumps(identity[field])}\n'
    go += f'const SourceEpoch int64 = {identity["sourceEpoch"]}\n'
    outputs = {'identity.json': encoded, 'build-info.json': encoded, 'generated.go': go,
               'rust-env.json': json.dumps(rust, sort_keys=True, indent=2) + '\n',
               'build-info.ts': '// Generated product identity.\nexport const buildInfo = ' +
                                json.dumps(identity, sort_keys=True, indent=2) + ' as const;\n'}
    for name in outputs:
        path = out / name
        parents(path)
        if path.exists():
            regular(path)
    for name, data in outputs.items():
        (out / name).write_text(data, encoding='utf-8', newline='\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--channel', required=True, choices=('pr', 'master', 'prerelease'))
    parser.add_argument('--ref', required=True)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    root, out = parents(args.root).resolve(), parents(args.out).resolve()
    if out.is_relative_to(root):
        raise ValueError('out: generated inputs must be outside the checkout')
    generate(derive(root, args.channel, args.ref), out)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(str(error))

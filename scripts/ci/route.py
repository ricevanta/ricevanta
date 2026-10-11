"""Bind complete changed paths to admitted GitHub events and checkout objects."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import inventory


def git(root, *args):
    try:
        return subprocess.run(['git', '-C', str(root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    except subprocess.CalledProcessError as exc:
        raise ValueError('Git object or history unavailable: ' + ' '.join(args[:2])) from exc


def sha(value):
    if not isinstance(value, str) or not re.fullmatch('[0-9a-f]{40}', value) or value == '0' * 40:
        raise ValueError('invalid commit identity')
    return value


def ensure(root, value, *, resolve_tag=False):
    value = sha(value)
    try: git(root, 'cat-file', '-e', value + '^{commit}')
    except ValueError:
        # Disable stored headers/helpers for public object fetches.
        git(root, '-c', 'credential.helper=', '-c', 'http.extraHeader=',
            'fetch', '--no-tags', 'origin', value)
        git(root, 'cat-file', '-e', value + '^{commit}')
    if resolve_tag:
        return sha(git(root, 'rev-parse', value + '^{commit}').decode().strip())
    if git(root, 'cat-file', '-t', value).strip() != b'commit':
        raise ValueError('event identity must name a commit object')
    return value


def diff(root, base, head):
    return [p for p in git(root, 'diff', '--name-only', '--no-renames', '-z', base, head, '--').split(b'\0') if p]


def build_route(event_name, event, root, env=None, full=False):
    env = os.environ if env is None else env
    try:
        tested = sha(env['GITHUB_SHA'])
        if git(root, 'rev-parse', 'HEAD').decode().strip() != tested:
            raise ValueError('checkout does not match GITHUB_SHA')
        ensure(root, tested)
        if event_name == 'pull_request' and not full:
            pr = event['pull_request']
            if pr['base']['ref'] != 'master': raise ValueError('PR must target master')
            base, head = ensure(root, pr['base']['sha']), ensure(root, pr['head']['sha'])
            parents = git(root, 'rev-list', '--parents', '-n', '1', tested).decode().split()[1:]
            if parents != [base, head]: raise ValueError('integration parents do not bind event base and head')
            merge_base = git(root, 'merge-base', base, head).decode().strip()
            paths = diff(root, merge_base, head) + diff(root, base, tested)
        elif event_name == 'push' and full:
            if not re.fullmatch(r'refs/tags/[^\s]+', event['ref']): raise ValueError('full mode needs a tag')
            head = ensure(root, event['after'], resolve_tag=True)
            if tested != head: raise ValueError('tag checkout mismatch')
            tag = git(root, 'rev-parse', event['ref'] + '^{commit}').decode().strip()
            if tag != tested: raise ValueError('tag does not resolve to tested commit')
            if git(root, 'rev-parse', '--is-shallow-repository').strip() != b'false':
                raise ValueError('release requires full history')
            master = git(root, 'rev-parse', 'refs/remotes/origin/master').decode().strip()
            git(root, 'merge-base', '--is-ancestor', tested, master)
            base = ensure(root, git(root, 'rev-parse', tested + '^1').decode().strip())
            paths = []
        elif event_name == 'push' and not full:
            if event['ref'] != 'refs/heads/master': raise ValueError('push must target master')
            base, head = ensure(root, event['before']), ensure(root, event['after'])
            if tested != head: raise ValueError('push checkout mismatch')
            git(root, 'merge-base', '--is-ancestor', base, head)
            paths = diff(root, base, head)
        else: raise ValueError('unsupported event')
        run_id, attempt = env['GITHUB_RUN_ID'], env['GITHUB_RUN_ATTEMPT']
        if not all(isinstance(v, str) and re.fullmatch('[1-9][0-9]*', v) for v in (run_id, attempt)):
            raise ValueError('invalid run identity')
        groups = sorted(inventory.GROUPS) if full else inventory.select_groups(paths)
        return dict(kind='route', version=1, event=event_name, baseSha=base, headSha=head,
                    testedSha=tested, runId=run_id, runAttempt=attempt,
                    groups=groups, units=inventory.units(groups))
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('malformed event or environment') from exc


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--event-name', required=True)
    p.add_argument('--event', type=Path, required=True)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--full', action='store_true')
    args = p.parse_args()
    result = build_route(args.event_name, json.loads(args.event.read_text()), args.root, full=args.full)
    args.out.write_text(json.dumps(result, separators=(',', ':')) + '\n')

if __name__ == '__main__': main()

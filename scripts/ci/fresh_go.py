"""Create fresh compiler roots and verify Cargo download archives."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tomllib


def create_root(root):
    runner = Path(os.environ['RUNNER_TEMP']).resolve(strict=True)
    if not root.is_absolute() or any(p.is_symlink() for p in (root, *root.parents)):
        raise ValueError('cache root must be absolute and have no symlinks')
    if not root.resolve().is_relative_to(runner) or root == runner:
        raise ValueError('cache root must be below RUNNER_TEMP')
    root.mkdir(mode=0o700)
    return root


def verify_cargo(home, lock):
    """Discard extracted sources and verify restored archives against Cargo.lock."""
    if any(p.is_symlink() for p in (home, *home.parents)):
        raise ValueError('Cargo home must not be a symlink')
    registry = home / 'registry'
    if registry.is_symlink() or (registry.exists() and any(p.is_symlink() for p in registry.rglob('*'))):
        raise ValueError('Cargo cache contains a symlink')
    sources = registry / 'src'
    if sources.exists():
        shutil.rmtree(sources)
    packages = tomllib.loads(lock.read_text(encoding='utf-8'))['package']
    checksums = {f"{p['name']}-{p['version']}.crate": p['checksum']
                 for p in packages if p.get('source', '').startswith('registry+')}
    archives = registry / 'cache'
    if archives.exists():
        for archive in archives.rglob('*'):
            if archive.is_dir():
                continue
            with archive.open('rb') as source:
                actual = hashlib.file_digest(source, 'sha256').hexdigest()
            if checksums.get(archive.name) != actual:
                raise ValueError(f'Cargo archive checksum mismatch: {archive.name}')


def prepare(root, env_out, cargo_home=None, cargo_lock=None):
    create_root(root)
    if cargo_home is None:
        env = {'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=readonly'}
        for key, name in (('GOCACHE', 'build'), ('GOMODCACHE', 'modules')):
            path = root / name
            path.mkdir(mode=0o700)
            count = len(list(path.iterdir()))
            if count:
                raise ValueError('nonempty cache')
            env[key] = str(path)
            print(f'{key}={path} initial entries={count}', flush=True)
    else:
        target = root / 'target'
        target.mkdir(mode=0o700)
        if not cargo_home.is_absolute():
            raise ValueError('Cargo home must be absolute')
        env = {'CARGO_TARGET_DIR': str(target), 'CARGO_HOME': str(cargo_home)}
        verify_cargo(cargo_home, cargo_lock)
        subprocess.run(['cargo', 'fetch', '--locked'], cwd=cargo_lock.parent,
                       env={**os.environ, **env, 'CARGO_HOME': str(cargo_home)}, check=True)
        verify_cargo(cargo_home, cargo_lock)
        print(f'CARGO_TARGET_DIR={target} initial entries=0', flush=True)
    if any('\n' in v or '\r' in v for v in env.values()):
        raise ValueError('environment path contains newline')
    with env_out.open('a', encoding='utf-8', newline='\n') as output:
        for key, value in env.items():
            output.write(f'{key}={value}\n')
    return env


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--env-out', required=True, type=Path)
    parser.add_argument('--cargo-home', type=Path)
    parser.add_argument('--cargo-lock', type=Path)
    args = parser.parse_args()
    if (args.cargo_home is None) != (args.cargo_lock is None):
        parser.error('--cargo-home and --cargo-lock must be supplied together')
    try:
        prepare(args.root, args.env_out, args.cargo_home, args.cargo_lock)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'fresh cache admission failed: {error}\n')


if __name__ == '__main__':
    main()

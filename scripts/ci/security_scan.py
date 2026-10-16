"""Admit pinned scanners and keep raw reports and credentials on the runner."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import queue
import re
import signal
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import tomllib
import urllib.request

import inventory
import required
import route as routing
from semgrep_observer import (NATIVE_TRACE_MODULES, NATIVE_OUTPUT_MARKERS, NATIVE_ERROR_TYPES, native_output_projection,
    MAX_SUMMARY_BYTES, SUMMARY_FIELDS, summary_size_projection)

PATH = '/usr/local/bin:/usr/bin:/bin'
REPOSITORY = 'ricevanta/ricevanta'
SEMGREP_EXCEPTION_IDENTITY = dict(advisoryId='CVE-2026-93687',osvAdvisoryId='GHSA-vfj7-8cjw-p6xm',product='sca',severity='ERROR',
    rule='ssc-dc89f360-8dea-4ff2-92c4-e67670eb22ef',package='braces',packageVersion='3.0.3',ecosystem='npm',
    path='console/pnpm-lock.yaml',line=870,consoleFiles=124,
    consoleSha256='11e45e4e42c78ced832fd814e1e4ce5f0619ab5d4a2fe00780881e0beff62303')
EMPTY_MANIFESTS = {
    'scripts/ci/gotestdecls/go.mod': ('ricevanta.invalid/gotestdecls','1.27.1'),
    'scripts/ci/fixtures/selected/tiny-go/go.mod': ('example.com/tiny','1.22'),
}
SEMGREP_COMMAND = ['semgrep', 'ci', '--code', '--supply-chain', '--pro', '--no-suppress-errors',
                   '--verbose', '--disable-nosem', '--disable-version-check', '--metrics=off',
                   '--json-output=/out/semgrep.json']
SCANNER_STAGES = {'semgrep-image-pull','semgrep-image-inspect','semgrep-pro-admission',
                  'semgrep-code-controls','semgrep-empty-parser-controls','semgrep-rust-probe','semgrep-vue-probe','semgrep-scan'}
OBSERVER_STAGES = {'startup','bundled-pro','code-controls','authenticated-scan'}
OBSERVER_STAGES.update({'start-scan-request','start-scan-validation','scan-configured','core-invocation',
    'plan-serialization','plan-validation','plan-complete','core-result-validation','core-complete',
    'report-validation','upload-request','upload-validation','upload-complete'})
OBSERVER_EXCEPTION_CLASSES = {'ValueError','TypeError','KeyError','AttributeError','RuntimeError','PermissionError',
    'FileNotFoundError','JSONDecodeError','UnicodeDecodeError','ImportError','ModuleNotFoundError',
    'SemgrepError','SemgrepCoreError','UnknownLanguageError','InvalidRuleSchemaError',
    'HTTPError','SSLError','ConnectionError','Timeout','TimeoutExpired','CalledProcessError','SystemExit','other'}
OBSERVER_EXCEPTION_KINDS = {'cli-exit','value','import','file','permission','json','native'}
MAX_CAPTURE_BYTES = 16_000_000
AUXILIARY_PATH = '.semgrepignore'
AUXILIARY_BYTES = b'# Reviewed full tracked-tree scan; no exclusion patterns.\n'
AUXILIARY_SHA256 = 'c8133eb012efe9edb83ce4df1e6106c1e110e8836e4c09b4c20a99a61dc1177a'
SKIP_REASONS = {'always_skipped','semgrepignore_patterns_match','cli_include_flags_do_not_match',
                'cli_exclude_flags_match','exceeded_size_limit','analysis_failed_parser_or_internal_error',
                'excluded_by_config','wrong_language','too_big','minified','binary','irrelevant_rule',
                'too_many_matches','Gitignore_patterns_match','Dotfile','Nonexistent_file','insufficient_permissions'}


def decode_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('duplicate report member')
            result[key] = value
        return result
    def invalid(value): raise ValueError('nonfinite report number')
    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid)


def verify_bytes(payload, pin):
    if len(payload) != pin['bytes'] or hashlib.sha256(payload).hexdigest() != pin['sha256']:
        raise ValueError('payload size or digest mismatch')


def extract_gitleaks(payload, destination):
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
        members = archive.getmembers()
        if not members or len(members) > 100: raise ValueError('invalid scanner archive')
        for member in members:
            path = PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not member.isfile() or len(path.parts) != 1:
                raise ValueError('unsafe scanner archive')
            if member.size > 40_000_000: raise ValueError('oversized scanner archive member')
        archive.extractall(destination, members=members, filter='data')
    binary = destination / 'gitleaks'
    if not binary.is_file(): raise ValueError('missing scanner executable')
    binary.chmod(0o700)
    return binary


def execute(argv, env, *, timeout=900, cwd=None, stage=None):
    process = captured_process(argv,env,timeout=timeout,cwd=cwd)
    if process.returncode:
        evidence = native_output_projection(process.stdout,process.stderr) if stage == 'semgrep-scan' else None
        raise ProcessFailure(process.returncode,stage,evidence)
    return process.stdout, process.stderr


def preflight(name, event, env):
    try:
        repo = event['repository']
        if repo['full_name'] != REPOSITORY or env['GITHUB_REPOSITORY'] != REPOSITORY:
            raise ValueError('repository identity mismatch')
        rid = int(env['GITHUB_REPOSITORY_ID'])
        if type(repo['id']) is not int or repo['id'] != rid: raise ValueError('repository identity mismatch')
        if name == 'push' and event['ref'] == 'refs/heads/master': return None
        if name != 'pull_request': raise ValueError('scanner event unsupported')
        pr = event['pull_request']
        if pr['user']['login'] == 'dependabot[bot]': raise ValueError('Dependabot requires maintainer replacement PR')
        if pr['head']['repo']['id'] != rid or pr['base']['repo']['id'] != rid:
            raise ValueError('fork requires reviewed maintainer replacement PR')
        number = event['number']
        if type(number) is not int or number <= 0: raise ValueError('invalid PR identity')
        return number
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('malformed scanner event') from exc


def scanner_environment(value, number, token):
    return {'PATH': PATH, 'HOME': '/tmp/security-home', 'SEMGREP_APP_TOKEN': token,
            'SEMGREP_REPO_NAME': REPOSITORY, 'SEMGREP_REPO_URL': 'https://github.com/' + REPOSITORY,
            'SEMGREP_COMMIT': value['testedSha'],
            'SEMGREP_BRANCH': 'master' if number is None else f"ci/pr/{number}/{value['testedSha']}",
            'SEMGREP_JOB_URL': f"https://github.com/{REPOSITORY}/actions/runs/{value['runId']}/attempts/{value['runAttempt']}"}


def validate_lock(lock):
    if set(lock) != {'version', 'gitleaks', 'semgrep', 'pro'} or type(lock['version']) is not int or lock['version'] != 1:
        raise ValueError('invalid scanner lock')
    shapes = {'gitleaks': {'version', 'url', 'bytes', 'sha256'},
              'semgrep': {'version', 'image', 'manifest', 'config'}, 'pro': {'path', 'marker', 'bytes', 'sha256'}}
    for tool, keys in shapes.items():
        if not isinstance(lock[tool], dict) or set(lock[tool]) != keys: raise ValueError('invalid scanner lock shape')
    if lock['gitleaks']['version'] != '8.30.1' or lock['semgrep']['version'] != '1.178.0':
        raise ValueError('unsupported scanner version')
    if lock['semgrep']['image'] != 'semgrep/semgrep': raise ValueError('untrusted scanner image')
    if lock['pro']['path'] != '/usr/lib/python3.12/site-packages/semgrep/bin/semgrep-core-proprietary' or lock['pro']['marker'] != '1.178.0\n':
        raise ValueError('invalid bundled Pro authority')
    for tool in ('gitleaks', 'pro'):
        pin = lock[tool]
        if type(pin['bytes']) is not int or not 0 < pin['bytes'] < 500_000_000:
            raise ValueError('invalid payload authority')
        if not re.fullmatch('[0-9a-f]{64}', pin['sha256']) or pin['sha256'] == '0'*64:
            raise ValueError('invalid payload digest')
    if lock['gitleaks']['url'] != 'https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz':
        raise ValueError('invalid scanner download authority')
    for key in ('manifest', 'config'):
        if not re.fullmatch('sha256:[0-9a-f]{64}', lock['semgrep'][key]) or lock['semgrep'][key] == 'sha256:'+'0'*64:
            raise ValueError('invalid image authority')
    return lock


def load_lock(root):
    return validate_lock(tomllib.loads((root / 'scripts/ci/security-tools.toml').read_text()))


def validate_image(images, pin):
    if not isinstance(images, list) or len(images) != 1: raise ValueError('invalid image inspection')
    image = images[0]
    if image.get('Id') != pin['config'] or image.get('Os') != 'linux' or image.get('Architecture') != 'amd64':
        raise ValueError('image digest or platform mismatch')


def gitleaks_evidence(report, log, mode):
    if not isinstance(report, list): raise ValueError('Gitleaks invalid report')
    text = log.decode('utf-8', errors='strict')
    pattern = r'\b([1-9][0-9]*) commits scanned' if mode == 'git' else r'\bscanned ~?([1-9][0-9]*) bytes'
    match = re.search(pattern, text)
    completed = 'no leaks found' in text if not report else bool(re.search(r'leaks found: *' + str(len(report)) + r'\b',text))
    if not match or not completed or re.search(r'\bERR\b',text): raise ValueError('missing Gitleaks completion evidence')
    return int(match[1])


def safe_path(path):
    if not isinstance(path, str): raise ValueError('invalid report path')
    p = PurePosixPath(path)
    if p.is_absolute() or '..' in p.parts or not p.parts or '\\' in path or any(ord(c) < 32 for c in path):
        raise ValueError('unsafe report path')
    return p.as_posix()


def validate_semgrep_exceptions(document):
    if (not isinstance(document,dict) or set(document) != {'version','scanner','exception'}
            or type(document['version']) is not int or document['version'] != 1 or document['scanner'] != '1.178.0'
            or not isinstance(document['exception'],list) or len(document['exception']) > 1):
        raise ValueError('invalid Semgrep exception set')
    for entry in document['exception']:
        if not isinstance(entry,dict) or set(entry) != set(SEMGREP_EXCEPTION_IDENTITY)|{'rationale','provenance'}:
            raise ValueError('invalid Semgrep exception set')
        for key,expected in SEMGREP_EXCEPTION_IDENTITY.items():
            if type(entry[key]) is not type(expected) or entry[key] != expected:raise ValueError('invalid Semgrep exception set')
        if any(not isinstance(entry[key],str) or not entry[key].strip() for key in ('rationale','provenance')):
            raise ValueError('invalid Semgrep exception set')
    return document['exception']


def load_semgrep_exceptions(root,hashes=None):
    path=root/'scripts/ci/semgrep-exceptions.toml'
    try:
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 65536:
            raise ValueError('invalid Semgrep exception set')
        with path.open('rb') as stream:payload=stream.read(65537)
        if not 0 < len(payload) <= 65536:raise ValueError('invalid Semgrep exception set')
        if hashes is not None and hashes.get('scripts/ci/semgrep-exceptions.toml') != hashlib.sha256(payload).hexdigest():
            raise ValueError('invalid Semgrep exception set')
        return validate_semgrep_exceptions(tomllib.loads(payload.decode('utf-8')))
    except (OSError,UnicodeError,tomllib.TOMLDecodeError):
        raise ValueError('invalid Semgrep exception set') from None


def verify_console_boundary(source,hashes,modes,exceptions):
    if not exceptions:return None
    validate_semgrep_exceptions(dict(version=1,scanner='1.178.0',exception=exceptions))
    if not isinstance(source,Path) or not isinstance(hashes,dict) or not isinstance(modes,dict):
        raise ValueError('Semgrep exception boundary mismatch')
    console={}
    for path,digest in hashes.items():
        if not isinstance(path,str):raise ValueError('Semgrep exception boundary mismatch')
        canonical=safe_path(path)
        if path != canonical or any(127 <= ord(c) <= 159 for c in path):raise ValueError('Semgrep exception boundary mismatch')
        if path.startswith('console/'):
            if not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('Semgrep exception boundary mismatch')
            console[path]=digest
    if set(modes) != set(console) or any(type(mode) is not str or mode not in ('100644','100755') for mode in modes.values()):
        raise ValueError('Semgrep exception boundary mismatch')
    rows=hashlib.sha256();size=0
    for path in sorted(console,key=lambda p:p.encode('utf-8')):
        row=path.encode('utf-8')+b'\0'+console[path].encode('ascii')+b'\n';rows.update(row);size+=len(row)
    entry=exceptions[0]
    if len(console) != entry['consoleFiles'] or size != 12728 or rows.hexdigest() != entry['consoleSha256']:
        raise ValueError('Semgrep exception boundary mismatch')
    for path in console:
        candidate=source/path
        try:
            before=candidate.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:raise ValueError('Semgrep exception boundary mismatch')
            if not candidate.resolve().is_relative_to(source.resolve()):raise ValueError('Semgrep exception boundary mismatch')
            for parent in candidate.parents:
                if parent == source:break
                if parent.is_symlink():raise ValueError('Semgrep exception boundary mismatch')
            with candidate.open('rb') as stream:
                opened=os.fstat(stream.fileno())
                if (before.st_dev,before.st_ino) != (opened.st_dev,opened.st_ino):raise ValueError('Semgrep exception boundary mismatch')
                digest=hashlib.file_digest(stream,'sha256').hexdigest()
            after=candidate.lstat()
            if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                    or (after.st_dev,after.st_ino) != (opened.st_dev,opened.st_ino) or digest != console[path]):
                raise ValueError('Semgrep exception boundary mismatch')
        except OSError:
            raise ValueError('Semgrep exception boundary mismatch') from None
    return dict(files=len(console),canonicalBytes=size,sha256=rows.hexdigest())


def verify_empty_manifests(source,hashes):
    """Consume the entire reviewed profile independently of native scan counts."""
    if not isinstance(source,Path) or not isinstance(hashes,dict):
        raise ValueError('empty manifest boundary mismatch')
    for path in hashes:
        if path != safe_path(path):raise ValueError('empty manifest boundary mismatch')
    verified={}
    for path,(module,version) in EMPTY_MANIFESTS.items():
        if path not in hashes or str(PurePosixPath(path).with_name('go.sum')) in hashes:
            raise ValueError('empty manifest inventory mismatch')
        candidate=source/path
        try:
            if source.is_symlink():raise ValueError('empty manifest boundary mismatch')
            for parent in candidate.parents:
                if parent == source:break
                if parent.is_symlink():raise ValueError('empty manifest boundary mismatch')
            before=candidate.lstat()
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 4096:
                raise ValueError('empty manifest boundary mismatch')
            with candidate.open('rb') as stream:
                opened=os.fstat(stream.fileno());payload=stream.read(4097)
            after=candidate.lstat()
            if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
                    or (before.st_dev,before.st_ino) != (opened.st_dev,opened.st_ino)
                    or (after.st_dev,after.st_ino) != (opened.st_dev,opened.st_ino)
                    or len(payload)>4096 or hashlib.sha256(payload).hexdigest()!=hashes[path]):
                raise ValueError('empty manifest boundary mismatch')
            pattern=rb'\n*module '+re.escape(module.encode('ascii'))+rb'\n+go '+re.escape(version.encode('ascii'))+rb'\n+'
            if re.fullmatch(pattern,payload) is None:raise ValueError('empty manifest profile mismatch')
            verified[path]=hashes[path]
        except OSError:
            raise ValueError('empty manifest boundary mismatch') from None
    return verified


def verify_empty_qualification(evidence,lock,hashes,source):
    """Check only evidence produced by the isolated admitted-image invocation."""
    try:
        verify_empty_manifests(source,hashes)
        if (set(evidence) != {'version','image','config','inputs'} or evidence['version'] != '1.178.0'
                or evidence['image'] != lock['semgrep']['manifest'] or evidence['config'] != lock['semgrep']['config']
                or set(evidence['inputs']) != set(EMPTY_MANIFESTS)):
            raise ValueError('empty manifest qualification mismatch')
        for path,row in evidence['inputs'].items():
            if (set(row) != {'sha256','dependencies','errors','populated','malformed'} or row['sha256'] != hashes[path]
                    or type(row['dependencies']) is not int or row['dependencies'] != 0
                    or type(row['errors']) is not int or row['errors'] != 0):
                raise ValueError('empty manifest qualification mismatch')
            for case in ('populated','malformed'):
                control=row[case]
                fields={'sha256','dependencies','errors'}|({'package','version','ecosystem'} if case=='populated' else set())
                if (set(control) != fields or not re.fullmatch('[0-9a-f]{64}',control['sha256'])
                        or type(control['dependencies']) is not int or type(control['errors']) is not int):
                    raise ValueError('empty manifest qualification mismatch')
                suffix=(b'require example.com/semgrep-control v1.2.3\n' if case=='populated'
                        else b'not_a_go_directive invalid\n')
                payload=(source/path).read_bytes()
                if hashlib.sha256(payload).hexdigest()!=hashes[path] or hashlib.sha256(payload+suffix).hexdigest()!=control['sha256']:
                    raise ValueError('empty manifest qualification mismatch')
                if case=='populated':
                    if (control['dependencies'] != 1 or control['errors'] != 0 or
                            (control['package'],control['version'],control['ecosystem']) != ('example.com/semgrep-control','1.2.3','gomod')):
                        raise ValueError('empty manifest qualification mismatch')
                elif control['dependencies'] < 0 or control['errors'] <= 0:
                    raise ValueError('empty manifest qualification mismatch')
    except (KeyError,TypeError,AttributeError):
        raise ValueError('empty manifest qualification mismatch') from None
    return evidence


def empty_parser_controls(image,root,output,source,hashes,lock):
    empty=verify_empty_manifests(source,hashes)
    staging=output/'empty-parser-source';staging.mkdir()
    control_hashes={}
    for path,digest in empty.items():
        payload=(source/path).read_bytes()
        if hashlib.sha256(payload).hexdigest()!=digest:raise ValueError('empty manifest boundary mismatch')
        control_hashes[path]={}
        for case,suffix in (('empty',b''),('populated',b'require example.com/semgrep-control v1.2.3\n'),
                            ('malformed',b'not_a_go_directive invalid\n')):
            target=staging/case/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(payload+suffix)
            control_hashes[path][case]=hashlib.sha256(payload+suffix).hexdigest()
    command=container_command(image,staging,output,root/'scripts/ci',scan=False)
    command[-2:]=['/control/fixtures/security/qualify_empty_manifests.py']
    execute(command,{'PATH':PATH,'HOME':str(output)},timeout=120,stage='semgrep-empty-parser-controls')
    native=read_private(output/'empty-parser.json',16384)
    if not isinstance(native,dict) or set(native) != {'version','inputs'}:raise ValueError('empty manifest qualification mismatch')
    evidence=dict(native,image=lock['semgrep']['manifest'],config=lock['semgrep']['config'])
    verify_empty_qualification(evidence,lock,hashes,source)
    for path,cases in control_hashes.items():
        for case,digest in cases.items():
            observed=evidence['inputs'][path] if case=='empty' else evidence['inputs'][path][case]
            if observed['sha256']!=digest:raise ValueError('empty manifest qualification mismatch')
    verify_empty_manifests(source,hashes)
    return evidence


def semgrep_exception_matches(result,entry):
    try:
        extra=result['extra'];metadata=extra['metadata'];match=extra['sca_info']['dependency_match'];dependency=match['found_dependency']
        pairs=((result['check_id'],entry['rule']),(result['path'],entry['path']),(result['start']['line'],entry['line']),
            (extra['severity'],entry['severity']),(metadata['product'],entry['product']),
            (metadata['sca-vuln-database-identifier'],entry['advisoryId']),(match['lockfile'],entry['path']),
            (dependency['package'],entry['package']),(dependency['version'],entry['packageVersion']),
            (dependency['ecosystem'],entry['ecosystem']),(dependency['lockfile_path'],entry['path']))
        return all(type(value) is type(expected) and value == expected for value,expected in pairs)
    except (KeyError,TypeError):return False


def finding_counts(findings):
    high=sum(row['severity'] in ('ERROR','HIGH','CRITICAL') for row in findings)
    excepted=sum(row.get('disposition') == 'excepted' for row in findings)
    return dict(total=len(findings),high=high,excepted=excepted,blocking=high-excepted,lower=len(findings)-high)


def findings_gate(results,*,exceptions=()):
    if not isinstance(results, list): raise ValueError('invalid finding list')
    safe = []
    for result in results:
        try:
            extra = result['extra']; severity = extra['severity']; product = extra['metadata']['product']
            rule = result['check_id']; line = result['start']['line']
            if severity not in ('ERROR', 'HIGH', 'CRITICAL', 'WARNING', 'MEDIUM', 'INFO', 'LOW', 'INVENTORY', 'EXPERIMENT'):
                raise ValueError('unknown finding severity')
            if product not in ('sast', 'sca'): raise ValueError('unknown finding product')
            if not isinstance(rule, str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,500}', rule): raise ValueError('unsafe rule identity')
            if type(line) is not int or line <= 0: raise ValueError('invalid finding line')
            row = dict(rule=rule, path=safe_path(result['path']), line=line, severity=severity, product=product)
            safe.append(row)
        except (KeyError, TypeError) as exc:
            raise ValueError('malformed finding') from exc
    if exceptions:
        validate_semgrep_exceptions(dict(version=1,scanner='1.178.0',exception=list(exceptions)))
        matched=[index for index,result in enumerate(results) if semgrep_exception_matches(result,exceptions[0])]
        if len(matched) != 1:raise ValueError('stale or duplicate Semgrep exception')
        row=safe[matched[0]]
        safe[matched[0]]=dict(row,advisory=sca_advisory_evidence(results[matched[0]]['extra']['metadata']),disposition='excepted')
    if finding_counts(safe)['blocking']:
        raise GateFailure('active high severity findings',blocking_finding_evidence(safe,results))
    return safe


def sca_advisory_evidence(metadata):
    key='sca-vuln-database-identifier'
    if key not in metadata:return dict(status='missing')
    value=metadata[key]
    if type(value) is str and len(value)<=28 and re.fullmatch(
            r'CVE-[0-9]{4}-[0-9]{4,19}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}',value):
        return dict(status='recognized',id=value)
    return dict(status='unrecognized')


def blocking_finding_evidence(findings,results):
    severities=('ERROR','HIGH','CRITICAL','WARNING','MEDIUM','INFO','LOW','INVENTORY','EXPERIMENT')
    by_severity={severity:0 for severity in severities};by_product=dict(sast=0,sca=0)
    for row in findings:
        by_severity[row['severity']] += 1;by_product[row['product']] += 1
    counts=finding_counts(findings)
    samples=[]
    for partition in ('blocking','excepted','lower'):
        for row,result in zip(findings,results):
            if len(samples)==32:break
            disposition='excepted' if row.get('disposition') == 'excepted' else 'blocking' if row['severity'] in ('ERROR','HIGH','CRITICAL') else 'lower'
            if disposition != partition:continue
            if row['line'] > 2**63-1 or len(json.dumps(row['path']).encode('utf-8'))>1002:continue
            samples.append(dict(row,advisory=sca_advisory_evidence(result['extra']['metadata'])) if row['product']=='sca' else row)
    return dict(counts,
                byProduct=by_product,bySeverity=by_severity,sampleLimit=32,sampleCount=len(samples),
                omittedCount=len(findings)-len(samples),identities=samples)


def fresh_output(root, output):
    root = root.resolve()
    if output.exists() or output.is_symlink() or output.resolve().is_relative_to(root):
        raise ValueError('output must be fresh and outside source')
    output.mkdir(mode=0o700)


def validate_source_entry(root, mode, path, payload):
    original=path
    path = safe_path(path)
    candidate = root / path
    if path in EMPTY_MANIFESTS:
        if original!=path or mode not in ('100644','100755') or root.is_symlink():
            raise ValueError('empty manifest boundary mismatch')
        for parent in candidate.parents:
            if parent==root:break
            if parent.is_symlink():raise ValueError('empty manifest boundary mismatch')
        info=candidate.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('empty manifest boundary mismatch')
    if mode == '160000': raise ValueError('unexpected submodule')
    if mode == '120000':
        if not candidate.is_symlink() or os.readlink(candidate).encode() != payload:
            raise ValueError('source symlink mismatch')
        if not candidate.resolve().is_relative_to(root.resolve()): raise ValueError('escaping source symlink')
    elif mode in ('100644', '100755'):
        if candidate.is_symlink() or not candidate.is_file() or candidate.read_bytes() != payload:
            raise ValueError('source differs from tested tree')
    else: raise ValueError('unsupported source mode')


def snapshot(root, value, destination,*,console_modes=None):
    import shutil
    entries = routing.git(root, 'ls-tree', '-r', '-z', value['testedSha']).split(b'\0')
    hashes = {}
    destination.mkdir(mode=0o700)
    for entry in entries:
        if not entry: continue
        metadata, raw_path = entry.split(b'\t', 1)
        mode, kind, blob = metadata.decode().split()
        path = raw_path.decode('utf-8')
        if console_modes is not None and path.startswith('console/'):console_modes[path]=mode
        if kind != 'blob': raise ValueError('unexpected submodule')
        payload = routing.git(root, 'cat-file', 'blob', blob)
        validate_source_entry(root, mode, path, payload)
        target = destination / path; target.parent.mkdir(parents=True, exist_ok=True)
        if mode == '120000': target.symlink_to(payload.decode('utf-8'))
        else: target.write_bytes(payload); target.chmod(0o755 if mode == '100755' else 0o644)
        hashes[path] = hashlib.sha256(payload).hexdigest()
    if not hashes: raise ValueError('empty tracked snapshot')
    git_dir = Path(routing.git(root, 'rev-parse', '--absolute-git-dir').decode().strip())
    if not git_dir.is_dir() or (git_dir / 'commondir').exists():
        raise ValueError('scanner requires standalone hosted checkout')
    shutil.copytree(git_dir, destination / '.git', symlinks=False)
    # Generic metadata reads this fixed tree. Hooks, refs and credentials cannot
    # select an alternate checkout because /src is mounted read-only.
    (destination / '.git/HEAD').write_text(value['testedSha'] + '\n')
    return hashes


def verify_snapshot(destination, hashes):
    for path, digest in hashes.items():
        candidate = destination / path
        payload = os.readlink(candidate).encode() if candidate.is_symlink() else candidate.read_bytes()
        if hashlib.sha256(payload).hexdigest() != digest: raise ValueError('source snapshot changed')


def verify_auxiliary(source,hashes,overlay):
    if any(safe_path(path) == AUXILIARY_PATH for path in hashes):
        raise ValueError('unexpected candidate Semgrep exclusions')
    if not isinstance(overlay,dict) or overlay != {AUXILIARY_PATH:AUXILIARY_SHA256}:
        raise ValueError('invalid generated scanner input')
    path=source/AUXILIARY_PATH
    try:
        before=path.lstat()
        if not stat.S_ISREG(before.st_mode):raise ValueError('invalid generated scanner input')
        with path.open('rb') as stream:
            opened=os.fstat(stream.fileno())
            if (opened.st_dev,opened.st_ino) != (before.st_dev,before.st_ino):
                raise ValueError('invalid generated scanner input')
            payload=stream.read(len(AUXILIARY_BYTES)+1)
        after=path.lstat()
        if not stat.S_ISREG(after.st_mode) or (after.st_dev,after.st_ino) != (opened.st_dev,opened.st_ino):
            raise ValueError('invalid generated scanner input')
        if payload != AUXILIARY_BYTES or hashlib.sha256(payload).hexdigest() != AUXILIARY_SHA256:
            raise ValueError('invalid generated scanner input')
    except OSError:
        raise ValueError('invalid generated scanner input') from None
    return frozenset({AUXILIARY_PATH})


def download(pin):
    request = urllib.request.Request(pin['url'])
    try:
        class Redirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, hdrs, newurl):
                if not newurl.startswith('https://'): raise ValueError('insecure download redirect')
                return super().redirect_request(req, fp, code, msg, hdrs, newurl)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect())
        with opener.open(request, timeout=120) as response:
            payload = response.read(pin['bytes'] + 1)
    except Exception as exc:
        raise ValueError('scanner payload download failed') from exc
    verify_bytes(payload, pin)
    return payload


def admitted_image(pin, *, pull):
    image = pin['image'] + '@' + pin['manifest']
    env = {'PATH': PATH, 'HOME': '/tmp'}
    if pull: execute(['docker', 'pull', '--platform=linux/amd64', image], env, timeout=300,stage='semgrep-image-pull')
    stdout, _ = execute(['docker', 'image', 'inspect', image], env, timeout=30,stage='semgrep-image-inspect')
    validate_image(decode_json(stdout), pin)
    return image


def gitleaks_command(binary, mode, source, output, sha):
    command = [str(binary), mode, str(source), '--redact=100', '--exit-code=1',
               '--report-format=json', '--report-path=' + str(output / (mode + '.json')),
               '--config=' + str(output / 'gitleaks.toml'), '--ignore-gitleaks-allow',
               '--gitleaks-ignore-path=' + str(output / 'empty.ignore'), '--no-banner', '--no-color']
    if mode == 'git': command.append('--log-opts=' + routing.sha(sha))
    return command


def run_gitleaks(root, value, output, lock):
    with tempfile.TemporaryDirectory(prefix='security-gitleaks-') as tmp:
        staging = Path(tmp)
        binary = extract_gitleaks(download(lock['gitleaks']), staging)
        env = {'PATH': PATH, 'HOME': str(staging), 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': os.devnull}
        version, _ = execute([str(binary), 'version'], env, timeout=30)
        if version.decode().strip() != lock['gitleaks']['version']: raise ValueError('Gitleaks version mismatch')
        if routing.git(root, 'rev-parse', '--is-shallow-repository').strip() != b'false':
            raise ValueError('Gitleaks requires full history')
        controls = gitleaks_controls(binary,staging,env,output)
        hashes = snapshot(root, value, staging / 'source')
        (output / 'gitleaks.toml').write_text('[extend]\nuseDefault = true\n')
        (output / 'empty.ignore').touch()
        counts = {};gates = {};statuses = {}
        exceptions = load_exceptions(root)
        blobs = exception_blobs(root,staging/'source')
        for mode in ('git', 'dir'):
            source = staging/'source'
            # Directory findings retain the scanner's native relative identity.
            target = Path('.') if mode == 'dir' else source
            process = captured_process(gitleaks_command(binary, mode, target, output, value['testedSha']), env,timeout=900,cwd=source)
            (output / (mode + '.log')).write_bytes(process.stdout + process.stderr)
            report = read_private(output/(mode+'.json'))
            counts[mode] = gitleaks_evidence(report, process.stdout+process.stderr, mode)
            gates[mode] = gitleaks_gate(report,process.returncode,mode,exceptions,blobs)
            statuses[mode] = process.returncode
        verify_snapshot(staging / 'source', hashes)
        return {'bootstrap':runner_inputs(), 'toolVersion':lock['gitleaks']['version'], 'commits': counts['git'], 'bytes': counts['dir'], 'files': len(hashes),
                'sourceHashes': hashes, 'tool': lock['gitleaks']['sha256'], 'controls': controls, 'gates': gates, 'statuses': statuses}


def expected_dependencies(hashes):
    names = {'go.mod', 'Cargo.lock', 'pnpm-lock.yaml', 'requirements-design.txt', 'requirements-build.txt', 'requirements.txt'}
    return sorted(path for path in hashes if PurePosixPath(path).name in names)


def skipped_targets(rows):
    if not isinstance(rows,list): raise ValueError('missing or malformed native skip evidence')
    safe = []
    for row in rows:
        if not isinstance(row,dict) or not {'path','reason'} <= set(row) or not set(row) <= {'path','reason','details','rule_id'}:
            raise ValueError('missing or malformed native skip evidence')
        reason = row['reason']
        if not isinstance(reason,str) or reason not in SKIP_REASONS:
            raise ValueError('missing or malformed native skip evidence')
        if 'rule_id' in row and (not isinstance(row['rule_id'],str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,500}',row['rule_id'])):
            raise ValueError('missing or malformed native skip evidence')
        safe.append(dict(path=safe_path(row['path']),reason=reason))
    return safe


def code_work_evidence(work,rules,targets,hashes,auxiliary=frozenset()):
    shape = {'pairs','rules','targets','analyzers','skippedTargets','skippedRules'}
    if not isinstance(work,dict) or set(work) != shape: raise ValueError('missing or malformed Code execution evidence')
    count = work['pairs'];code_rules = work['rules'];code_targets = work['targets'];analyzers = work['analyzers']
    if type(count) is not int or not 0 < count <= 2_000_000 or not isinstance(code_rules,list) or not code_rules or not isinstance(code_targets,list) or not code_targets:
        raise ValueError('missing or malformed Code execution evidence')
    if not all(isinstance(rule,str) and rules.get(rule) == 'sast' for rule in code_rules) or len(set(code_rules)) != len(code_rules):
        raise ValueError('missing or malformed Code execution evidence')
    code_targets = [safe_path(path) for path in code_targets]
    if (len(set(code_targets)) != len(code_targets) or not set(code_targets) <= set(targets)
            or not set(code_targets) <= set(hashes)|auxiliary or not set(code_targets) & set(hashes)):
        raise ValueError('missing or malformed Code execution evidence')
    if count < max(len(code_rules),len(code_targets)) or not isinstance(analyzers,dict) or not analyzers:
        raise ValueError('missing or malformed Code execution evidence')
    for language,row in analyzers.items():
        if not isinstance(language,str) or not re.fullmatch('[a-z0-9_+-]{1,40}',language) or not isinstance(row,dict) or set(row) != {'pairs','rules','targets'}:
            raise ValueError('missing or malformed Code execution evidence')
        if any(type(n) is not int or not 0 < n <= count for n in row.values()) or row['rules'] > len(code_rules) or row['targets'] > len(code_targets) or row['pairs'] < max(row['rules'],row['targets']):
            raise ValueError('missing or malformed Code execution evidence')
    if sum(row['pairs'] for row in analyzers.values()) != count: raise ValueError('missing or malformed Code execution evidence')
    core_skips = []
    if not isinstance(work['skippedTargets'],list) or not isinstance(work['skippedRules'],list): raise ValueError('missing or malformed Code execution evidence')
    for row in work['skippedTargets']:
        if not isinstance(row,dict) or set(row) not in ({'path','reason'},{'path','reason','rule'}): raise ValueError('missing or malformed Code execution evidence')
        safe = skipped_targets([dict(path=row['path'],reason=row['reason'])])[0]
        if safe['path'] not in hashes and safe['path'] not in auxiliary:raise ValueError('missing or malformed Code execution evidence')
        if 'rule' not in row and safe['path'] in code_targets: raise ValueError('missing or malformed Code execution evidence')
        if 'rule' in row:
            if not isinstance(row['rule'],str) or row['rule'] not in rules: raise ValueError('missing or malformed Code execution evidence')
            safe['rule'] = row['rule']
        core_skips.append(safe)
    if not all(isinstance(rule,str) and rule in rules for rule in work['skippedRules']) or len(set(work['skippedRules'])) != len(work['skippedRules']) or set(work['skippedRules']) & set(code_rules):
        raise ValueError('missing or malformed Code execution evidence')
    return dict(pairs=count,rules=len(code_rules),targets=len(code_targets),analyzers=analyzers,
                skippedTargets=core_skips,skippedRules=work['skippedRules'],
                gitTargets=len(set(code_targets)&set(hashes)),auxiliaryTargets=len(set(code_targets)&auxiliary))


def semgrep_evidence(report, summary, sha, invocation, hashes,auxiliary=frozenset(),*,exceptions=(),source=None,console_modes=None):
    try:
        if type(auxiliary) is not frozenset or not auxiliary <= frozenset({AUXILIARY_PATH}):
            raise ValueError('invalid generated scanner input')
        if auxiliary and AUXILIARY_PATH in hashes:raise ValueError('unexpected candidate Semgrep exclusions')
        members=set(hashes)|auxiliary
        shape = set(SUMMARY_FIELDS)
        if not isinstance(summary,dict) or set(summary) != shape: raise ValueError('invalid observer summary shape')
        if summary['invocation'] != invocation or summary['testedSha'] != sha: raise ValueError('stale observer summary')
        if type(summary['scanId']) is not int or summary['scanId'] <= 0: raise ValueError('invalid scan identifier')
        if summary['products'] != ['sast','sca'] or summary['upload'] is not True: raise ValueError('incomplete products or upload')
        if type(summary['parserErrors']) is not int or summary['parserErrors'] != 0 or summary['engine'] != 'PRO':
            raise ValueError('incomplete parser or engine')
        rules = summary['rules']
        configured = summary['configuredRules']
        if (not isinstance(configured,dict) or set(configured) != {'sast','sca'}
                or any(type(count) is not int or not 0 < count <= 2**63-1 for count in configured.values())
                or not isinstance(rules,dict) or not rules or not set(rules.values()) <= {'sast','sca'}
                or any(sum(product == kind for product in rules.values()) > count for kind,count in configured.items())):
            raise ValueError('missing applicable Code or Supply Chain rules')
        if not all(isinstance(r,str) and re.fullmatch('[A-Za-z0-9_.:/-]{1,500}',r) for r in rules): raise ValueError('invalid rule identifier')
        if not re.fullmatch('[A-Za-z0-9_.+ -]{1,100}',summary['proVersion']): raise ValueError('invalid Pro version evidence')
        if report['version'] != '1.178.0' or report['errors'] != [] or report['engine_requested'] != 'PRO':
            raise ValueError('Semgrep scan errors or wrong version/engine')
        targets = [safe_path(path) for path in report['paths']['scanned']]
        skipped = skipped_targets(report['paths']['skipped'])
        observed = [safe_path(path) for path in summary['targets']]
        if not targets or not observed or not set(targets) <= set(observed) or not set(observed) <= members:
            raise TargetInventoryFailure(targets,observed,hashes)
        if any(row['path'] not in members for row in skipped):raise ValueError('foreign skipped target')
        code_work = code_work_evidence(summary['codeWork'],rules,targets,hashes,auxiliary)
        source_targets = [p for p in targets if PurePosixPath(p).suffix in ('.go','.rs','.py','.ts','.tsx','.js','.jsx','.vue')]
        if not source_targets: raise ValueError('empty Code source target inventory')
        empty=verify_empty_manifests(source,hashes)
        dependencies = summary['dependencies']
        if not isinstance(dependencies,dict) or not all(p == safe_path(p) and p in hashes and type(n) is int
                and (n == 0 if p in empty else n > 0) for p,n in dependencies.items()):
            raise ValueError('invalid parsed dependency inventory')
        expected = set(expected_dependencies(hashes))
        if not expected or not expected-set(empty) <= set(dependencies):raise ValueError('omitted supported dependency input')
        coverage = {};empty_native={}
        for subproject in report['subprojects']:
            raw_paths=subproject['dependency_sources']
            if not isinstance(raw_paths,list):raise ValueError('dependency coverage mismatch')
            paths = [safe_path(p) for p in raw_paths]
            if paths != raw_paths or len(set(paths)) != len(paths):raise ValueError('dependency coverage mismatch')
            relevant=set(paths)&expected
            if not relevant:continue
            stats = subproject['resolved_stats']
            if subproject['resolved'] is not True or subproject.get('unresolved_reason') is not None or stats['resolution_method'] != 'LockfileParsing':
                raise ValueError('unresolved supported dependency input')
            count = stats['dependency_count']
            for path in relevant:
                if path in coverage:raise ValueError('dependency coverage mismatch')
                if path in empty:
                    if paths != [path] or stats['ecosystem'] != 'gomod' or type(count) is not int or count != 0:
                        raise ValueError('empty manifest native mismatch')
                    if path in dependencies and (type(dependencies[path]) is not int or dependencies[path] != 0):
                        raise ValueError('empty manifest native mismatch')
                    empty_native[path]=dict(resolved=subproject['resolved'],resolutionMethod=stats['resolution_method'],
                        ecosystem=stats['ecosystem'],dependencyCount=count,mapPresent=path in dependencies)
                    if path in dependencies:empty_native[path]['mapCount']=dependencies[path]
                else:
                    if type(count) is not int or count <= 0:raise ValueError('empty supported dependency inventory')
                    if dependencies[path] != count:raise ValueError('dependency coverage mismatch')
                coverage[path] = count
        if set(coverage) != expected:raise ValueError('missing native dependency parser evidence')
        # Native rule.product supplies the product when normal finding metadata
        # omits it. Explicit conflicting metadata still fails closed.
        results = []
        for result in report['results']:
            if safe_path(result['path']) not in members:raise ValueError('foreign finding target')
            rule = result['check_id']
            if rule not in rules: raise ValueError('unobserved finding rule')
            extra = dict(result['extra']); metadata = dict(extra['metadata'])
            if 'product' in metadata and metadata['product'] != rules[rule]: raise ValueError('finding product mismatch')
            metadata['product'] = rules[rule];extra['metadata'] = metadata
            results.append(dict(result,extra=extra))
        ignored = [safe_path(p) for p in summary['ignoredTargets']]
        if not set(ignored) <= members: raise ValueError('foreign unsupported target')
        rule_languages = summary['codeRuleLanguages']
        if not isinstance(rule_languages,dict) or not rule_languages or not all(re.fullmatch('[a-z0-9_+-]{1,40}',lang) and type(n) is int and 0 < n <= configured['sast'] for lang,n in rule_languages.items()):
            raise ValueError('missing Code language rule counts')
        language_counts = {}
        for path in source_targets:
            suffix = PurePosixPath(path).suffix
            language_counts[suffix] = language_counts.get(suffix,0) + 1
        verify_console_boundary(source,hashes,console_modes,exceptions)
        safe = findings_gate(results,exceptions=exceptions)
        evidence = dict(scanId=summary['scanId'], products=['sast','sca'],
                    codeRules=code_work['rules'],codeTargets=code_work['targets'],codePairs=code_work['pairs'],codeAnalyzers=code_work['analyzers'],
                    gitCodeTargets=code_work['gitTargets'],auxiliaryCodeTargets=code_work['auxiliaryTargets'],
                    configuredCodeRules=configured['sast'],
                    configuredSupplyChainRules=configured['sca'],
                    mixedTargets=len(targets),mixedSourceTargets=len(source_targets),mixedSourceExtensions=language_counts,configuredCodeRuleLanguages=rule_languages,
                    dependencies=dict(dependencies), emptyInputs=empty, emptyNativeInputs=empty_native, findings=safe, unsupportedTargets=ignored,
                    skippedTargets=skipped,skippedTargetCount=len(skipped),
                    coreSkippedTargets=code_work['skippedTargets'],coreSkippedRules=code_work['skippedRules'],
                    proVersion=summary['proVersion'],
                    limits=['Account-triaged ignored findings are trusted owner policy outside this JSON gate.',
                            'Rust SCA is version-based; no reachability or transitivity guarantee.',
                            'Vue template analysis is not established by script coverage.'])
        if auxiliary:
            evidence['auxiliaryInput']=dict(path=AUXILIARY_PATH,bytes=len(AUXILIARY_BYTES),sha256=AUXILIARY_SHA256,
                targets=targets.count(AUXILIARY_PATH),skippedTargets=sum(row['path']==AUXILIARY_PATH for row in skipped),
                coreSkippedTargets=sum(row['path']==AUXILIARY_PATH for row in code_work['skippedTargets']),
                ignoredTargets=ignored.count(AUXILIARY_PATH),findings=sum(row['path']==AUXILIARY_PATH for row in safe),
                codeTargets=code_work['auxiliaryTargets'])
        if exceptions:evidence['findingCounts']=finding_counts(safe)
        return evidence
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('malformed or incomplete Semgrep evidence') from exc


def require_token(token):
    if not isinstance(token,str) or not token or len(token) > 8192 or any(c.isspace() or ord(c)<32 for c in token):
        raise ValueError('missing or invalid Semgrep token')
    return token


def container_command(image, source, output, control, *, scan, identity=None):
    for path in (source, output, control):
        if any(c in str(path) for c in (':',',','\n','\r')): raise ValueError('unsafe container mount path')
    if identity is None: identity = (os.geteuid(),os.getegid())
    if not isinstance(identity,tuple) or len(identity) != 2 or any(type(value) is not int or not 0 <= value < 2**32 for value in identity):
        raise ValueError('invalid container process identity')
    uid,gid = identity
    command = ['docker','run','--rm','--pull=never','--platform=linux/amd64','--read-only',
               '--user',f'{uid}:{gid}',
               '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','256',
               '--tmpfs','/tmp:rw,nosuid,nodev,size=2g','--tmpfs',f'/home/security:rw,nosuid,nodev,size=64m,uid={uid},gid={gid},mode=0700',
               '--workdir','/src','--env','HOME=/home/security','--env','PATH=' + PATH,
               '--volume',str(source) + ':/src:ro','--volume',str(output) + ':/out:rw',
               '--volume',str(control) + ':/control:ro','--entrypoint','/usr/bin/python3']
    if scan:
        for key in sorted(scanner_environment({'testedSha':'a'*40,'runId':'1','runAttempt':'1'},None,'').keys() - {'PATH','HOME'}):
            command += ['--env',key]
    else: command += ['--network','none']
    return command + [image,'-I','/control/semgrep_observer.py','--scan' if scan else '--admission']


def read_private(path, maximum=100_000_000):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= maximum:
        raise ValueError('missing or oversized scanner output')
    return decode_json(path.read_text(encoding='utf-8'))


def write_json(path, value):
    path.write_text(json.dumps(value,sort_keys=True,separators=(',',':')) + '\n')


def observer_failure_projection(native):
    base = {'reason','stage','exceptionKind'}
    if not isinstance(native,dict) or not base <= set(native) or not set(native) <= base|{'processExit','callback','trace','summarySize'}:
        return None
    if native['reason'] not in OBSERVER_FAILURES or native['stage'] not in OBSERVER_STAGES or native['exceptionKind'] not in OBSERVER_EXCEPTION_KINDS or 'processExit' in native and type(native['processExit']) is not int:
        return None
    safe = dict(observerReason=native['reason'],observerStage=native['stage'],observerExceptionKind=native['exceptionKind'])
    if 'processExit' in native:safe['observerExit']=native['processExit']
    if 'summarySize' in native:
        sizing=summary_size_projection(native['summarySize'])
        if sizing is None or native['reason'] != 'observer-summary-size' or native['stage'] != 'upload-complete' or native['exceptionKind'] != 'value':return None
        safe['observerSummarySize']=sizing
    if 'callback' in native:
        callback=native['callback']
        fields={'reason','stage','exceptionClass'}
        if not isinstance(callback,dict) or not fields <= set(callback) or not set(callback) <= fields|{'coreErrors'} or callback['reason'] not in OBSERVER_FAILURES or callback['stage'] not in OBSERVER_STAGES or callback['exceptionClass'] not in OBSERVER_EXCEPTION_CLASSES:
            return None
        safe.update(observerCallbackReason=callback['reason'],observerCallbackStage=callback['stage'],observerCallbackException=callback['exceptionClass'])
        if 'coreErrors' in callback:
            core=core_failure_projection(callback['coreErrors'])
            if core is None or callback['reason'] != 'observer-core-errors' or callback['stage'] != 'core-result-validation':return None
            safe['nativeCoreErrors']=core
    if 'trace' in native:
        trace=native['trace']
        if not isinstance(trace,dict) or set(trace) != {'frames','exceptionClasses','categories'}:return None
        frames=trace['frames'];classes=trace['exceptionClasses'];categories=trace['categories']
        if not isinstance(frames,list) or len(frames)>32 or not isinstance(classes,list) or len(classes)>len(OBSERVER_EXCEPTION_CLASSES) or not isinstance(categories,list) or len(categories)>len(NATIVE_OUTPUT_MARKERS):return None
        if any(not isinstance(row,dict) or set(row) != {'module','line'} or not isinstance(row['module'],str) or row['module'] not in NATIVE_TRACE_MODULES or type(row['line']) is not int or not 0 < row['line'] <= NATIVE_TRACE_MODULES[row['module']] for row in frames):return None
        if any(not isinstance(name,str) or name not in OBSERVER_EXCEPTION_CLASSES-{'other'} for name in classes) or any(not isinstance(name,str) or name not in NATIVE_OUTPUT_MARKERS for name in categories):return None
        safe['nativeErrorTrace']=trace
    return safe


def core_failure_projection(core):
    if core == {'status':'rejected'}:return core
    if not isinstance(core,dict) or set(core) != {'status','errorCount','convertedErrorCount','errors'} or core['status'] != 'present':return None
    if any(type(core[key]) is not int or core[key]<0 for key in ('errorCount','convertedErrorCount')) or not isinstance(core['errors'],list) or len(core['errors']) != min(32,core['errorCount']):return None
    for row in core['errors']:
        if not isinstance(row,dict) or not {'type','level'} <= set(row) or not set(row) <= {'type','level','rule','path'} or not isinstance(row['type'],str) or row['type'] not in NATIVE_ERROR_TYPES|{'unknown'} or row['level'] not in ('error','warn','info','unknown'):return None
        if 'rule' in row and (not isinstance(row['rule'],str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,500}',row['rule'])):return None
        if 'path' in row:
            try:
                if safe_path(row['path']) != row['path'] or len(json.dumps(row['path'],ensure_ascii=False).encode('utf-8'))>1002:return None
            except (ValueError,UnicodeError):return None
    return core


def native_error_projection(report):
    if not isinstance(report,dict) or not isinstance(report.get('errors'),list):return dict(status='rejected')
    safe=[]
    for row in report['errors'][:32]:
        if not isinstance(row,dict):row={}
        kind=row.get('type')
        if isinstance(kind,list) and len(kind)==2:kind=kind[0]
        kind=kind if isinstance(kind,str) and kind in NATIVE_ERROR_TYPES else 'unknown'
        code=row.get('code');code=code if type(code) is int and code in (0,1,2,3,4,5,7,8,13) else 'unknown'
        level=row.get('level');level=level if isinstance(level,str) and level in ('error','warn','info') else 'unknown'
        category='unknown'
        message=row.get('message')
        if kind=='SemgrepError' and isinstance(message,str):
            if message.startswith('Could not start scan: '):category='scan-initialization'
            elif message.startswith('No products are enabled for this organization.'):category='products-unavailable'
            elif re.fullmatch(r'invalid configuration file found \([0-9]+ configs were invalid\)',message):category='configuration'
        elif kind in ('InvalidRuleSchemaError','UnknownLanguageError','Invalid YAML','Rule parse error','Pattern parse error','PatternParseError','Incompatible rule','IncompatibleRule'):category='configuration'
        elif kind in ('Lexical error','Syntax error','Other syntax error','AST builder error','PartialParsing'):category='parsing'
        elif kind=='DependencyResolutionError':category='dependencies'
        elif kind in ('Fatal error','Internal matching error','Timeout','Out of memory','Fixpoint timeout','Stack overflow','Timeout during interfile analysis','OOM during interfile analysis','Missing plugin','Too many matches'):category='engine'
        safe.append(dict(type=kind,code=code,level=level,category=category))
    return dict(status='present',errorCount=len(report['errors']),errors=safe)


def bind_route(root, path, *, authenticated=False):
    value = read_private(path,65536)
    event = read_private(Path(os.environ['GITHUB_EVENT_PATH']),5_000_000)
    if authenticated: number = preflight(os.environ['GITHUB_EVENT_NAME'],event,os.environ)
    else: number = None
    recomputed = routing.build_route(os.environ['GITHUB_EVENT_NAME'],event,root)
    if recomputed != value: raise ValueError('scanner route does not match checkout and event')
    required.validate_route(value,shape=False)
    return value, number


def admit_semgrep(root, value, output, lock):
    exceptions=load_semgrep_exceptions(root)
    console_modes={} if exceptions else None
    image = admitted_image(lock['semgrep'],pull=True)
    hashes = snapshot(root,value,output / 'source',console_modes=console_modes)
    exceptions=load_semgrep_exceptions(output/'source',hashes)
    verify_console_boundary(output/'source',hashes,console_modes,exceptions)
    verify_empty_manifests(output/'source',hashes)
    # Explicit control overlay disables broad default exclusions. It is outside
    # the unchanged source hash inventory and contains no source code.
    ignore = output/'source'/AUXILIARY_PATH
    if AUXILIARY_PATH in hashes: raise ValueError('unexpected candidate Semgrep exclusions')
    if ignore.exists() or ignore.is_symlink():raise ValueError('invalid generated scanner input')
    ignore.write_bytes(AUXILIARY_BYTES)
    overlay={AUXILIARY_PATH:AUXILIARY_SHA256}
    verify_auxiliary(output/'source',hashes,overlay)
    execute(container_command(image,output/'source',output,root/'scripts/ci',scan=False),
            {'PATH':PATH,'HOME':str(output)},timeout=180,stage='semgrep-pro-admission')
    controls = semgrep_controls(image,root,output)
    controls['emptyManifests']=empty_parser_controls(image,root,output,output/'source',hashes,lock)
    pro = read_private(output/'pro.json',4096)
    if set(pro) != {'version','sha256'} or pro['sha256'] != lock['pro']['sha256']:
        raise ValueError('invalid admitted Pro result')
    verify_auxiliary(output/'source',hashes,overlay)
    verify_console_boundary(output/'source',hashes,console_modes,exceptions)
    verify_empty_manifests(output/'source',hashes)
    admission=dict(route=value,sourceHashes=hashes,pro=pro,tools=lock,controls=controls,overlay=overlay)
    if exceptions:admission['consoleModes']=console_modes
    write_json(output/'admission.json',admission)
    return dict(bootstrap=runner_inputs(docker=True),image=lock['semgrep']['manifest'],config=lock['semgrep']['config'],pro=pro['sha256'],
                sourceFiles=len(hashes),supportedInputs=expected_dependencies(hashes),controls=controls)


def run_semgrep(root, value, number, output, lock, token):
    token = require_token(token)
    admission_dir = output.parent/'security-semgrep-admission'
    admission = read_private(admission_dir/'admission.json',10_000_000)
    if admission['route'] != value or admission['tools'] != lock: raise ValueError('stale Semgrep admission')
    verify_snapshot(admission_dir/'source',admission['sourceHashes'])
    auxiliary=verify_auxiliary(admission_dir/'source',admission['sourceHashes'],admission['overlay'])
    exceptions=load_semgrep_exceptions(admission_dir/'source',admission['sourceHashes'])
    console_modes=admission.get('consoleModes')
    verify_console_boundary(admission_dir/'source',admission['sourceHashes'],console_modes,exceptions)
    verify_empty_manifests(admission_dir/'source',admission['sourceHashes'])
    verify_empty_qualification(admission['controls'].get('emptyManifests'),lock,admission['sourceHashes'],admission_dir/'source')
    image = admitted_image(lock['semgrep'],pull=False)
    invocation = os.urandom(16).hex()
    write_json(output/'context.json',dict(invocation=invocation,testedSha=value['testedSha']))
    env = scanner_environment(value,number,token)
    execute(container_command(image,admission_dir/'source',output,root/'scripts/ci',scan=True),env,timeout=1000,stage='semgrep-scan')
    verify_snapshot(admission_dir/'source',admission['sourceHashes'])
    auxiliary=verify_auxiliary(admission_dir/'source',admission['sourceHashes'],admission['overlay'])
    summary = read_private(output/'observer.json',MAX_SUMMARY_BYTES)
    report = read_private(output/'semgrep.json')
    if summary['proVersion'] != admission['pro']['version']: raise ValueError('Pro engine changed after admission')
    result = semgrep_evidence(report,summary,value['testedSha'],invocation,admission['sourceHashes'],auxiliary,
        exceptions=exceptions,source=admission_dir/'source',console_modes=console_modes)
    return result


def verified_completion(root, value, output, unit, lock):
    complete = read_private(output/'complete.json',10_000_000)
    if set(complete) != {'unit','route','tools','result'} or complete['unit'] != unit or complete['route'] != value or complete['tools'] != lock:
        raise ValueError('stale or invalid scanner completion')
    if unit == 'gitleaks':
        exceptions = load_exceptions(root); blobs = exception_blobs(root,root)
        result = complete['result']
        verify_snapshot(root,result['sourceHashes'])
        counts = {}
        for mode in ('git','dir'):
            report = read_private(output/(mode+'.json'))
            counts[mode] = gitleaks_evidence(report, (output/(mode+'.log')).read_bytes(),mode)
            gate = gitleaks_gate(report,result['statuses'][mode],mode,exceptions,blobs)
            if gate != result['gates'][mode]: raise ValueError('Gitleaks completion mismatch')
        if result['commits'] != counts['git'] or result['bytes'] != counts['dir'] or result['files'] != len(result['sourceHashes']):
            raise ValueError('Gitleaks completion mismatch')
    else:
        admission_dir = output.parent/'security-semgrep-admission'
        admission = read_private(admission_dir/'admission.json',10_000_000)
        context = read_private(output/'context.json',4096)
        verify_empty_qualification(admission['controls'].get('emptyManifests'),lock,admission['sourceHashes'],admission_dir/'source')
        verify_snapshot(admission_dir/'source',admission['sourceHashes'])
        auxiliary=verify_auxiliary(admission_dir/'source',admission['sourceHashes'],admission['overlay'])
        exceptions=load_semgrep_exceptions(admission_dir/'source',admission['sourceHashes'])
        result = semgrep_evidence(read_private(output/'semgrep.json'),read_private(output/'observer.json',MAX_SUMMARY_BYTES),
                                 value['testedSha'],context['invocation'],admission['sourceHashes'],auxiliary,
                                 exceptions=exceptions,source=admission_dir/'source',console_modes=admission.get('consoleModes'))
        if result != complete['result']: raise ValueError('scanner completion does not match native output')
    return complete['result']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode',choices=['gitleaks','semgrep'])
    parser.add_argument('--phase',choices=['preflight','admission','scan','verify'],default='scan')
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--route',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    root = args.root.resolve(); output = args.output.absolute()
    try:
        lock = load_lock(root)
        if args.phase in ('preflight','admission') and os.environ.get('SEMGREP_APP_TOKEN'):
            raise ValueError('credential forbidden during admission')
        token = os.environ.pop('SEMGREP_APP_TOKEN',None) if args.phase == 'scan' else None
        value,number = bind_route(root,args.route,authenticated=args.mode=='semgrep')
        if not output.resolve().is_relative_to(Path(os.environ['RUNNER_TEMP']).resolve()):
            raise ValueError('scanner output must stay in runner temporary directory')
        if args.phase == 'preflight':
            fresh_output(root,output)
            write_json(output/'diagnostics.json',dict(unit=args.mode,result='success',testedSha=value['testedSha'],phase='preflight'))
            print('Security event preflight passed');return
        if platform.system() != 'Linux' or platform.machine() not in ('x86_64','AMD64'):
            raise ValueError('scanner requires Linux AMD64 host')
        if args.phase == 'verify':
            verified_completion(root,value,output,args.mode,lock)
            print('Native scanner completion and finding gate verified');return
        fresh_output(root,output)
        if args.phase == 'admission':
            if args.mode != 'semgrep': raise ValueError('unsupported admission phase')
            result = admit_semgrep(root,value,output,lock)
        else:
            result = run_gitleaks(root,value,output,lock) if args.mode == 'gitleaks' else run_semgrep(root,value,number,output,lock,token)
            write_json(output/'complete.json',dict(unit=args.mode,route=value,tools=lock,result=result))
        safe = {k:v for k,v in result.items() if k != 'sourceHashes'}
        write_json(output/'diagnostics.json',dict(unit=args.mode,testedSha=value['testedSha'],result='success',evidence=safe))
        print('Security scanner phase passed')
    except Exception as exc:
        # Never stringify exception text from network clients, the scanner or
        # report parsers. It can contain credentials, source or absolute paths.
        if not output.is_symlink() and not output.resolve().is_relative_to(root) and output.resolve().is_relative_to(Path(os.environ.get('RUNNER_TEMP','/nonexistent')).resolve()):
            output.mkdir(mode=0o700,exist_ok=True)
            diagnostic = dict(unit=args.mode,phase=args.phase,result='failure',reason=failure_code(exc))
            if isinstance(exc,ProcessFailure):
                diagnostic['processExit'] = exc.status
                if exc.stage in SCANNER_STAGES: diagnostic['stage'] = exc.stage
                if exc.stage == 'semgrep-scan' and exc.output_evidence is not None:
                    diagnostic['nativeOutput'] = exc.output_evidence
            if isinstance(exc,GateFailure): diagnostic['findings'] = exc.safe
            if isinstance(exc,TargetInventoryFailure): diagnostic['targetInventory'] = exc.safe
            if args.mode == 'semgrep' and isinstance(exc,ProcessFailure):
                try:
                    native = read_private(output/'observer-failure.json',65536)
                    safe=observer_failure_projection(native)
                    if safe is not None:diagnostic.update(safe)
                except Exception: pass
                if args.phase == 'scan':
                    report=output/'semgrep.json'
                    try:diagnostic['nativeReport']=native_error_projection(read_private(report))
                    except Exception:diagnostic['nativeReport']=dict(status='rejected' if report.exists() else 'missing')
            write_json(output/'diagnostics.json',diagnostic)
        print('Security scan failed: ' + failure_code(exc))
        raise SystemExit(1) from None



def verify_gitleaks_control(status, log, report, secret):
    if status != 1 or not isinstance(report,list) or not report or secret.encode() in log or secret in json.dumps(report):
        raise ValueError('Gitleaks positive control or redaction failed')
    if any(row.get('Secret') != 'REDACTED' or 'REDACTED' not in row.get('Match','') for row in report):
        raise ValueError('Gitleaks report redaction failed')


def gitleaks_controls(binary, staging, env, output):
    source = staging/'controls';source.mkdir()
    secret = 'ghp_' + ''.join('aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5')
    (source/'clean.txt').write_text('synthetic clean control\n')
    git_env = dict(env,GIT_AUTHOR_NAME='Fixture',GIT_AUTHOR_EMAIL='fixture@example.invalid',
                   GIT_COMMITTER_NAME='Fixture',GIT_COMMITTER_EMAIL='fixture@example.invalid')
    def git(*args):
        return execute(['git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false',
                        '-c','core.excludesFile=/dev/null','-C',str(source),*args],git_env,timeout=30)[0]
    git('init','-b','master');git('add','clean.txt');git('commit','-m','Synthetic clean control')
    control_out = output/'gitleaks-controls';control_out.mkdir()
    (control_out/'gitleaks.toml').write_text('[extend]\nuseDefault = true\n');(control_out/'empty.ignore').touch()
    clean_sha = git('rev-parse','HEAD').decode().strip()
    for mode in ('git','dir'):
        stdout,stderr = execute(gitleaks_command(binary,mode,source,control_out,clean_sha),git_env,timeout=30)
        gitleaks_evidence(read_private(control_out/(mode+'.json')),stdout+stderr,mode)
    (source/'deleted.txt').write_text('token = "'+secret+'"\n')
    git('add','deleted.txt');git('commit','-m','Synthetic secret control')
    (source/'deleted.txt').unlink();git('add','deleted.txt');git('commit','-m','Synthetic deleted control')
    sha = git('rev-parse','HEAD').decode().strip()
    for mode in ('git','dir'): (control_out/(mode+'.json')).unlink()
    def positive(mode):
        process = captured_process(gitleaks_command(binary,mode,source,control_out,sha),git_env,timeout=30)
        verify_gitleaks_control(process.returncode,process.stdout+process.stderr,
                                read_private(control_out/(mode+'.json')),secret)
    positive('git')
    # Add the secret only in a two-parent merge resolution tree.
    git('checkout','-b','control-branch')
    (source/'branch-clean.txt').write_text('synthetic branch control\n')
    git('add','branch-clean.txt');git('commit','-m','Synthetic branch control')
    git('checkout','master')
    (source/'master-clean.txt').write_text('synthetic master control\n')
    git('add','master-clean.txt');git('commit','-m','Synthetic master control')
    git('merge','--no-ff','--no-commit','control-branch')
    (source/'merge-only.txt').write_text('token = "'+secret+'" # gitleaks:allow\n')
    git('add','merge-only.txt');git('commit','-m','Synthetic merge resolution control')
    sha = git('rev-parse','HEAD').decode().strip()
    positive('dir')
    return {'deletedHistory':True,'mergeTree':True,'redactedReports':True,'redactedConsole':True,'cleanHistory':True,'cleanTree':True}


def control_report(report,allowed):
    if not isinstance(report,dict) or report.get('version') != '1.178.0' or report.get('engine_requested') != 'OSS' or not isinstance(report.get('errors'),list) or not isinstance(report.get('results'),list):
        raise ValueError('Code controls failed')
    def path(value):
        if not isinstance(value,str): raise ValueError('Code controls failed')
        if value.startswith('/src/'): value = value[5:]
        value = safe_path(value)
        if value not in allowed: raise ValueError('Code controls failed')
        return value
    try:
        scanned = report['paths']['scanned']
        if not isinstance(scanned,list): raise ValueError('Code controls failed')
        scanned = {path(value) for value in scanned}
        findings = []
        for row in report['results']:
            rule = row['check_id']
            if not isinstance(rule,str): raise ValueError('Code controls failed')
            findings.append((rule,path(row['path'])))
    except (KeyError,TypeError,AttributeError) as exc: raise ValueError('Code controls failed') from exc
    return scanned,findings


def verify_code_controls(report):
    expected = {'control.go','control.py','control.ts'}
    scanned,findings = control_report(report,expected|{'negative.ts'})
    if report['errors'] or set(findings) != {('qualification',path) for path in expected} or len(findings) != 3 or scanned != expected|{'negative.ts'}:
        raise ValueError('supported Code positive control missing')
    return dict(engine='OSS',inputs='synthetic',required=dict(status='supported',rule='qualification',targets=sorted(expected),negative='negative.ts'))


def verify_optional_control(report,status,mode):
    path,rule = {'rust':('control.rs','qualification-rust'),'vue':('control.vue','qualification-vue')}[mode]
    scanned,findings = control_report(report,{path})
    if report['errors']:
        # Pinned MissingPlugin maps to this exact JSON type and fatal status.
        # Only this isolated rule/target can authorize an unsupported limit.
        if status != 2 or findings or not all(isinstance(error,dict) and error.get('type') == 'Missing plugin' and type(error.get('code')) is int and error['code'] == 2 and error.get('level') == 'error' and error.get('rule_id') == rule and error.get('path') in (path,'/src/'+path) for error in report['errors']):
            raise ValueError('Code controls failed')
        return dict(engine='OSS',status='unsupported',target=path,rule=rule,reason='Missing plugin',processExit=2)
    if status != 0 or findings not in ([],[(rule,path)]) or findings and path not in scanned:
        raise ValueError('Code controls failed')
    return dict(engine='OSS',status='supported' if findings else 'unqualified',target=path,rule=rule)



def semgrep_controls(image,root,output):
    import shutil
    source = output/'control-source';source.mkdir()
    for name in ('control.go','control.py','control.ts'):
        shutil.copyfile(root/'scripts/ci/fixtures/security'/name,source/name)
    (source/'negative.ts').write_text('export function different(x: number, y: number): boolean { return x == y; }\n')
    command = container_command(image,source,output,root/'scripts/ci',scan=False)
    command[-1] = '--controls'
    execute(command,{'PATH':PATH,'HOME':str(output)},timeout=120,stage='semgrep-code-controls')
    report = read_private(output/'code-controls.json')
    result = verify_code_controls(report)
    for mode,name in (('rust','control.rs'),('vue','control.vue')):
        probe = output/('control-'+mode);probe.mkdir()
        shutil.copyfile(root/'scripts/ci/fixtures/security'/name,probe/name)
        command = container_command(image,probe,output,root/'scripts/ci',scan=False)
        command[-1] = '--probe-'+mode
        process = captured_process(command,{'PATH':PATH,'HOME':str(output)},timeout=120)
        report = read_private(output/('code-'+mode+'-probe.json'))
        try: result['rust' if mode=='rust' else 'vueScript'] = verify_optional_control(report,process.returncode,mode)
        except ValueError as exc:
            if process.returncode: raise ProcessFailure(process.returncode,'semgrep-'+mode+'-probe') from exc
            raise
    result['vueFramework']='not-qualified';result['vueTemplate']='not-qualified'
    return result



GITLEAKS_IDENTITY = ('RuleID','File','StartLine','EndLine','StartColumn','EndColumn','Commit','Fingerprint')
EXCEPTION_PATH = 'schemas/dsse/v1/vectors.json'
EXCEPTION_COMMIT = 'c9e1db5bf4c6f6431d5a88a07f0b0469969f515e'
EXCEPTION_DIGEST = '020860808f72ce3119a8a2c168ce57ccd98a1fd9de3f85c152f36d605c57e085'


def load_exceptions(root):
    doc = tomllib.loads((root/'scripts/ci/gitleaks-exceptions.toml').read_text())
    if set(doc) != {'version','scanner','exception'} or type(doc['version']) is not int or doc['version'] != 1 or doc['scanner'] != '8.30.1':
        raise ValueError('invalid Gitleaks exception authority')
    seen = set()
    lines = {18,44,70,96,122,148,174,187,213,226,239,252,265}
    expected = {(mode,line) for mode in ('git','dir') for line in lines}
    for row in doc['exception']:
        if set(row) != set(GITLEAKS_IDENTITY) | {'mode','blobSha256','rationale','provenance'}:
            raise ValueError('unknown Gitleaks exception field')
        mode = row['mode'];line = row['StartLine']
        identity = (mode,line)
        commit = EXCEPTION_COMMIT if mode == 'git' else ''
        fingerprint = (commit+':' if commit else '') + EXCEPTION_PATH + ':generic-api-key:' + str(line)
        if identity not in expected or identity in seen or row['RuleID'] != 'generic-api-key' or row['File'] != EXCEPTION_PATH or row['Commit'] != commit or row['Fingerprint'] != fingerprint or row['blobSha256'] != EXCEPTION_DIGEST:
            raise ValueError('unreviewed Gitleaks exception identity')
        if any(type(row[k]) is not int for k in ('StartLine','EndLine','StartColumn','EndColumn')) or row['EndLine'] != line or row['StartColumn'] != 9 or row['EndColumn'] != 30:
            raise ValueError('invalid Gitleaks exception coordinates')
        if not isinstance(row['rationale'],str) or not row['rationale'] or not isinstance(row['provenance'],str) or not row['provenance']:
            raise ValueError('missing Gitleaks exception provenance')
        seen.add(identity)
    if seen != expected: raise ValueError('missing reviewed Gitleaks exception entries')
    return doc['exception']


def exception_blobs(root, source):
    hashes = {}
    entry = routing.git(root,'ls-tree',EXCEPTION_COMMIT,'--',EXCEPTION_PATH).decode().strip()
    if entry.startswith('100644 blob ') and entry.split('\t')[-1] == EXCEPTION_PATH:
        payload = routing.git(root,'cat-file','blob',EXCEPTION_COMMIT+':'+EXCEPTION_PATH)
        hashes[('git',EXCEPTION_PATH)] = hashlib.sha256(payload).hexdigest()
    path = source/EXCEPTION_PATH
    if path.is_file() and not path.is_symlink(): hashes[('dir',EXCEPTION_PATH)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def gitleaks_gate(report,status,mode,exceptions,hashes):
    if type(status) is not int or status not in (0,1) or not isinstance(report,list) or bool(report) != (status==1):
        raise ValueError('contradictory Gitleaks status and report')
    active = {tuple(row[k] for k in GITLEAKS_IDENTITY) for row in exceptions
              if row['mode'] == mode and hashes.get((mode,row['File'])) == row['blobSha256']}
    disabled = sum(row['mode']==mode for row in exceptions) - len(active)
    seen = set();safe = [];blocking = 0
    for finding in report:
        try:
            row = {k:finding[k] for k in GITLEAKS_IDENTITY}
            if not isinstance(row['RuleID'],str) or not re.fullmatch('[A-Za-z0-9_.-]{1,200}',row['RuleID']): raise ValueError('invalid Gitleaks rule')
            if safe_path(row['File']) != row['File']: raise ValueError('Gitleaks path alias')
            for key in ('StartLine','EndLine','StartColumn','EndColumn'):
                if type(row[key]) is not int or row[key] <= 0: raise ValueError('invalid Gitleaks coordinates')
            if row['EndLine'] < row['StartLine'] or row['EndLine'] == row['StartLine'] and row['EndColumn'] < row['StartColumn']:
                raise ValueError('invalid Gitleaks coordinate range')
            if mode == 'git': routing.sha(row['Commit'])
            elif row['Commit'] != '': raise ValueError('unexpected tree commit')
            expected = (row['Commit']+':' if row['Commit'] else '')+row['File']+':'+row['RuleID']+':'+str(row['StartLine'])
            if row['Fingerprint'] != expected: raise ValueError('invalid Gitleaks fingerprint')
            identity = tuple(row[k] for k in GITLEAKS_IDENTITY)
            if identity in seen: raise ValueError('duplicate Gitleaks finding')
            seen.add(identity);safe.append(row)
            if identity not in active: blocking += 1
        except (KeyError,TypeError) as exc: raise ValueError('malformed Gitleaks finding') from exc
    if blocking: raise GateFailure('unexcepted Gitleaks finding',dict(total=len(report),excepted=len(report)-blocking,disabled=disabled,blocking=blocking,identities=safe))
    return dict(total=len(report),excepted=len(report),disabled=disabled,blocking=blocking,identities=safe)



class ProcessFailure(ValueError):
    def __init__(self,status,stage=None,output_evidence=None):
        super().__init__('scanner process failed')
        self.status=status
        self.stage=stage
        self.output_evidence=output_evidence


def captured_process(argv,env,*,timeout,cwd=None):
    try:
        process = subprocess.Popen(argv,env=env,cwd=cwd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                   start_new_session=os.name=='posix')
    except OSError as exc: raise ValueError('scanner process unavailable') from exc
    chunks = queue.Queue(maxsize=2)
    stopped = threading.Event()
    buffers = [bytearray(),bytearray()]
    deadline = time.monotonic()+timeout
    def publish(value):
        while not stopped.is_set():
            try: chunks.put(value,timeout=.05);return
            except queue.Full: pass
    def read(index,stream):
        try:
            while not stopped.is_set():
                block = stream.read1(65536)
                if not block: break
                publish((index,block))
        finally:
            stream.close()
            publish((index,None))
    readers = [threading.Thread(target=read,args=(index,stream),daemon=True)
               for index,stream in enumerate((process.stdout,process.stderr))]
    for reader in readers: reader.start()
    total = 0;finished = 0;succeeded = False
    try:
        while finished < 2:
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise ValueError('scanner timeout')
            try: index,block = chunks.get(timeout=remaining)
            except queue.Empty as exc: raise ValueError('scanner timeout') from exc
            if block is None: finished += 1;continue
            total += len(block)
            if total > MAX_CAPTURE_BYTES: raise ValueError('scanner output limit exceeded')
            buffers[index].extend(block)
        try: status = process.wait(timeout=max(0,deadline-time.monotonic()))
        except subprocess.TimeoutExpired as exc: raise ValueError('scanner timeout') from exc
        succeeded = True
        return subprocess.CompletedProcess(argv,status,bytes(buffers[0]),bytes(buffers[1]))
    finally:
        stopped.set()
        if not succeeded and os.name == 'posix':
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        elif process.poll() is None: process.kill()
        process.wait()
        for reader in readers: reader.join(timeout=1)



FAILURE_CODES = {
    'invalid Semgrep exception set':'semgrep-exception-set-invalid',
    'Semgrep exception boundary mismatch':'semgrep-exception-boundary-mismatch',
    'stale or duplicate Semgrep exception':'semgrep-exception-identity-mismatch',
    'incomplete products or upload':'products-or-upload-incomplete',
    'missing applicable Code or Supply Chain rules':'applicable-rules-missing',
    'omitted supported dependency input':'supported-dependency-input-omitted',
    'missing native dependency parser evidence':'dependency-parser-evidence-missing',
    'dependency coverage mismatch':'dependency-count-mismatch',
    'unresolved supported dependency input':'dependency-input-unresolved',
    'empty supported dependency inventory':'dependency-inventory-empty',
    'empty manifest boundary mismatch':'empty-manifest-boundary',
    'empty manifest inventory mismatch':'empty-manifest-inventory',
    'empty manifest profile mismatch':'empty-manifest-profile',
    'empty manifest native mismatch':'empty-manifest-native',
    'empty manifest qualification mismatch':'empty-manifest-qualification',
    'missing or foreign scanned targets':'scanned-targets-missing-or-foreign',
    'Semgrep scan errors or wrong version/engine':'scan-errors-or-engine-version',
    'stale observer summary':'observer-summary-stale',
    'invalid observer summary shape':'observer-summary-shape',
    'malformed or incomplete Semgrep evidence':'native-evidence-malformed',
    'active high severity findings':'active-high-findings',
    'unexcepted Gitleaks finding':'gitleaks-blocking-findings',
    'contradictory Gitleaks status and report':'gitleaks-status-report-mismatch',
    'missing Gitleaks completion evidence':'gitleaks-completion-missing',
    'Gitleaks positive control or redaction failed':'gitleaks-control-failed',
    'Gitleaks report redaction failed':'gitleaks-report-redaction-failed',
    'supported Code positive control missing':'code-positive-control-missing',
    'Code controls failed':'code-controls-failed',
    'scanner timeout':'scanner-timeout',
    'scanner output limit exceeded':'scanner-output-limit-exceeded',
    'missing or malformed native skip evidence':'native-skip-evidence-missing-or-malformed',
    'missing or malformed Code execution evidence':'code-execution-evidence-missing-or-malformed',
    'scanner process failed':'scanner-process-failed',
    'scanner process unavailable':'scanner-process-unavailable',
    'missing or oversized scanner output':'scanner-output-missing-or-oversized',
    'missing or invalid Semgrep token':'semgrep-token-missing-or-invalid',
    'fork requires reviewed maintainer replacement PR':'fork-requires-maintainer-replacement',
    'Dependabot requires maintainer replacement PR':'dependabot-requires-maintainer-replacement',
    'scanner event unsupported':'scanner-event-unsupported',
    'repository identity mismatch':'repository-identity-mismatch',
    'scanner route does not match checkout and event':'route-checkout-event-mismatch',
    'payload size or digest mismatch':'scanner-payload-digest-mismatch',
    'image digest or platform mismatch':'scanner-image-digest-platform-mismatch',
    'source differs from tested tree':'source-tested-tree-mismatch',
    'escaping source symlink':'source-symlink-escape',
    'source snapshot changed':'source-snapshot-changed',
    'unexpected submodule':'source-submodule',
    'duplicate report member':'duplicate-report-member',
    'scanner payload download failed':'scanner-download-failed',
}
OBSERVER_FAILURES = {
    'observer-identity','observer-path','observer-duplicate-start','observer-project-identity',
    'observer-products','observer-full-scan-mode','observer-scan-id','observer-completion-identity',
    'observer-incomplete-scan','observer-rule-id','observer-rule-product','observer-dependencies',
    'observer-package-version','observer-upload-incomplete','observer-scan-id-changed',
    'observer-missing-completion','observer-start-interface','observer-complete-interface',
    'observer-cli-version','observer-pro-size','observer-pro-digest','observer-pro-marker',
    'observer-pro-installation','observer-pro-version','observer-command','observer-summary-size',
    'observer-native-failure','observer-cli-exit',
    'observer-code-execution-missing','observer-code-execution-mismatch','observer-code-work-empty',
    'observer-plan-identity','observer-plan-evidence','observer-plan-rule-index','observer-plan-budget',
    'observer-core-identity','observer-core-mode','observer-core-errors','observer-core-evidence','observer-core-interface',
    'observer-control-credential',
}


class GateFailure(ValueError):
    def __init__(self,message,safe):
        super().__init__(message)
        self.safe=safe


class TargetInventoryFailure(ValueError):
    def __init__(self,targets,observed,hashes):
        super().__init__('missing or foreign scanned targets')
        reported=set(targets);observed=set(observed);source=set(hashes)
        unobserved=reported-observed;foreign=observed-source;reported_foreign=reported-source
        overlay='.semgrepignore'
        self.safe=dict(reportTargetCount=len(reported),observerTargetCount=len(observed),sourceFileCount=len(source),
            reportNotObservedCount=len(unobserved),observerNotSourceCount=len(foreign),reportNotSourceCount=len(reported_foreign),
            reportNotObservedTrackedCount=len(unobserved & source),
            reportNotObservedOverlayCount=int(overlay in unobserved-source),reportNotObservedOtherCount=len(unobserved-source-{overlay}),
            observerNotSourceOverlayCount=int(overlay in foreign),observerNotSourceOtherCount=len(foreign-{overlay}),
            reportNotSourceOverlayCount=int(overlay in reported_foreign),reportNotSourceOtherCount=len(reported_foreign-{overlay}),
            reportHasSemgrepignore=overlay in reported,observerHasSemgrepignore=overlay in observed)


def failure_code(exc):
    if type(exc) in (ValueError,ProcessFailure,GateFailure,TargetInventoryFailure) and exc.args and isinstance(exc.args[0],str):
        return FAILURE_CODES.get(exc.args[0],'security-evidence-rejected')
    if isinstance(exc,json.JSONDecodeError): return 'malformed-json-report'
    return 'security-evidence-rejected'



def runner_inputs(*,docker=False):
    result = {}
    for key in ('ImageOS','ImageVersion'):
        value = os.environ.get(key,'unavailable')
        if not re.fullmatch('[A-Za-z0-9_.+-]{1,100}',value): raise ValueError('invalid runner image metadata')
        result[key] = value
    if docker:
        stdout,_ = execute(['docker','--version'],{'PATH':PATH,'HOME':'/tmp'},timeout=30)
        value = stdout.decode().strip()
        if not re.fullmatch('[A-Za-z0-9_.+, /-]{1,200}',value): raise ValueError('invalid Docker version metadata')
        result['docker'] = value
    return result


if __name__ == '__main__': main()

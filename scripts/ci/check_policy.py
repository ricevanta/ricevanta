"""Check the reviewed workflow graph, routing inputs and receipt obligations."""
import argparse
import ast
from pathlib import Path
import re
import json
import yaml
import bootstrap
import inventory
import python_env
from required import NEEDS, CALLERS


class WorkflowLoader(yaml.BaseLoader):
    """Reject duplicate keys before structural credential checks."""
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError('duplicate or non-scalar workflow key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


SEMGREP_COMMAND = ['semgrep', 'ci', '--code', '--supply-chain', '--pro', '--no-suppress-errors',
                   '--verbose', '--disable-nosem', '--disable-version-check', '--metrics=off',
                   '--json-output=/out/semgrep.json']


def observer_command_valid(root):
    """Inspect the fixed observer arguments without executing candidate code."""
    try:
        tree = ast.parse((root / 'scripts/ci/semgrep_observer.py').read_text())
        values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'COMMAND' for target in node.targets)]
        return len(values) == 1 and ast.literal_eval(values[0]) == SEMGREP_COMMAND
    except (OSError, SyntaxError, ValueError, TypeError):
        return False

DESIGN_COMMANDS = inventory.DESIGN_COMMANDS
CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
DOWNLOAD = 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093'
VERIFIER_COMMAND = ('python -B scripts/ci/required.py --route "$RUNNER_TEMP/route.json" '
                    '--needs "$RUNNER_TEMP/needs.json" --receipts "$RUNNER_TEMP/ci-receipts"')
LEAVES = {'design': {'validate': 'design'},
          'server': {'validate': 'server-validate', 'race': 'server-race',
                     'fuzz': 'server-fuzz:${{ matrix.package }}:${{ matrix.target }}',
                     'loader-gate-a': 'loader', 'loader-gate-b': 'loader-gate-b', 'ocsf-native': 'ocsf'},
          'agent': {'validate': 'agent', 'rustinterop': 'interop'},
          'console': {'validate': 'console'}, 'bootstrap': {'validate': 'bootstrap'},
          'ci': {'ci-contracts': 'ci-contracts'}}

# Task 2 receipts prove step success. Keep the existing commands behind each
# declared ID until Task 4 replaces selected execution with audited wrappers.
COMMANDS = {
    ('server', 'validate'): ('gofmt -l .', 'go test -count=1 ./...', 'go vet ./...',
                            "go test -run '^$' -bench '^BenchmarkValidate$' -benchmem -benchtime=100x ./internal/signing/ed25519key"),
    ('server', 'race'): ('go test -race -count=1 -timeout=15m ./...',),
    ('server', 'fuzz'): ('go test -count=1 "$FUZZ_PACKAGE" -fuzz="^${FUZZ_TARGET}$" -fuzztime=60s -parallel=2',),
    ('server', 'loader-gate-a'): ("go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetExtended$' -v -args -loader-budget-extended",
        "go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetSmoke$' -v -args -loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50",
        "go test -count=1 ./internal/extensions/loader -fuzz='^FuzzParserQualification$' -fuzztime=60s -parallel=2"),
    ('server', 'loader-gate-b'): ("go test -count=1 ./internal/extensions/loader -run '^TestLoaderBudgetExtended$' -v -args -loader-budget-extended",),
    ('server', 'ocsf-native'): ('go test -count=1 ./internal/events/ocsf',),
    ('agent', 'validate'): ('cargo metadata --locked --format-version 1', 'python tools/generate-spool-fixtures.py --check',
        'cargo fmt --all -- --check', 'cargo clippy --locked --workspace --all-targets -vv -- -D warnings',
        'cargo test --locked --workspace',
        'cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact',
        'cargo test --locked -p ricevanta-batch --test fuzz_seal fuzz_seal_extended -- --ignored --exact'),
    ('agent', 'rustinterop'): ('cargo build --locked -p ricevanta-batch --example seal-vector -vv',
        "go test -v -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1",
        "go test -v -race -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1"),
    ('console', 'validate'): ('pnpm install --frozen-lockfile', 'pnpm typecheck', 'pnpm lint',
        'pnpm format:check', 'pnpm audit:deps', 'pnpm test:unit', 'pnpm test:component',
        'pnpm build', 'pnpm check:reproducible', 'pnpm test:csp', 'pnpm test:fuzz'),
    ('ci', 'ci-contracts'): ("python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v",
        'python -B scripts/ci/check_policy.py --root .'),
    ('bootstrap', 'validate'): ("python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v",
        'schemas/ci/v1/contracts.schema.json', 'schemas/ci/v1/examples.json', 'scripts/ci/toolchains.lock.json'),
}


CACHE = 'actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9'
# Every toolchain comes from the reviewed lock through one exact bootstrap step; setup actions and
# ad hoc installers fetch unchecked payloads and are forbidden everywhere.
BOOTSTRAP_COMMAND = ('python3 -B scripts/ci/bootstrap.py --lock scripts/ci/toolchains.lock.json --platform "$CI_PLATFORM" '
                     '--tools "$CI_TOOLS" --dest "$RUNNER_TEMP/admitted" --cache-mode none --env-out "$RUNNER_TEMP/tools.env"')
# The plan's interface writes the admitted environment to a file; one exact step then applies it for later steps.
APPLY_COMMAND = 'cat "$RUNNER_TEMP/tools.env" >> "$GITHUB_ENV"'
APPLY_NAME = 'Apply admitted toolchain environment'
EVIDENCE_COMMAND = ('python3 -B scripts/ci/bootstrap/controls.py evidence --lock scripts/ci/toolchains.lock.json --platform "$CI_PLATFORM" '
                    '--tools "$CI_TOOLS" --evidence "$RUNNER_TEMP/admitted/bootstrap-evidence.json"')
CONTROLS_COMMAND = ('python3 -B scripts/ci/bootstrap/controls.py corrupt --lock scripts/ci/toolchains.lock.json --platform "$CI_PLATFORM" '
                    '--tools "$CI_TOOLS" --work "$RUNNER_TEMP/bootstrap-controls"')
PLATFORM_EXPRESSION = '${{ fromJSON(\'{"ubuntu-24.04":"linux-x64","windows-2025":"windows-x64","macos-15":"macos-arm64"}\')[matrix.os] }}'
ALLOWED_ACTIONS = (CHECKOUT, UPLOAD, DOWNLOAD, CACHE)
UNCHECKED_DOWNLOAD = re.compile(r'\brustup\b|\bplaywright install\b|\bcorepack\b|\bapt(?:-get)?\s+install\b|\bbrew\s+install\b|\bchoco\b|'
                                r'\bwinget\b|\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b|Start-BitsTransfer|'
                                r'\bbitsadmin\b|\bcertutil\b|\bnpm\s+(?:i|install|exec|x)\b|\bnpx\b|\bpnpx\b|\bpnpm\s+(?:dlx|create|env|self-update)\b|'
                                r'\bpnpm\s+(?:add|install|i)\s+(?:-g|--global)\b|--pm-on-fail|\bgh\s+(?:release|run|attestation)\s+download\b|'
                                r'\bgh\s+api\b|\bgit\s+clone\b|\burllib\.request\b|\burllib3\b|\burlretrieve\b|\burlopen\b|\bhttp\.client\b|\brequests\.|'
                                r'\bWebClient\b|\bDownload(?:File|String|Data)(?:Async)?\b|\bHttpClient\b|\bInvoke-WebRequest\b|'
                                r'\brequire\(\s*[\'"](?:node:)?https?[\'"]\s*\)|\bimport\(\s*[\'"](?:node:)?https?[\'"]\s*\)|'
                                r'\bfrom\s+[\'"](?:node:)?https?[\'"]|\bhttps?\.(?:get|request)\(|'
                                r'\bfetch\(|\bgo\s+(?:install|get)\b|\bcargo\s+(?:install|binstall)\b|\bpip\s+download\b')
TOOL_CONSUMERS = (('python', re.compile(r'\bpython3?\b')), ('go', re.compile(r'\bgo(?:fmt)?\s')),
                  ('rust', re.compile(r'\bcargo\b|\brustc\b|\brustfmt\b')), ('node', re.compile(r'\bnode\b|\bpnpm\b')),
                  ('pnpm', re.compile(r'\bpnpm\b')), ('playwright', re.compile(r'pnpm test:(?:component|csp)|\bplaywright\b')))
# Variables bootstrap.py writes through --env-out, and loader or interpreter hooks that would substitute other code
# for an admitted tool; no other step or env mapping may set them. Whole families are closed by prefix.
ADMITTED_ENV = frozenset({'PATH', 'Path', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT', 'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES',
                          'DYLD_FRAMEWORK_PATH', 'RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CI_ADMITTED_ROOT',
                          'GOROOT', 'GOTOOLCHAIN', 'NODE_OPTIONS', 'NODE_PATH', 'COREPACK_ENABLE_STRICT'})
ADMITTED_ENV_PREFIXES = ('PLAYWRIGHT_', 'RUSTUP_', 'COREPACK_', 'pnpm_config_', 'npm_config_', 'PNPM_', 'NPM_CONFIG_')
ADMITTED_ENV_WRITE = re.compile(r'(?<![A-Za-z0-9_])(?:' + '|'.join(sorted(ADMITTED_ENV)) + '|'
                                + '|'.join(p + r'\w*' for p in ADMITTED_ENV_PREFIXES) + r')\s*=')


def admitted_env_names(mapping):
    if not isinstance(mapping, dict): return []
    return sorted(k for k in mapping if k in ADMITTED_ENV or str(k).startswith(ADMITTED_ENV_PREFIXES))
BOOTSTRAP_NAME = 'Bootstrap admitted toolchains'
EVIDENCE_NAME = 'Verify admitted toolchain evidence'
CONTROLS_NAME = 'Reject corrupted payloads before any extraction or execution'
# Only these three exact steps may touch installers, environments or the helper; any step that merely names an
# installer, environment manager or the helper is rejected at token level, whatever its flag order. Shell indirection
# and third-party actions stay outside this source-level rule; the terminal re-check covers what lands in the venv.
ADMITTED_PYTHON_RUNS = frozenset({python_env.VENV_COMMAND, python_env.INSTALL_COMMAND, python_env.CHECK_COMMAND})
BYPASS_TOKEN = re.compile(r'(?<![\w.-])(?:pip3?|venv|ensurepip|virtualenv|uvx?|pipx|pipenv|poetry|conda|mamba|micromamba|'
                          r'pdm|hatch|rye|pixi|python_env\.py)(?![\w-])')
# These commands import the closure, so the admitted install must precede them in the job.
CLOSURE_CONSUMERS = tuple(inventory.DESIGN_COMMANDS) + (
    'scripts/ci/check_policy.py', 'unittest discover -s scripts/ci', 'unittest discover -s schemas', 'test_validate.py',
    'test_key_admission_contract.py', 'required.py --route "$RUNNER_TEMP/route.json" --needs',
    'from jsonschema import', 'import jsonschema', 'import yaml')
TOKEN = '${{ secrets.SEMGREP_APP_TOKEN }}'
ROUTE_ENV = {'ROUTE_JSON': '${{ needs.route.outputs.route }}'}
PREPARE_ROUTE = ("python -B - <<'PY'\n"
                 "import os, pathlib\n"
                 "(pathlib.Path(os.environ['RUNNER_TEMP']) / 'route.json').write_text(os.environ['ROUTE_JSON'])\n"
                 "PY\n")


def scanner_command(unit, phase):
    suffix = '-' + phase if phase in ('preflight', 'admission') else ''
    return (f'python -B scripts/ci/security_scan.py {unit} --phase {phase} --root . '
            f'--route "$RUNNER_TEMP/route.json" --output "$RUNNER_TEMP/security-{unit}{suffix}"')


def scanner_job(unit):
    """Closed workflow recipe: token-free admission precedes the sole scan step."""
    steps = [
        {'uses': CHECKOUT, 'with': {'persist-credentials': 'false', 'fetch-depth': '0',
                                  'ref': '${{ fromJSON(needs.route.outputs.route).testedSha }}'}},
        *bootstrap_steps('linux-x64', 'python'),
        {'id': 'preflight', 'shell': 'bash', 'working-directory': '.', 'env': ROUTE_ENV,
         'run': PREPARE_ROUTE + scanner_command(unit, 'preflight') + '\n'},
    ]
    if unit == 'semgrep':
        steps.append({'id': 'admission', 'shell': 'bash', 'working-directory': '.',
                      'run': scanner_command(unit, 'admission')})
    scan = {'id': 'scan', 'shell': 'bash', 'working-directory': '.',
            'run': scanner_command(unit, 'scan')}
    if unit == 'semgrep': scan['env'] = {'SEMGREP_APP_TOKEN': TOKEN}
    steps.append(scan)
    phases = ['-preflight', '-admission', ''] if unit == 'semgrep' else ['-preflight', '']
    steps.append({'id': 'diagnostics', 'if': '${{ always() }}', 'uses': UPLOAD,
                  'with': {'name': 'security-diagnostics-${{ github.run_id }}-${{ github.run_attempt }}-' + unit,
                           'path': '\n'.join('${{ runner.temp }}/security-' + unit + phase + '/diagnostics.json'
                                             for phase in phases),
                           'retention-days': '30', 'if-no-files-found': 'error'}})
    checks = json.dumps(inventory.checks(unit))
    steps.append({'id': 'proof', 'shell': 'bash', 'working-directory': '.',
                  'run': scanner_command(unit, 'verify') + '\n' +
                         'python -B scripts/ci/required.py --route "$RUNNER_TEMP/route.json" '
                         f"--emit-unit {unit} --checks '{checks}' " +
                         '--out "$RUNNER_TEMP/ci-proof/receipt.json"\n'})
    steps.append({'uses': UPLOAD, 'with': {
        'name': '${{ steps.proof.outputs.artifact }}', 'path': '${{ runner.temp }}/ci-proof/receipt.json',
        'retention-days': '30', 'if-no-files-found': 'error'}})
    return {'needs': ['route'], 'runs-on': 'ubuntu-24.04',
            'timeout-minutes': '20' if unit == 'semgrep' else '15', 'steps': steps}


def bootstrap_steps(platform, tools):
    env = {'CI_PLATFORM': platform, 'CI_TOOLS': tools}
    return [{'name': BOOTSTRAP_NAME, 'shell': 'bash', 'working-directory': '.', 'env': dict(env), 'run': BOOTSTRAP_COMMAND},
            {'name': APPLY_NAME, 'shell': 'bash', 'working-directory': '.', 'run': APPLY_COMMAND},
            {'name': EVIDENCE_NAME, 'shell': 'bash', 'working-directory': '.', 'env': dict(env), 'run': EVIDENCE_COMMAND}]


def lock_tools(root):
    try:
        lock = bootstrap.load_lock(root / bootstrap.LOCK)
    except bootstrap.BootstrapError:
        return {}
    tools = {}
    for entry in lock['entries']: tools.setdefault(entry['platform'], set()).add(entry['tool'])
    return tools


LOCK_TOOLS = {}


def consumer_tools(steps):
    text = '\n'.join(s.get('run', '') for s in steps)
    return {tool for tool, pattern in TOOL_CONSUMERS if pattern.search(text)}


def resolve_tools(value, job):
    """A literal comma list, or `${{ matrix.tools }}` over literal include rows (tools common to every row)."""
    if value == '${{ matrix.tools }}':
        matrix = job.get('strategy', {}).get('matrix', {})
        rows = matrix.get('include', []) if isinstance(matrix, dict) else []
        values = [row.get('tools') for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
        if not values or len(values) != len(rows): return None
        common = None
        for row_value in values:
            tools = resolve_tools(row_value, job)
            if tools is None: return None
            common = tools if common is None else common & tools
        return common
    if not isinstance(value, str) or '${{' in value: return None
    try:
        bootstrap.expand_tools(value)
    except bootstrap.BootstrapError:
        return None
    return set(value.split(','))


def bootstrap_errors(data, name):
    """One exact admitted bootstrap per job, first after checkout, covering every tool the job runs; no unchecked fetch."""
    errors = []
    for jid, job in data.get('jobs', {}).items():
        if 'uses' in job: continue
        steps = job.get('steps', [])
        def fail(message): errors.append(f'{jid}: {message}')
        for step in steps:
            action = step.get('uses', '')
            if action and not action.startswith('./') and action not in ALLOWED_ACTIONS: fail('unchecked setup action: ' + action)
            if UNCHECKED_DOWNLOAD.search(step.get('run', '')): fail('unchecked download or install command')
        for scope in (data, job):
            env = scope.get('env', {})
            if isinstance(env, dict) and {'CI_PLATFORM', 'CI_TOOLS'} & set(env): fail('bootstrap inputs must be literal step env')
        # Only the admitted bootstrap sets PATH and tool variables; only the admitted venv step prepends to PATH.
        for scope in (data, job, *steps):
            for key in admitted_env_names(scope.get('env', {})): fail('admitted tool environment override forbidden: ' + key)
        for step in steps:
            run = step.get('run', '')
            if 'GITHUB_PATH' in run and run != python_env.VENV_COMMAND: fail('PATH changes outside the admitted bootstrap forbidden')
            # Quotes and escapes cannot split a variable name past the check: "GO""ROOT=" is GOROOT=.
            if 'GITHUB_ENV' in run and run != APPLY_COMMAND and ADMITTED_ENV_WRITE.search(re.sub(r'["\'\\`]', '', run)):
                fail('admitted tool environment override forbidden')
            if 'tools.env' in run and run not in (BOOTSTRAP_COMMAND, APPLY_COMMAND): fail('the admitted environment file is written and applied only by its exact steps')
        bootstraps = [i for i, s in enumerate(steps) if s.get('run') == BOOTSTRAP_COMMAND]
        if any('scripts/ci/bootstrap.py' in s.get('run', '') for i, s in enumerate(steps) if i not in bootstraps):
            fail('missing exact bootstrap command')
        helpers = {BOOTSTRAP_COMMAND, APPLY_COMMAND, EVIDENCE_COMMAND, CONTROLS_COMMAND}
        consumers = [s for s in steps if s.get('run') not in helpers]
        required = consumer_tools(consumers)
        if not bootstraps and not required: continue
        if len(bootstraps) != 1:
            fail('exactly one admitted bootstrap step required'); continue
        index = bootstraps[0]
        step = steps[index]
        env = step.get('env', {})
        if (set(step) != {'name', 'shell', 'working-directory', 'env', 'run'} or step.get('name') != BOOTSTRAP_NAME or step.get('shell') != 'bash'
                or step.get('working-directory') != '.' or not isinstance(env, dict) or set(env) != {'CI_PLATFORM', 'CI_TOOLS'}):
            fail('bootstrap step must be unconditional at root with bash and literal CI_PLATFORM and CI_TOOLS'); continue
        runner = job.get('runs-on', '')
        expected_platform = PLATFORM_EXPRESSION if '${{' in str(runner) else inventory.HOSTS.get(runner)
        if env['CI_PLATFORM'] != expected_platform: fail('CI_PLATFORM must come from the fixed runner matrix')
        selected = resolve_tools(env['CI_TOOLS'], job)
        if selected is None:
            fail('CI_TOOLS must be a literal tool list from the workflow'); selected = set()
        expanded = set(bootstrap.expand_tools(','.join(sorted(selected)))) if selected else set()
        for tool in sorted(required):
            if {'rust': 'rustc', 'playwright': 'chromium-headless-shell'}.get(tool, tool) not in expanded: fail('bootstrap tools omit ' + tool)
        apply = {'name': APPLY_NAME, 'shell': 'bash', 'working-directory': '.', 'run': APPLY_COMMAND}
        if not (index + 1 < len(steps) and steps[index + 1] == apply) or sum(s.get('run') == APPLY_COMMAND for s in steps) != 1:
            fail('the exact admitted environment step must directly follow the bootstrap step')
        if not (index + 2 < len(steps) and steps[index + 2] == {**step, 'name': EVIDENCE_NAME, 'run': EVIDENCE_COMMAND}):
            fail('admitted toolchain evidence step must follow the bootstrap step')
        if name == 'bootstrap':
            # The bootstrap leaves cold-install every payload the lock holds for their host, so dropping one is visible.
            for row in job.get('strategy', {}).get('matrix', {}).get('include', []) or []:
                platform = inventory.HOSTS.get(row.get('os')) if isinstance(row, dict) else None
                try:
                    chosen = set(bootstrap.expand_tools(row.get('tools', ''))) if platform else None
                except bootstrap.BootstrapError:
                    chosen = None
                if chosen != LOCK_TOOLS.get(platform): fail(f'bootstrap matrix row {row.get("os")!r} must select every lock tool for its host')
        controls = {**step, 'name': CONTROLS_NAME, 'run': CONTROLS_COMMAND}
        for s in steps[:index]:
            if s.get('uses', '').startswith('actions/checkout@') or (name == 'bootstrap' and s == controls): continue
            fail('bootstrap must precede every step except checkout')
        if name == 'bootstrap' and (sum(s == controls for s in steps) != 1 or index == 0 or steps[index - 1] != controls):
            fail('exact corruption controls must precede the cold install')
    return errors


def package_manager_errors(root):
    """pnpm and Node come only from the admitted bootstrap: no project setting may let pnpm switch or download either."""
    errors = []
    console = root / 'console'
    try:
        manifest = json.loads((console / 'package.json').read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return ['console/package.json: unreadable']
    def walk(value, path):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == 'onFail' and child != 'error': errors.append(f'console/package.json: {path}.onFail must be error')
                walk(child, f'{path}.{key}')
        elif isinstance(value, list):
            for child in value: walk(child, path)
    walk(manifest.get('devEngines', {}), 'devEngines')
    runtime = (manifest.get('devEngines') or {}).get('runtime') if isinstance(manifest.get('devEngines'), dict) else None
    if runtime is not None: errors.append('console/package.json: devEngines.runtime can download Node; Node comes from the admitted bootstrap')
    for name in ('pnpm-workspace.yaml', '.npmrc'):
        try:
            text = (console / name).read_text(encoding='utf-8')
        except OSError:
            continue
        for match in re.finditer(r'(?im)^\s*(pmOnFail|pm-on-fail|managePackageManagerVersions|manage-package-manager-versions|'
                                 r'packageManagerStrict\w*|package-manager-strict\S*|useNodeVersion|use-node-version|nodeVersion|node-version)\s*[:=]\s*(\S+)', text):
            key, value = match[1], match[2].strip('\'"')
            if not (key.lower() in ('pmonfail', 'pm-on-fail') and value == 'error'):
                errors.append(f'console/{name}: {key} {value} lets pnpm switch versions or download a runtime')
    return errors


def secret_errors(data, name):
    """Allow one literal credential leaf; deny every other secret use or mapping."""
    errors = []
    allowed = ('jobs', 'semgrep', 'steps', 'scan', 'env', 'SEMGREP_APP_TOKEN')
    def walk(value, path=()):
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = path + (key,)
                if key == 'secrets': errors.append('secret mappings and inheritance are forbidden')
                if key == 'SEMGREP_APP_TOKEN' and not (name == 'ci' and child_path == allowed and child == TOKEN):
                    errors.append('token environment is outside the sole scan scope')
                if re.search(r'\bsecrets\b', str(key), re.I): errors.append('secret expression in mapping key')
                walk(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                identifier = child.get('id', index) if path == ('jobs', 'semgrep', 'steps') and isinstance(child, dict) else index
                walk(child, path + (identifier,))
        elif re.search(r'\bsecrets\b|SEMGREP_APP_TOKEN', str(value), re.I):
            if not (name == 'ci' and path == allowed and value == TOKEN):
                errors.append('secret reference is outside the sole scan environment')
    walk(data)
    return errors


def group_condition(groups, source):
    return '${{ ' + ' || '.join(f"contains(fromJSON({source}).groups, '{g}')" for g in groups) + ' }}'


def run_defaults(scope):
    """Distinguish omitted run defaults from malformed explicit settings."""
    defaults = scope.get('defaults', {})
    if not isinstance(defaults, dict): return None
    run = defaults.get('run', {})
    return run if isinstance(run, dict) else None


def windows_rows(job):
    """Include unresolved runner expressions conservatively."""
    runner = job.get('runs-on', '')
    if isinstance(runner, str):
        axis = re.fullmatch(r'\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}', runner)
        if axis:
            matrix = job.get('strategy', {}).get('matrix', {})
            if not isinstance(matrix, dict): return True
            values = matrix.get(axis[1], [])
            if not isinstance(values, list): return True
            values = values + [row[axis[1]] for row in matrix.get('include', []) if axis[1] in row]
            return not values or any('windows' in str(value).lower() or '${{' in str(value) for value in values)
    return 'windows' in str(runner).lower() or '${{' in str(runner)


GO_FRESH = 'python -B scripts/ci/fresh_go.py --root "$RUNNER_TEMP/go-fresh" --env-out "$GITHUB_ENV"'
CARGO_FRESH = ('python -B scripts/ci/fresh_go.py --root "$RUNNER_TEMP/cargo-fresh" --env-out "$GITHUB_ENV" '
               '--cargo-home "$CARGO_HOME" --cargo-lock "$PWD/agent/Cargo.lock"')
# Cargo's home is the admitted, bin-free CARGO_HOME from the bootstrap; only its registry index and archives are cached.
CARGO_CACHE_PATHS = ['${{ runner.temp }}/admitted/cargo-home/registry/index', '${{ runner.temp }}/admitted/cargo-home/registry/cache']
CACHE_ENV = {'GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOFLAGS', 'CARGO_TARGET_DIR', 'CARGO_HOME'}


def cache_errors(data):
    """Require fresh compiler environments before every workflow consumer."""
    errors = []
    for jid, job in data.get('jobs', {}).items():
        steps = job.get('steps', [])
        def fail(message): errors.append(f'{jid}: {message}')
        for scope in (data, job, *steps):
            if CACHE_ENV & set(scope.get('env', {})):
                fail('compiler cache environment override forbidden')
        go_setups = [i for i, s in enumerate(steps) if s.get('uses', '').startswith('actions/setup-go@')]
        go_consumers = [i for i, s in enumerate(steps) if re.search(r'\bgo (?:test|vet|env|mod|build|run)\b', s.get('run', ''))]
        cargo_consumers = [i for i, s in enumerate(steps) if re.search(r'\bcargo (?:metadata|build|test|clippy|fetch)\b', s.get('run', ''))]
        for step in steps:
            action = step.get('uses', '')
            settings = step.get('with', {})
            if action.startswith('actions/setup-go@') and (settings.get('cache') != 'false' or 'cache-dependency-path' in settings):
                fail('setup-go cache must be disabled')
            if action.startswith('actions/cache'):
                paths = settings.get('path', '').strip().splitlines()
                if paths != CARGO_CACHE_PATHS:
                    fail('cache restore may contain only Cargo index and archives')
            run = step.get('run', '')
            if re.search(r'\benv\s+-i\b|\bunset\s+(?:GOCACHE|GOMODCACHE|GOFLAGS|GOTOOLCHAIN|CARGO_TARGET_DIR|CARGO_HOME)\b|\b(?:GOCACHE|GOMODCACHE|GOFLAGS|GOTOOLCHAIN|CARGO_TARGET_DIR|CARGO_HOME)\s*=', run):
                fail('compiler cache environment reset forbidden')
        def admission(command, consumers):
            matching = [i for i, s in enumerate(steps) if s.get('run') == command]
            if len(matching) != 1:
                fail('missing exact fresh cache admission command')
                return None
            index = matching[0]
            step = steps[index]
            if any(k in step for k in ('if', 'continue-on-error')) or step.get('shell') != 'bash' or step.get('working-directory') != '.':
                fail('fresh cache admission must be unconditional at root with bash')
            if consumers and index >= min(consumers):
                fail('fresh cache admission must precede consumers')
            return index
        if go_setups or go_consumers:
            index = admission(GO_FRESH, go_consumers)
            modules = [i for i, s in enumerate(steps) if s.get('run') == 'go mod download\ngo mod verify\n']
            if len(modules) != 1 or index is None or modules[0] <= index:
                fail('fresh module cache download and verification required')
            else:
                step = steps[modules[0]]
                if step.get('working-directory') != 'server' or any(k in step for k in ('if', 'continue-on-error')):
                    fail('module cache verification must be unconditional in server')
                if any(i < modules[0] for i in go_consumers):
                    fail('Go consumer precedes module cache verification')
        if cargo_consumers or any(s.get('run') == CARGO_FRESH for s in steps):
            index = admission(CARGO_FRESH, cargo_consumers)
            if index is not None and any(i > index for i, s in enumerate(steps) if s.get('uses', '').startswith('actions/cache')):
                fail('Cargo cache restore must precede integrity admission')
    return errors


def python_env_keys(mapping):
    if not isinstance(mapping, dict): return []
    return [k for k in mapping if (str(k).startswith('PYTHON') and k not in python_env.ALLOWED_PYTHON_ENV) or str(k).startswith('PIP_')]


def python_errors(data):
    """One admitted Python, one fresh venv, one hash-locked install and one terminal re-check per closure consumer."""
    errors = []
    consuming_workflow = False
    for jid, job in data.get('jobs', {}).items():
        steps = job.get('steps', [])
        def fail(message): errors.append(f'{jid}: {message}')
        setups = [i for i, s in enumerate(steps) if s.get('run') == BOOTSTRAP_COMMAND]
        venvs = [i for i, s in enumerate(steps) if s.get('run') == python_env.VENV_COMMAND]
        installs = [i for i, s in enumerate(steps) if s.get('run') == python_env.INSTALL_COMMAND]
        checks = [i for i, s in enumerate(steps) if s.get('run') == python_env.CHECK_COMMAND]
        for step in steps:
            run = step.get('run', '')
            if run in ADMITTED_PYTHON_RUNS: continue
            if BYPASS_TOKEN.search(run) or 'requirements-design.txt' in run:
                fail('ad hoc Python environment or package installation forbidden')
        consumers = [i for i, s in enumerate(steps) if any(c in s.get('run', '') for c in CLOSURE_CONSUMERS)]
        if not (venvs or installs or checks or consumers): continue
        consuming_workflow = True
        if len(venvs) != 1 or len(installs) != 1 or not setups or not setups[0] < venvs[0] < installs[0]:
            fail('closure consumer requires the admitted bootstrap, one fresh venv and one hash-locked install in order')
        else:
            if any(i < installs[0] for i in consumers):
                fail('validator runs before the hash-locked closure is admitted')
            if any(i > venvs[0] for i in setups):
                fail('Python setup after the validator venv forbidden')
            proofs = [i for i, s in enumerate(steps) if s.get('id') == 'proof']
            boundary = proofs[0] if proofs else len(steps) - 1 if jid == 'ci-required' else len(steps)
            python_steps = [i for i, s in enumerate(steps) if i < boundary and re.search(r'\bpython\b', s.get('run', ''))]
            if len(checks) != 1 or checks[0] <= installs[0] or not python_steps or python_steps[-1] != checks[0]:
                fail('terminal re-check must be the last Python step before the receipt')
        for i in venvs + installs + checks:
            step = steps[i]
            if any(k in step for k in ('if', 'continue-on-error')) or step.get('shell') != 'bash' or step.get('working-directory') != '.':
                fail('closure admission steps must be unconditional at root with bash')
        for scope in (job, *steps):
            for key in python_env_keys(scope.get('env', {})):
                fail(f'interpreter or installer environment forbidden in closure consumer: {key}')
        for step in steps:
            run = step.get('run', '')
            if 'GITHUB_PATH' in run and run != python_env.VENV_COMMAND:
                fail('PATH changes outside the admitted venv step forbidden in closure consumer')
            # The admitted bootstrap step writes PATH and tool variables once, before the venv; bootstrap_errors
            # closes its name, keys, inputs and position.
            if 'GITHUB_ENV' in run and run not in (GO_FRESH, CARGO_FRESH, APPLY_COMMAND):
                fail('environment writes outside the fresh cache helper and admitted bootstrap forbidden in closure consumer')
    if consuming_workflow:
        for key in python_env_keys(data.get('env', {})):
            errors.append(f'workflow: interpreter or installer environment forbidden in closure consumer: {key}')
    return errors


def fuzz_evidence_errors(job, native_parser=False):
    """Preserve exact fuzz selection, failure exit and minimized corpora."""
    command = COMMANDS[('server', 'loader-gate-a' if native_parser else 'fuzz')][-1]
    selected = [step for step in job.get('steps', []) if '-fuzz=' in step.get('run', '')]
    expected = ({'name': 'Fuzz parser qualification for 60 seconds', 'run': command} if native_parser else
                {'name': 'Fuzz for 60 seconds', 'env': {'FUZZ_PACKAGE': '${{ matrix.package }}',
                                                      'FUZZ_TARGET': '${{ matrix.target }}'}, 'run': command})
    errors = []
    if selected != [expected]: errors.append('exact unconditional fuzz command required')
    corpus = {'name': 'Upload failing corpus', 'if': 'failure()', 'uses': UPLOAD,
              'with': {'name': 'loader-gate-a-${{ matrix.os }}' if native_parser else 'go-fuzz-${{ strategy.job-index }}-${{ matrix.target }}',
                       'path': 'server/internal/extensions/loader/testdata/fuzz/FuzzParserQualification/**' if native_parser else 'server/${{ matrix.package }}/testdata/fuzz/${{ matrix.target }}/**',
                       'if-no-files-found': 'ignore', 'retention-days': '30'}}
    if sum(step == corpus for step in job.get('steps', [])) != 1:
        errors.append('exact failure corpus upload required')
    return errors


def loader_qualification_errors(job, gate):
    """Keep qualification commands and diagnostic success gates closed."""
    errors = []
    steps = job.get('steps', [])
    jid = 'loader-gate-' + gate
    def fail(message): errors.append(jid + ': ' + message)
    if job.get('name') != 'loader Gate ' + gate.upper() + ' (${{ matrix.os }})' or job.get('runs-on') != '${{ matrix.os }}':
        fail('exact native job identity required')
    if job.get('timeout-minutes') != ('15' if gate == 'a' else '20'):
        fail('qualification timeout mismatch')
    if job.get('defaults') != {'run': {'shell': 'bash', 'working-directory': 'server'}}:
        fail('qualification requires literal Bash in server')
    if job.get('strategy') != {'fail-fast': 'false', 'matrix': {'os': list(inventory.HOSTS)}}:
        fail('qualification requires all three independent native rows')
    recipes = ([('Extended parser budget', 'extended', COMMANDS[('server', jid)][0]),
                ('Repeat affected parser measurement 50 times', 'repeat', COMMANDS[('server', jid)][1])]
               if gate == 'a' else [('Extended loader budget', 'extended', COMMANDS[('server', jid)][0])])
    indices = []
    for name, log, command in recipes:
        run = ('set -euo pipefail\n'
               f'mkdir -p "$RUNNER_TEMP/loader-measurements-gate-{gate}"\n'
               f'{command} 2>&1 | tee "$RUNNER_TEMP/loader-measurements-gate-{gate}/{log}.log"\n')
        matches = [i for i, step in enumerate(steps) if step == {'name': name, 'run': run}]
        if len(matches) != 1: fail('exact unconditional measurement pipeline required: ' + log)
        else: indices += matches
    log_paths = [f'${{{{ runner.temp }}}}/loader-measurements-gate-{gate}/{log}.log' for _, log, _ in recipes]
    verify_run = 'set -euo pipefail\n' + ''.join(
        f'test -s "$RUNNER_TEMP/loader-measurements-gate-{gate}/{log}.log"\n' for _, log, _ in recipes)
    verify = {'name': 'Verify loader measurement logs', 'if': 'always()', 'run': verify_run}
    upload = {'name': 'Upload loader measurements', 'if': 'always()', 'uses': UPLOAD,
              'with': {'name': 'loader-measurements-${{ github.run_id }}-${{ github.run_attempt }}-gate-' + gate + '-${{ matrix.os }}',
                       'path': '\n'.join(log_paths) + ('\n' if len(log_paths) > 1 else ''),
                       'retention-days': '30', 'if-no-files-found': 'error'}}
    verify_indices = [i for i, step in enumerate(steps) if step == verify]
    uploads = [i for i, step in enumerate(steps) if step == upload]
    proof_indices = [i for i, step in enumerate(steps) if step.get('id') == 'proof']
    if len(verify_indices) != 1 or len(uploads) != 1 or len(proof_indices) != 1:
        fail('mandatory complete measurement logs and diagnostic upload required')
    elif not (max(indices, default=-1) < verify_indices[0] < uploads[0] < proof_indices[0] == len(steps) - 2):
        fail('diagnostic verification/upload must precede terminal success proof')
    if len(proof_indices) == 1:
        proof = steps[proof_indices[0]]
        unit = 'loader' if gate == 'a' else 'loader-gate-b'
        if proof.get('env') != {'ROUTE_JSON': '${{ inputs.route }}', 'UNIT': unit,
                                'CHECKS': json.dumps(inventory.checks(unit + ':linux-x64')),
                                'HOST_OS': '${{ matrix.os }}'}:
            fail('exact native receipt identity required')
    host_run = ("python - <<'PY'\n"
                "import os, platform, sys\n"
                "sys.path.insert(0, 'scripts/ci')\n"
                "from inventory import HOSTS\n"
                "expected = HOSTS[os.environ['HOST_OS']]\n"
                "actual = {'Linux': 'linux', 'Windows': 'windows', 'Darwin': 'macos'}[platform.system()]\n"
                "arch = {'x86_64': 'x64', 'AMD64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]\n"
                "assert actual + '-' + arch == expected, (actual, arch, expected)\n"
                "PY\n")
    host = {'name': 'Assert native receipt host', 'shell': 'bash', 'working-directory': '.',
            'env': {'HOST_OS': '${{ matrix.os }}'}, 'run': host_run}
    if sum(step == host for step in steps) != 1:
        fail('exact native host assertion required')
    return errors


def check(root: Path) -> list[str]:
    errors = []
    LOCK_TOOLS.clear(); LOCK_TOOLS.update(lock_tools(root))
    def fail(name, message): errors.append(f'.github/workflows/{name}.yml: {message}')
    workflows = {}
    for path in sorted((root / '.github/workflows').glob('*.yml')):
        name = path.stem
        try:
            data = yaml.load(path.read_text(), Loader=WorkflowLoader)
            if not isinstance(data, dict): raise ValueError('not a mapping')
            workflows[name] = data
        except (ValueError, yaml.YAMLError):
            fail(name, 'malformed workflow'); continue
        for error in cache_errors(data): fail(name, error)
        for error in python_errors(data): fail(name, error)
        for error in bootstrap_errors(data, name): fail(name, error)
        if name.startswith('diagnose-'): fail(name, 'remove diagnosis before landing')
        # Optional Copilot setup has its own event, but receives no required-check authority.
        for error in secret_errors(data, name): fail(name, error)
        if name == 'copilot-code-review': continue
        if data.get('permissions') != {'contents': 'read'}: fail(name, 'read-only permissions required')
        if set(data.get('on', {})) - {'push', 'pull_request', 'workflow_call'}: fail(name, 'unsupported event')
        for jid, job in data.get('jobs', {}).items():
            if 'concurrency' in job: fail(name, f'{jid}: job concurrency forbidden')
            if 'permissions' in job and job['permissions'] != {'contents': 'read'}: fail(name, f'{jid}: write permission')
            if 'continue-on-error' in job: fail(name, f'{jid}: continue-on-error forbidden')
            if 'secrets' in job: fail(name, f'{jid}: inherited secrets forbidden')
            if 'self-hosted' in str(job.get('runs-on', '')): fail(name, f'{jid}: untrusted runner')
            strategy = job.get('strategy', {})
            if 'matrix' in strategy and strategy.get('fail-fast') != 'false': fail(name, f'{jid}: fail-fast must be false')
            on_windows = windows_rows(job)
            default_shell = (run_defaults(job) or {}).get('shell')
            for step in job.get('steps', []):
                shell = step.get('shell', default_shell)
                if on_windows and 'run' in step and (not isinstance(shell, str) or not shell.strip()):
                    fail(name, f'{jid}: Windows run step requires an explicit shell')
                if 'continue-on-error' in step and not (
                    name == 'design' and step.get('run') == 'python server/internal/authz/catalogue/schema_test.py --check-sources'
                    and step['continue-on-error'] == 'true'):
                    fail(name, f'{jid}: hidden step failure')
                action = step.get('uses', '')
                if action and not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}', action): fail(name, f'{jid}: unpinned action')
                if action.startswith('actions/checkout@') and (
                        action != CHECKOUT or step.get('with', {}).get('persist-credentials') != 'false'):
                    fail(name, f'{jid}: unsafe checkout')
    try:
        inventory.fuzz_targets(root)
    except (OSError, ValueError, KeyError, TypeError):
        errors.append('scripts/ci/targets.toml: invalid fuzz inventory or budget')
    errors += python_env.lock_errors(root)
    errors += bootstrap.lock_errors(root)
    errors += package_manager_errors(root)
    required_names = {'ci', 'design', 'server', 'agent', 'console', 'bootstrap'}
    for name in required_names - set(workflows): fail(name, 'missing required workflow')
    if not required_names <= set(workflows): return errors
    if not observer_command_valid(root):
        errors.append('scripts/ci/semgrep_observer.py: exact Code/Supply Chain Pro command required')
    ci = workflows['ci']
    events = ci.get('on', {})
    if events != {'push': {'branches': ['master']}, 'pull_request': {'branches': ['master'], 'types': ['opened', 'synchronize', 'reopened', 'ready_for_review', 'edited']}}:
        fail('ci', 'entry must admit every PR and master push without paths')
    if ci.get('concurrency') != {'group': 'ci-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}', 'cancel-in-progress': "${{ github.event_name == 'pull_request' }}"}:
        fail('ci', 'unsafe cancellation')
    jobs = ci.get('jobs', {})
    if set(jobs) != set(NEEDS) | {'ci-required'}: fail('ci', 'caller job set mismatch')
    for unit in ('gitleaks', 'semgrep'):
        if jobs.get(unit) != scanner_job(unit):
            fail('ci', f'{unit}: exact unconditional scanner recipe required')
    if ci.get('env') or ci.get('defaults') not in (None, {'run': {'shell': 'bash'}}):
        fail('ci', 'scanner workflow environment and defaults overrides forbidden')
    aggregate = jobs.get('ci-required', {})
    if aggregate.get('name') != 'ci-required' or aggregate.get('needs') != list(NEEDS) or aggregate.get('if') != '${{ always() }}':
        fail('ci', 'required aggregate must unconditionally need every required job')
    for name, groups in CALLERS.items():
        caller = jobs.get(name, {})
        ordered = [g for g in inventory.GROUPS if g in groups]
        if caller != {'needs': ['route'], 'if': group_condition(ordered, 'needs.route.outputs.route'),
                      'uses': f'./.github/workflows/{name}.yml', 'with': {'route': '${{ needs.route.outputs.route }}'}}:
            fail('ci', 'caller contract mismatch: ' + name)
    download = [s for s in aggregate.get('steps', []) if s.get('uses', '').startswith('actions/download-artifact@')]
    if len(download) != 1 or download[0].get('uses') != DOWNLOAD or download[0].get('with') != {
            'pattern': 'ci-proof-${{ github.run_id }}-${{ github.run_attempt }}-*',
            'path': '${{ runner.temp }}/ci-receipts', 'merge-multiple': 'false'}:
        fail('ci', 'download must isolate this run and attempt')
    aggregate_steps = aggregate.get('steps', [])
    terminal = aggregate_steps[-1] if aggregate_steps else {}
    if any(key in terminal for key in ('if', 'continue-on-error', 'uses')):
        fail('ci', 'ci-required must end with one unconditional terminal verifier step')
    if terminal.get('run') != VERIFIER_COMMAND:
        fail('ci', 'ci-required must end with the exact fixed verifier command')
    for scope, settings in (
            ('step', terminal),
            ('job', aggregate.get('defaults', {}).get('run', {})),
            ('workflow', ci.get('defaults', {}).get('run', {}))):
        if 'shell' in settings and settings['shell'] != 'bash':
            fail('ci', f'ci-required: verifier shell must be literal bash at {scope} level')
    if not any(step.get('env', {}).get('NEEDS_JSON') == '${{ toJSON(needs) }}'
               and step.get('env', {}).get('ROUTE_JSON') == '${{ needs.route.outputs.route }}'
               for step in aggregate_steps[:-1]):
        fail('ci', 'aggregate input preparation must receive safe route and needs inputs')
    for name in required_names - {'ci'}:
        data = workflows[name]
        if data.get('on') != {'workflow_call': {'inputs': {'route': {'required': 'true', 'type': 'string'}}}} or 'concurrency' in data:
            fail(name, 'reusable route input required; reusable cancellation forbidden')
        expected_jobs = set(LEAVES[name]) | ({'fuzz-targets'} if name == 'server' else set())
        if set(data.get('jobs', {})) != expected_jobs: fail(name, 'leaf job set mismatch')
    for name, leaves in LEAVES.items():
        for jid, unit in leaves.items():
            job = workflows[name].get('jobs', {}).get(jid, {})
            steps = job.get('steps', [])
            for command in COMMANDS.get((name, jid), ()):
                matches = [s for s in steps if command in s.get('run', '')]
                if not matches or any('if' in step or 'continue-on-error' in step for step in matches):
                    fail(name, f'{jid}: missing unconditional command: {command}')
            proofs = [s for s in steps if s.get('id') == 'proof']
            native = unit in ('loader', 'loader-gate-b', 'ocsf', 'agent', 'bootstrap')
            wanted = (['go-fuzz:${{ matrix.package }}:${{ matrix.target }}'] if jid == 'fuzz' else
                      inventory.checks(unit + ':linux-x64' if native else unit))
            if len(proofs) != 1 or proofs[0].get('env', {}).get('UNIT') != unit:
                fail(name, f'{jid}: missing leaf proof')
            else:
                try: actual = json.loads(proofs[0].get('env', {}).get('CHECKS', 'null'))
                except ValueError: actual = None
                if actual != wanted or 'if' in proofs[0] or 'required.receipt(' not in proofs[0].get('run', ''):
                    fail(name, f'{jid}: receipt checks mismatch')
            if not steps or steps[-1].get('uses') != UPLOAD or steps[-1].get('with') != {
                    'name': '${{ steps.proof.outputs.artifact }}', 'path': '${{ runner.temp }}/ci-proof/receipt.json',
                    'retention-days': '30', 'if-no-files-found': 'error'} or 'if' in steps[-1]:
                fail(name, f'{jid}: missing final required receipt upload')
            if native:
                matrix = job.get('strategy', {}).get('matrix', {})
                hosts = matrix.get('os', [r.get('os') for r in matrix.get('include', [])])
                if len(hosts) != 3 or set(hosts) != set(inventory.HOSTS): fail(name, f'{jid}: native matrix mismatch')
                host_steps = [i for i, step in enumerate(steps) if step.get('name') == 'Assert native receipt host' and 'platform.machine()' in step.get('run', '')]
                commands = COMMANDS.get((name, jid), ())
                # The admitted bootstrap and its controls refuse a foreign host before any download, so they may precede the assertion.
                helpers = (BOOTSTRAP_COMMAND, EVIDENCE_COMMAND, CONTROLS_COMMAND)
                first_check = next((i for i, step in enumerate(steps) if step.get('run') not in helpers
                                    and any(command in step.get('run', '') for command in commands)), len(steps))
                if len(host_steps) != 1 or host_steps[0] >= first_check:
                    fail(name, f'{jid}: native host admission must precede checks')
            if name in ('server', 'agent'):
                group = {'validate': 'server', 'race': 'server', 'fuzz': 'server', 'loader-gate-a': 'loader', 'loader-gate-b': 'loader', 'ocsf-native': 'ocsf'}.get(jid) if name == 'server' else ('agent' if jid == 'validate' else 'interop')
                if job.get('if') != group_condition([group], 'inputs.route'): fail(name, f'{jid}: route selection mismatch')
            expected_needs = 'fuzz-targets' if name == 'server' and jid == 'fuzz' else (['route'] if name == 'ci' else None)
            if job.get('needs') != expected_needs: fail(name, f'{jid}: needs mismatch')
    design_steps = workflows['design']['jobs']['validate']['steps']
    for command in DESIGN_COMMANDS:
        matches = [s for s in design_steps if command in s.get('run', '') and '--check-sources' not in s.get('run', '')]
        if not matches or any('if' in s or 'continue-on-error' in s for s in matches): fail('design', 'missing blocking consumer: ' + command)
    text = '\n'.join(s.get('run', '') for s in design_steps)
    for path in ('schemas/ci/v1/contracts.schema.json', 'schemas/ci/v1/examples.json', 'scripts/ci/toolchains.lock.json'):
        if path not in text: fail('design', 'missing CI schema validation: ' + path)
    server = workflows['server']['jobs']
    race = server.get('race', {})
    race_steps = race.get('steps', [])
    # A closed step rejects trailing flags, shell wrappers and extra test runs.
    race_checks = [step for step in race_steps
                   if step.get('name') == 'Test with race detector'
                   or re.search(r'\bgo\s+test\b', step.get('run', ''))]
    if race_checks != [{'name': 'Test with race detector',
                        'run': COMMANDS[('server', 'race')][0]}]:
        fail('server', 'race: exact unconditional race command required')
    for scope, settings in (('workflow', workflows['server']), ('job', race)):
        defaults = run_defaults(settings)
        if defaults is None or ('shell' in defaults and defaults['shell'] != 'bash'):
            fail('server', 'race: unsafe execution defaults at ' + scope)
        if scope == 'job' and (defaults or {}).get('working-directory') != 'server':
            fail('server', 'race: working-directory must be server')
    if race.get('timeout-minutes') != '20':
        fail('server', 'race: job timeout must remain 20 minutes')
    if any('GORACE' in scope.get('env', {}) for scope in (workflows['server'], race, *race_steps)) or any(
            re.search(r'\bGORACE\b', step.get('run', '')) for step in race_steps):
        fail('server', 'race: GORACE override forbidden')
    for gate in ('a', 'b'):
        for error in loader_qualification_errors(server.get('loader-gate-' + gate, {}), gate):
            fail('server', error)
    for jid, native_parser in (('fuzz', False), ('loader-gate-a', True)):
        for error in fuzz_evidence_errors(server.get(jid, {}), native_parser):
            fail('server', jid + ': ' + error)
    matrix_job = server.get('fuzz-targets', {})
    if matrix_job.get('if') != group_condition(['server'], 'inputs.route') or 'scripts/ci/inventory.py --fuzz-matrix' not in str(matrix_job):
        fail('server', 'fuzz matrix must come from inventory')
    if server['fuzz'].get('strategy', {}).get('matrix') != {'include': '${{ fromJSON(needs.fuzz-targets.outputs.targets) }}'}:
        fail('server', 'fuzz matrix expression mismatch')
    for job in server.values():
        if 'permission-schema-venv' in str(job) or 'schemas/export/v1alpha1/validate.py' in str(job): fail('server', 'duplicate Python validator')
    if 'pnpm test:fuzz' not in str(workflows['console']): fail('console', 'missing bounded properties')
    # Payload admission is checked per job in bootstrap_errors; Task 3 admits compiler caches above.
    for name, data in workflows.items():
        if name not in required_names: continue
        for jid, job in data.get('jobs', {}).items():
            if 'uses' in job: continue
            checkouts = [step for step in job.get('steps', []) if step.get('uses', '').startswith('actions/checkout@')]
            source = ('needs.route.outputs.route' if name == 'ci' else 'inputs.route')
            if name == 'ci' and jid in ('route', 'ci-required'):
                if len(checkouts) != 1 or checkouts[0].get('with', {}).get('fetch-depth') != '0':
                    fail(name, f'{jid}: full checkout history required')
            elif len(checkouts) != 1 or checkouts[0].get('with', {}).get('ref') != '${{ fromJSON(' + source + ').testedSha }}':
                fail(name, f'{jid}: checkout must bind testedSha')
    return errors

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    errors = check(args.root)
    if errors: raise SystemExit('\n'.join(errors))
    print('CI workflow policy passed')

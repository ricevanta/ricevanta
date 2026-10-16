"""Check the reviewed workflow graph, routing inputs and receipt obligations."""
import argparse
import ast
import fnmatch
import os
from pathlib import Path
import re
import json
import shlex
import yaml
import bootstrap
import inventory
import python_env
import run_selected
import rust_env
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

# Selected tests, benchmarks, fuzzing and property runs execute only through the
# wrapper; targets.toml holds their exact commands, pinned in SELECTED_COMMANDS.
def wrapper(target_id):
    return f'python -B scripts/ci/run_selected.py --id {target_id} --evidence "$RUNNER_TEMP/evidence"'


FUZZ_WRAPPER = 'python -B scripts/ci/run_selected.py --id "go-fuzz:${FUZZ_PACKAGE}:${FUZZ_TARGET}" --evidence "$RUNNER_TEMP/evidence"'
RECEIPT_WITH_EVIDENCE = "required.receipt(route, unit, json.loads(os.environ['CHECKS']), pathlib.Path(os.environ['RUNNER_TEMP']) / 'evidence')"
AGENT_CHECKS = "checks = json.loads(os.environ['CHECKS']) + inventory.agent_native_checks(inventory.HOSTS[os.environ['HOST_OS']])"
AGENT_RECEIPT = "required.receipt(route, unit, checks, pathlib.Path(os.environ['RUNNER_TEMP']) / 'evidence')"
SELECTED_COMMANDS = {
    'server-keyfile-root': ("go test -list '^(TestReadKeyFileGroupRules)$' ./internal/platform/config",
                            "go test -json -count=1 -exec 'sudo -n --' ./internal/platform/config -run '^(TestReadKeyFileGroupRules)$'"),
    'server-unit': ("go test -list '.*' ./...", 'go test -json -count=1 ./...'),
    'server-race': ("go test -race -list '.*' ./...", 'go test -json -race -count=1 -timeout=15m ./...'),
    'key-admission-bench': ("go test -list '^BenchmarkValidate$' ./internal/signing/ed25519key",
                            "go test -json -run '^$' -bench '^BenchmarkValidate$' -benchmem -benchtime=100x ./internal/signing/ed25519key"),
    'ingest-cost-model': ("go test -list '^(TestDecodeCostModel)$' ./internal/events/body",
                          "go test -json -count=1 -timeout=15m ./internal/events/body -run '^(TestDecodeCostModel)$'"),
    'loader-extended': ("go test -list '^(TestParserBudgetExtended)$' ./internal/extensions/loader",
                        "go test -json -count=1 ./internal/extensions/loader -run '^(TestParserBudgetExtended)$' -args -loader-budget-extended"),
    'loader-repeat': ("go test -list '^(TestParserBudgetSmoke)$' ./internal/extensions/loader",
                      "go test -json -count=1 ./internal/extensions/loader -run '^(TestParserBudgetSmoke)$' -args "
                      "-loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50"),
    'loader-fuzz': ("go test -list '^FuzzParserQualification$' ./internal/extensions/loader",
                    "go test -json -count=1 ./internal/extensions/loader '-fuzz=^FuzzParserQualification$' -fuzztime=60s -parallel=2"),
    'loader-gate-b-extended': ("go test -list '^(TestLoaderBudgetExtended)$' ./internal/extensions/loader",
                               "go test -json -count=1 ./internal/extensions/loader -run '^(TestLoaderBudgetExtended)$' -args -loader-budget-extended"),
    'ocsf-native': ("go test -list '.*' ./internal/events/ocsf", 'go test -json -count=1 ./internal/events/ocsf'),
    'agent-unit': ('cargo test --locked --workspace -- --list', 'cargo test --locked --workspace -- --nocapture'),
    'spool-extended': ('cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact --list',
                       'cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact --nocapture --test-threads=1'),
    'batch-extended': ('cargo test --locked -p ricevanta-batch --test fuzz_seal fuzz_seal_extended -- --ignored --exact --list',
                       'cargo test --locked -p ricevanta-batch --test fuzz_seal fuzz_seal_extended -- --ignored --exact --nocapture --test-threads=1'),
    'interop-unit': ("go test -tags rustinterop -list '^TestRustWriter' ./internal/events/body",
                     "go test -json -tags rustinterop -count=1 ./internal/events/body -run '^TestRustWriter'"),
    'interop-race': ("go test -race -tags rustinterop -list '^TestRustWriter' ./internal/events/body",
                     "go test -json -race -tags rustinterop -count=1 ./internal/events/body -run '^TestRustWriter'"),
}
SELECTED_COMMANDS.update({
    'json-extended': ('cargo test --locked -p ricevanta-json --test fuzz_json fuzz_json_extended -- --ignored --exact --list',
                      'cargo test --locked -p ricevanta-json --test fuzz_json fuzz_json_extended -- --ignored --exact --nocapture --test-threads=1'),
    'agent-protection-root-linux': ("sudo '{executable}' root_ --ignored --list", "sudo '{executable}' root_ --ignored"),
    'agent-protection-root-macos': ("sudo '{executable}' root_ --ignored --list", "sudo '{executable}' root_ --ignored"),
})

INTEROP_PROOF = {
    'tests': ['TestRustWriterFixtures', 'TestRustWriterBoundaries', 'TestRustWriterMutations', 'TestRustWriterCaptureOverflow'],
    'helpers': ['TestRustWriterPrecondition', 'TestRustWriterCaptureChild'],
    'subtests': ['TestRustWriterCaptureOverflow/stdout', 'TestRustWriterCaptureOverflow/stderr'],
    'subtest_prefixes': ['TestRustWriterFixtures/body/', 'TestRustWriterFixtures/header/', 'TestRustWriterFixtures/descriptor/'],
    'children': [{'parent': 'TestRustWriterMutations', 'Helper': 'TestRustWriterPrecondition', 'Pipe': '', 'Outcome': 'rejected'},
                 {'parent': 'TestRustWriterCaptureOverflow/stdout', 'Helper': 'TestRustWriterCaptureChild', 'Pipe': 'stdout', 'Outcome': 'overflow'},
                 {'parent': 'TestRustWriterCaptureOverflow/stderr', 'Helper': 'TestRustWriterCaptureChild', 'Pipe': 'stderr', 'Outcome': 'overflow'}],
}
# Where and how each selected ID executes; a row may not move its command elsewhere.
SELECTED_PLACES = {
    'server-keyfile-root': ('server', 'go-selected'),
    'server-unit': ('server', 'go-suite'), 'server-race': ('server', 'go-suite'), 'key-admission-bench': ('server', 'go-bench'),
    'ingest-cost-model': ('server', 'go-cost-model'),
    'loader-extended': ('server', 'go-selected'), 'loader-repeat': ('server', 'go-selected'), 'loader-fuzz': ('server', 'go-fuzz'),
    'loader-gate-b-extended': ('server', 'go-selected'), 'ocsf-native': ('server', 'go-suite'), 'agent-unit': ('agent', 'rust-suite'),
    'spool-extended': ('agent', 'rust-selected'), 'batch-extended': ('agent', 'rust-selected'),
    'interop-unit': ('server', 'go-interop'), 'interop-race': ('server', 'go-interop'),
}
INGEST_CASE_KEYS = [
    'arrayobjs-64x1MiB-single/1',
    'arrayobjs-64x1MiB-single/4',
    'badid-10000-single/1',
    'badid-10000-single/8',
    'blocks-4m-at',
    'blocks-4m-over',
    'blocks-64m-at',
    'blocks-64m-over',
    'blocks-min-at',
    'blocks-min-ceiling',
    'blocks-min-over',
    'concurrent-blocks64',
    'concurrent-small-window64',
    'dense-4x1MiB-win4/1',
    'dense-4x1MiB-win4/16',
    'dense-64x1MiB-single/1',
    'densenested-64x1MiB-single/1',
    'flat-10000x6710-single/1',
    'flat-16x1MiB-single/1',
    'flat-16x1MiB-win4/1',
    'flat-1x1MiB-single/1',
    'flat-1x1MiB-win4/1',
    'flat-4x1MiB-single/1',
    'flat-4x1MiB-win4/1',
    'flat-64x1MiB-single/1',
    'flat-64x1MiB-single/4',
    'flat-64x1MiB-win4/1',
    'late-checksum64',
    'malformed-entropy',
    'minok-10000-single/1',
    'nested-64x1MiB-single/1',
    'numbers-64x1MiB-single/1',
    'prefix-64x1MiB-single/1',
    'preflight-ceiling',
    'preflight-rate-deficit',
    'random3-64x1MiB-single/1',
    'random3-64x1MiB-single/4',
    'realistic-10000-win4/1',
    'realistic-2000-win4/1',
    'realistic-5000-win4/1',
    'realistic-5000-win4/8',
    'round-10000x5377-single/1',
    'round-2047x32769-single/1',
    'round-2047x32769-single/4',
    'singlechar-64x1MiB-single/1',
    'singlechar-64x1MiB-single/4',
    'size-lie-small',
    'small-window64',
    'small-window64-checksum',
    'strings-64x1MiB-single/1',
]
SELECTED_BUDGETS = {'loader-repeat': {'marker': 'PARSER_MEASUREMENT', 'marker_samples': 50}, 'key-admission-bench': {'operations': 100},
                    'ingest-cost-model': {'packages': ['./internal/events/body'], 'tests': ['TestDecodeCostModel'],
                                          'test_flags': ['-timeout=15m'], 'cases': 50, 'case_keys': INGEST_CASE_KEYS, 'benchmark': 'BenchmarkDecodeCost', 'operations': 3,
                                          'benchmark_flags': ['-benchmem', '-benchtime=3x', '-timeout=15m']},
                    'loader-extended': {'marker': 'PARSER_MEASUREMENT'}, 'loader-gate-b-extended': {'marker': 'LOADER_MEASUREMENT'},
                    'spool-extended': {'seed': '0x525653505f763031', 'cases': 100000},
                    'batch-extended': {'seed': '0x5249564241544348', 'cases': 20000},
                    'interop-unit': INTEROP_PROOF, 'interop-race': INTEROP_PROOF}
# Ordinary suites whose discovered Fuzz* names must equal the fuzz inventory.
FUZZ_INVENTORY_SUITES = ('server-unit', 'server-race', 'ocsf-native')
LOADER_FUZZ = ('./internal/extensions/loader', 'FuzzParserQualification')
SELECTED_PLACES.update({'json-extended': ('agent', 'rust-selected'),
                        'agent-protection-root-linux': ('agent', 'rust-root'),
                        'agent-protection-root-macos': ('agent', 'rust-root')})
SELECTED_BUDGETS['json-extended'] = {'seed': '0x52564a534f4e5631', 'cases': 20000}
AGENT_ROOT_TESTS = ['root_foreign_owner_of_config_and_parent_fails', 'root_directory_parent_owner_and_group_rules', 'root_service_mode_refuses_unprivileged_directory_owner', 'root_foreign_health_file_is_refused_untouched']
for suffix, platform in (('linux', 'linux'), ('macos', 'darwin')):
    SELECTED_BUDGETS['agent-protection-root-' + suffix] = {
        'platform': platform, 'target': 'protection', 'tests': AGENT_ROOT_TESTS,
        'cargo': ['--locked', '-p', 'ricevanta-os-' + suffix, '--test', 'protection']}
SELECTED_BUDGETS['agent-unit'] = {'required': [
    {'platform': 'linux', 'target': 'growth', 'test': 'sampling_does_not_grow_private_memory'}]}

# The closed skip allowance: each row names its separate proving unit or parent test.
LOADER = 'github.com/ricevanta/ricevanta/server/internal/extensions/loader'
YAMLTOKENS = LOADER + '/internal/yamltokens'
GO_SKIP_MODES = ['server-unit', 'server-race', 'go-fuzz']
SKIP_ALLOWANCES = [
    {'package': 'github.com/ricevanta/ricevanta/server/internal/platform/config', 'test': 'TestReadKeyFileGroupRules',
     'reason': 'foreign file group requires root; selected root binary proves the live check',
     'proof': 'server-keyfile-root', 'modes': GO_SKIP_MODES},
    {'package': 'github.com/ricevanta/ricevanta/server/internal/events/body', 'test': 'TestDecodeCostModel',
     'reason': 'full ingest cost model runs separately without race instrumentation', 'proof': 'ingest-cost-model', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestParserBudgetExtended', 'reason': 'native extended parser corpus',
     'proof': 'loader-extended', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestLoaderBudgetExtended', 'reason': 'native extended complete-loader corpus',
     'proof': 'loader-gate-b-extended', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestLoaderMeasurementChild', 'reason': 'fresh measurement child entry point',
     'proof': 'loader-gate-b-extended', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestDecodeVerifiedYAMLInstrumented',
     'reason': 'instrumented child entry point driven by TestDecodeVerifiedYAMLCallCounts',
     'parent': 'TestDecodeVerifiedYAMLCallCounts', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestAgreementOutcomeChild',
     'reason': 'negative-control child entry point driven by TestAgreementRejectsOutcomeMismatch',
     'parent': 'TestAgreementRejectsOutcomeMismatch', 'modes': GO_SKIP_MODES},
    {'package': YAMLTOKENS, 'test': 'TestParserBudgetHarness', 'reason': 'nested harness entry point run by the loader root tests',
     'proof': 'loader-extended', 'modes': ['server-unit', 'server-race']},
    {'package': YAMLTOKENS, 'test': 'TestParserMeasurementChild', 'reason': 'fresh measurement child entry point',
     'proof': 'loader-extended', 'modes': ['server-unit', 'server-race']},
    {'package': 'ricevanta-spool', 'test': 'fuzz_recover_extended', 'reason': 'extended 100,000-case native property budget',
     'target': 'fuzz_recover', 'proof': 'spool-extended', 'modes': ['agent-unit']},
    {'package': 'ricevanta-batch', 'test': 'fuzz_seal_extended', 'reason': 'extended 20,000-case native property budget',
     'target': 'fuzz_seal', 'proof': 'batch-extended', 'modes': ['agent-unit']},
]


SKIP_ALLOWANCES.append({
    'package': 'ricevanta-json', 'test': 'fuzz_json_extended',
    'reason': 'extended 20,000-case native JSON property budget',
    'target': 'fuzz_json', 'proof': 'json-extended', 'modes': ['agent-unit']})
for suffix, platform in (('linux', 'linux'), ('macos', 'darwin')):
    for name in AGENT_ROOT_TESTS:
        SKIP_ALLOWANCES.append({
            'package': 'ricevanta-os-' + suffix, 'test': name,
            'reason': 'privileged native ownership and protection assertions',
            'target': 'protection', 'proof': 'agent-protection-root-' + suffix,
            'modes': ['agent-unit'], 'platform': platform})
    for name in ('umask_child_narrow', 'umask_child_open'):
        SKIP_ALLOWANCES.append({
            'package': 'ricevanta-os-' + suffix, 'test': name,
            'reason': 'isolated umask child of created_modes_do_not_depend_on_umask',
            'target': 'protection', 'parent': 'created_modes_do_not_depend_on_umask',
            'modes': ['agent-unit'], 'platform': platform})
SKIP_ALLOWANCES.append({
    'package': 'ricevanta-os-linux', 'test': 'from_env_child',
    'reason': 'isolated notification environment child', 'target': 'notify',
    'parent': 'environment_is_read_by_from_env', 'modes': ['agent-unit'], 'platform': 'linux'})


# test2json treats a stdout line starting with 0x16 as its own framing, so a test
# that prints the byte can forge run/pass events. This is a partial tripwire, not
# a closed gap: it rejects the literal byte and its string escapes in the sources
# compiled into selected Go test binaries (server/ outside testdata, and the
# wrapper's Go fixtures), but a byte computed at run time, an integer literal, or
# data read from testdata, embedded files or assembly is not detected. Spec
# section 11 covers that residual: a PR author can falsify their own tests.
FRAMING_BYTE = re.compile(rb'\x16|\\x16|\\u0016|\\U00000016|\\026')


def framing_errors(root):
    errors = []
    paths = [p for p in (root / 'server').rglob('*.go') if 'testdata' not in p.relative_to(root).parts]
    paths += list((root / 'scripts').rglob('*_test.go'))
    for path in sorted(paths):
        try: data = path.read_bytes()
        except OSError: continue
        if FRAMING_BYTE.search(data):
            errors.append(path.relative_to(root).as_posix() + ': test2json framing byte 0x16 is forbidden in selected Go sources')
    return errors


def cargo_config_errors(root):
    """No Cargo configuration may live in the tree: a runner or wrapper replaces harness execution."""
    errors = []
    for directory, subdirectories, files in os.walk(root):
        # Cargo reads only the working directory's ancestors; ignored build trees are skipped.
        subdirectories[:] = [d for d in subdirectories if d not in ('.git', 'node_modules', 'target')]
        if os.path.basename(directory) == '.cargo':
            for name in ('config', 'config.toml'):
                if name in files or name in subdirectories:
                    errors.append(Path(directory, name).relative_to(root).as_posix() + ': repository Cargo configuration is forbidden')
    return errors


# Shell-style assignments (`NAME=value cmd`, `export NAME=`, `env NAME=` or a GITHUB_ENV line); cc reads target-suffixed
# names with hyphens, which `env` can pass.
SHELL_ASSIGNMENT = re.compile(r'(?<![\w$.-])([A-Za-z_][A-Za-z0-9_-]*)\+?=')


def cargo_override_errors(data):
    """Closed allowlists (rust_env) for Cargo/rustc and C toolchain variables in workflow env, run scripts and GITHUB_ENV writes.

    Workflows may set only rust_env.WORKFLOW_RUST_ENV; CARGO_HOME and CARGO_TARGET_DIR come solely from the bootstrap's env
    file and fresh_go.py (see cache_errors). No workflow sets a C compiler, archiver, flag or SDK variable that cc or cgo reads.
    """
    errors = []
    def check(name):
        if rust_env.CONTROLLED.search(name.upper()) and name.upper() not in rust_env.WORKFLOW_RUST_ENV:
            errors.append(f'{jid}: unreviewed Cargo or rustc variable {name} forbidden')
        if rust_env.is_c_toolchain_name(name):
            errors.append(f'{jid}: C toolchain variable {name} forbidden')
    for jid, job in data.get('jobs', {}).items():
        for scope in (data, job, *job.get('steps', [])):
            env = scope.get('env', {})
            for key in (env if isinstance(env, dict) else {}): check(str(key))
        for step in job.get('steps', []):
            names = set(re.findall(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*=', str(step.get('run', ''))))
            names |= set(SHELL_ASSIGNMENT.findall(str(step.get('run', ''))))
            for name in sorted(names): check(name)
    return errors


def selected_errors(root):
    """targets.toml must resolve every wrapper ID to its exact reviewed command."""
    try:
        targets = run_selected.inventory(root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return ['scripts/ci/targets.toml: invalid selected inventory: ' + str(error)]
    errors = []
    for target_id, target in targets.items():
        if target.get('requires', []) != (['server-keyfile-root'] if target_id == 'server-unit' else []):
            errors.append('scripts/ci/targets.toml: required selected proof mismatch: ' + target_id)
        # No other wrapper ID may exist; console IDs are pinned here when Task 8 adds them.
        if target_id not in SELECTED_COMMANDS and not (target_id.startswith('go-fuzz:') and target['mode'] == 'go-fuzz'):
            errors.append('scripts/ci/targets.toml: unreviewed selected target ' + target_id)
    fuzz_pairs = sorted(map(list, inventory.FUZZ_PAIRS | {LOADER_FUZZ}))
    for target_id, target in targets.items():
        expected = fuzz_pairs if target_id in FUZZ_INVENTORY_SUITES else None
        if sorted(target.get('fuzz_inventory') or []) != (expected or []) or (expected is None) == ('fuzz_inventory' in target):
            errors.append('scripts/ci/targets.toml: fuzz inventory cross-check mismatch: ' + target_id)
    try: skips = run_selected.load_targets(root).get('skips', [])
    except (OSError, ValueError): skips = None
    canonical = lambda rows: sorted(json.dumps(row, sort_keys=True) for row in rows)
    if not isinstance(skips, list) or canonical(skips) != canonical(SKIP_ALLOWANCES):
        errors.append('scripts/ci/targets.toml: skip allowances differ from the reviewed set')
    for target_id, (discovery, command) in SELECTED_COMMANDS.items():
        target = targets.get(target_id)
        if target is None:
            errors.append('scripts/ci/targets.toml: missing selected target ' + target_id); continue
        if shlex.join(run_selected.discovery_command(target)) != discovery or shlex.join(run_selected.run_command(target)) != command:
            errors.append('scripts/ci/targets.toml: selected command mismatch: ' + target_id)
        if (target['cwd'], target['mode']) != SELECTED_PLACES[target_id]:
            errors.append('scripts/ci/targets.toml: selected directory or mode mismatch: ' + target_id)
        for key, value in SELECTED_BUDGETS.get(target_id, {}).items():
            if target.get(key) != value: errors.append('scripts/ci/targets.toml: selected budget mismatch: ' + target_id)
    cost=targets.get('ingest-cost-model')
    if cost:
        bench=run_selected.cost_model_benchmark(cost)
        if (shlex.join(run_selected.discovery_command(bench)) != "go test -list '^BenchmarkDecodeCost$' ./internal/events/body" or
            shlex.join(run_selected.run_command(bench)) != "go test -json -run '^$' -bench '^BenchmarkDecodeCost$' -benchmem -benchtime=3x -timeout=15m ./internal/events/body"):
            errors.append('scripts/ci/targets.toml: ingest benchmark commands mismatch')
    for package, name in inventory.FUZZ_PAIRS:
        target = targets.get(f'go-fuzz:{package}:{name}')
        minimize = ' -fuzzminimizetime=3s' if package == './internal/extensions/admission' else ''
        if target is None or (target['cwd'], target['mode']) != ('server', 'go-fuzz') or shlex.join(run_selected.run_command(target)) != f"go test -json -count=1 {package} '-fuzz=^{name}$' -fuzztime=60s -parallel=2{minimize}":
            errors.append(f'scripts/ci/targets.toml: fuzz command mismatch: {package} {name}')
    for row in targets.values():
        for allowance in row['skips'].values():
            proof = allowance.get('proof')
            if ('*' in allowance['test'] or not allowance['reason'] or (proof is None) == ('parent' not in allowance)
                    or (proof is not None and (proof not in targets or proof in allowance['modes'] or targets[proof]['mode'] in allowance['modes']))):
                errors.append('scripts/ci/targets.toml: skip allowance must name an exact test and a separate proving unit')
    return errors


def agent_native_errors(job):
    """Every native root proof executes on exactly its own host before receipt creation."""
    errors = []
    steps = job.get('steps', [])
    for suffix, host in (('linux', 'Linux'), ('macos', 'macOS')):
        command = wrapper('agent-protection-root-' + suffix)
        matches = [step for step in steps if command in step.get('run', '')]
        expected = {'name': 'Root ' + ('Linux' if suffix == 'linux' else 'macOS') + ' protection tests',
                    'if': "runner.os == '" + host + "'", 'shell': 'bash', 'working-directory': '.',
                    'env': {'CARGO_NET_OFFLINE': 'true'}, 'run': command}
        if matches != [expected]: errors.append('exact host-guarded root protection step required: ' + suffix)
    proof = next((step for step in steps if step.get('id') == 'proof'), {})
    if AGENT_CHECKS not in proof.get('run', '') or AGENT_RECEIPT not in proof.get('run', ''):
        errors.append('agent receipt must include native root evidence for its host')
    root_steps = [step for step in steps if any(wrapper('agent-protection-root-' + suffix) in step.get('run', '')
                                               for suffix in ('linux', 'macos'))]
    if proof and any(steps.index(step) > steps.index(proof) for step in root_steps):
        errors.append('native root proofs must precede the receipt')
    return errors


COMMANDS = {
    ('server', 'validate'): ('gofmt -l .', wrapper('server-keyfile-root'), wrapper('server-unit'), 'go vet ./...', wrapper('key-admission-bench'), wrapper('ingest-cost-model')),
    ('server', 'race'): (wrapper('server-race'),),
    ('server', 'fuzz'): (FUZZ_WRAPPER,),
    ('server', 'loader-gate-a'): (wrapper('loader-extended'), wrapper('loader-repeat'), wrapper('loader-fuzz')),
    ('server', 'loader-gate-b'): (wrapper('loader-gate-b-extended'),),
    ('server', 'ocsf-native'): (wrapper('ocsf-native'),),
    ('agent', 'validate'): ('cargo metadata --locked --format-version 1', 'python tools/generate-spool-fixtures.py --check',
        'cargo fmt --all -- --check', 'cargo clippy --locked --workspace --all-targets -vv -- -D warnings',
        wrapper('agent-unit'), wrapper('spool-extended'), wrapper('batch-extended'), wrapper('json-extended')),
    ('agent', 'rustinterop'): ('cargo build --locked -p ricevanta-batch --example seal-vector -vv',
        wrapper('interop-unit'), wrapper('interop-race')),
    ('console', 'validate'): ('pnpm install --frozen-lockfile', 'pnpm typecheck', 'pnpm lint',
        'pnpm format:check', 'pnpm audit:deps', 'pnpm test:unit', 'pnpm test:component',
        'pnpm build', 'pnpm check:reproducible', 'pnpm test:csp', 'pnpm test:fuzz'),
    ('ci', 'ci-contracts'): ('gofmt -l .', 'go vet .', "python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v",
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
                                # .NET and JavaScript clients count when constructed or called, not when prose names them.
                                r'\bNet\.WebClient\b|New-Object\s+(?:-TypeName\s+)?\S*WebClient\b|\.Download(?:File|String|Data)(?:Async)?\s*\(|'
                                r'\bNet\.Http\.HttpClient\b|\bnew\s+HttpClient\s*\(|\.Get(?:String|ByteArray|Stream)?Async\s*\(|'
                                r'\brequire\(\s*[\'"](?:node:)?https?[\'"]\s*\)|\bimport\(\s*[\'"](?:node:)?https?[\'"]\s*\)|'
                                r'\bfrom\s+[\'"](?:node:)?https?[\'"]|\bhttps?\.(?:get|request)\(|'
                                r'(?<!\w)fetch\(\s*(?:[\'"`]|[A-Za-z_$][\w$.]*\s*[,)])|\bgo\s+(?:install|get)\b|\bcargo\s+(?:install|binstall)\b|\bpip\s+download\b')
TOOL_CONSUMERS = (('python', re.compile(r'\bpython3?\b')), ('go', re.compile(r'\bgo(?:fmt)?\s')),
                  ('rust', re.compile(r'\bcargo\b|\brustc\b|\brustfmt\b')), ('node', re.compile(r'\bnode\b|\bpnpm\b')),
                  ('pnpm', re.compile(r'\bpnpm\b')), ('playwright', re.compile(r'pnpm test:(?:component|csp)|\bplaywright\b')))
# Variables bootstrap.py writes through --env-out, and loader or interpreter hooks that would substitute other code
# for an admitted tool; no other step or env mapping may set them. Whole families are closed by prefix.
# The runner's own RUNNER_* facts (RUNNER_TEMP, RUNNER_ENVIRONMENT) and the linker are closed the same way.
ADMITTED_ENV = frozenset({'PATH', 'Path', 'LD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_AUDIT', 'DYLD_LIBRARY_PATH', 'DYLD_INSERT_LIBRARIES',
                          'DYLD_FRAMEWORK_PATH', 'RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'CI_ADMITTED_ROOT',
                          'GOROOT', 'GOTOOLCHAIN', 'GOTOOLDIR', 'LD', 'NODE_OPTIONS', 'NODE_PATH', 'COREPACK_ENABLE_STRICT'})
ADMITTED_ENV_PREFIXES = ('PLAYWRIGHT_', 'RUSTUP_', 'COREPACK_', 'pnpm_config_', 'npm_config_', 'PNPM_', 'NPM_CONFIG_', 'RUNNER_',
                         'LD_', 'DYLD_')
ADMITTED_ENV_WRITE = re.compile(r'(?<![A-Za-z0-9_])(?:' + '|'.join(sorted(ADMITTED_ENV)) + '|'
                                + '|'.join(p + r'\w*' for p in ADMITTED_ENV_PREFIXES) + r')\s*=')


def admitted_env_names(mapping):
    if not isinstance(mapping, dict): return []
    return sorted(k for k in mapping if k in ADMITTED_ENV or str(k).startswith(ADMITTED_ENV_PREFIXES))


# The one shape of a GITHUB_ENV write outside the pinned helper and apply steps: a literal name and a value without command
# substitution, so the reviewed name is the name the runner sets. Names built at run time (`${n}ROOT=`, printf, Python
# string concatenation, a block redirect or the `github.env` context) cannot be reviewed and are refused.
LITERAL_ENV_WRITE = re.compile(r'[ \t]*echo[ \t]+"([A-Za-z_][A-Za-z0-9_]*)=(?:[^"`$\n\\]|\$(?!\()\{?[A-Za-z_][A-Za-z0-9_]*\}?)*"[ \t]*>>[ \t]*"\$GITHUB_ENV"[ \t]*')


def forbidden_env_name(name):
    """Section 8: names no step outside the pinned helpers may set through env or GITHUB_ENV."""
    return (name in ADMITTED_ENV or name.startswith(ADMITTED_ENV_PREFIXES) or name in CACHE_ENV
            or rust_env.is_c_toolchain_name(name) or bool(rust_env.rust_overrides([name])) or name.upper() in ('BASH_ENV', 'ENV'))


def env_write_errors(step):
    """GITHUB_ENV writes outside the pinned steps: one literal echo line per write, naming a variable outside section 8's list."""
    run = step.get('run', '')
    if run in (APPLY_COMMAND, GO_FRESH, CARGO_FRESH): return []
    errors = []
    other = step_text({key: value for key, value in step.items() if key != 'run'})
    if ENV_FILE.search(other): errors.append('environment file writes must be literal echo lines in the run script')
    for line in str(run).splitlines():
        if not ENV_FILE.search(line): continue
        match = LITERAL_ENV_WRITE.fullmatch(line)
        if not match:
            errors.append('environment file writes must be literal echo lines naming a reviewed variable')
        elif forbidden_env_name(match[1]):
            errors.append('admitted tool environment override forbidden: ' + match[1])
    return errors
BOOTSTRAP_NAME = 'Bootstrap admitted toolchains'
EVIDENCE_NAME = 'Verify admitted toolchain evidence'
CONTROLS_NAME = 'Reject corrupted payloads before any extraction or execution'
# Closure consumers are checked at two levels.
#
# Source level (this file): only the three exact admission steps may touch installers, environments or the helper;
# any command or shell that names an installer, environment manager or the helper is rejected at token level, whatever
# its flag order. Environment that would redirect imports, packages, the interpreter or the shell is rejected in `env`
# mappings, in run scripts (inline `NAME=value cmd`, `export`, `declare -x`, `env NAME=`, `set -a`) and in custom shells.
# The runner's PATH and environment files, the validator venv, site-packages, the scripts directory and the base
# interpreter may be named only by their admitted steps. These rules match spellings: they cover the forms listed in
# the patterns below, including absolute, `..`-relative and glob spellings of the venv directory, not every way a
# script can compute or obtain a path.
#
# Runtime level (the terminal `--check`, run isolated and without site): the interpreter, environment, import paths,
# every site-packages file against the admitted RECORDs, the scripts directory against its --venv manifest, the venv
# root on Windows, sitecustomize/usercustomize and repository names that shadow closure modules. It detects divergence,
# not deliberate tampering by job steps. Uncatchable inside the job, and left to independent review of the workflow
# and script diff: shell indirection that hides these spellings (`bash scripts/x.sh`, escaped tokens such as `pi\p`,
# third-party actions); a step that rewrites a RECORD or the venv marker together with the files they describe; a
# replaced interpreter or `bash` in any PATH directory, which runs instead of the admission shell or the checker; and
# environment set only for one validator process by such indirection.
ADMITTED_PYTHON_RUNS = frozenset({python_env.VENV_COMMAND, python_env.INSTALL_COMMAND, python_env.CHECK_COMMAND})
BYPASS_TOKEN = re.compile(r'(?<![\w.-])(?:pip3?|venv|ensurepip|virtualenv|uvx?|pipx|pipenv|poetry|conda|mamba|micromamba|'
                          r'pdm|hatch|rye|pixi|python_env\.py)(?![\w-])')
# The runner's PATH and environment files: by variable, by `github` context (`github.path`, `github['env']`, or the
# whole context passed to a function) or by the runner's file-command directory and file names.
PATH_FILE = re.compile(r'(?i)github_path|\bgithub\s*\.\s*path\b|_runner_file_commands|add_path_')
ENV_FILE = re.compile(r'(?i)github_env|\bgithub\s*\.\s*env\b|_runner_file_commands|set_env_')
WHOLE_GITHUB = re.compile(r'(?i)\bgithub\s*(?:[\[,)]|\}\})')
# Ways to locate site-packages, the scripts directory, the base interpreter or start-up hooks without naming the venv.
SITE_PROBE = re.compile(r'(?i)sysconfig|getsitepackages|getusersitepackages|site-packages|dist-packages|_base_executable|'
                        r'\bsys\s*\.\s*(?:base_|exec_)*(?:prefix|executable)\b|\bcommand\s+-[vV]\b|\bwhich\b|'
                        r'\btype\s+-[aPp]\b|\bwhereis\b|pythonlocation|python[23]?_root_dir|toolcache|\.pth\b|'
                        r'sitecustomize|usercustomize')
PATH_PART = re.compile(r'[^/\\\s"\'$(){};|&<>=:,`]+')
# Environment names a closure consumer may set; shell start-up (BASH_ENV, ENV), exported functions, loader preloads,
# PATH and interpreter or installer variables all fall outside it.
# CI_PLATFORM and CI_TOOLS are the admitted bootstrap's literal step inputs; bootstrap_errors pins their values and forbids
# them at job and workflow scope.
# BASE_SHA and CANDIDATE_SHA carry the validated route's commits to the catalogue compatibility check.
CONSUMER_ENV = python_env.ALLOWED_PYTHON_ENV | {'ROUTE_JSON', 'NEEDS_JSON', 'UNIT', 'CHECKS', 'HOST_OS', 'CI_PLATFORM', 'CI_TOOLS',
                                                 'BASE_SHA', 'CANDIDATE_SHA'}
RISKY_NAME = r'(PYTHON\w*|PIP_\w*|BASH_ENV|ENV|BASH_FUNC_[^\s=]*|LD_\w*|DYLD_\w*|PATH|SHELLOPTS|BASHOPTS)'
SHELL_ASSIGN = re.compile(rf'(?i)(?<![\w$.-]){RISKY_NAME}\+?=')
SHELL_EXPORT = re.compile(rf'(?i)\b(?:export|declare|typeset|local|readonly)\b[^\n;|&]*?(?<![\w$.-]){RISKY_NAME}(?![\w=])')
ALLEXPORT = re.compile(r'(?i)\bset\s+(?:[-+][a-z]*a[a-z]*\b|-o\s+allexport\b)')
CONSUMER_SHELLS = frozenset({'bash', python_env.ADMISSION_SHELL})


def names_venv(text):
    """True when any path component is the validator venv directory, literally or as a glob that matches it."""
    for part in PATH_PART.findall(text.lower()):
        if part == 'validator' or (any(c in part for c in '*?[') and fnmatch.fnmatchcase('validator', part)):
            return True
    return False


def shell_env_names(text):
    """Risky names assigned, exported or env-prefixed by shell text, except the admitted interpreter toggles."""
    names = [m[1] for pattern in (SHELL_ASSIGN, SHELL_EXPORT) for m in pattern.finditer(text)]
    return sorted({n for n in names if n.upper() not in python_env.ALLOWED_PYTHON_ENV})
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
# Each consuming job's literal CI_TOOLS (section 8); bootstrap.yml's rows select every lock tool for their host instead.
JOB_TOOLS = {
    ('agent', 'validate'): 'python,rust', ('agent', 'rustinterop'): 'python,go,rust',
    ('ci', 'route'): 'python', ('ci', 'ci-contracts'): 'python,go', ('ci', 'gitleaks'): 'python', ('ci', 'semgrep'): 'python',
    ('ci', 'ci-required'): 'python', ('console', 'validate'): 'python,node,pnpm,playwright',
    ('copilot-code-review', 'copilot-setup-steps'): 'python,go,rust,node,pnpm', ('design', 'validate'): 'python',
    ('server', 'validate'): 'python,go', ('server', 'race'): 'python,go', ('server', 'fuzz-targets'): 'python',
    ('server', 'fuzz'): 'python,go', ('server', 'loader-gate-a'): 'python,go', ('server', 'loader-gate-b'): 'python,go',
    ('server', 'ocsf-native'): 'python,go',
}


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
            # By variable, `github.path` context or runner file name, in any key of the step.
            if PATH_FILE.search(step_text(step)) and run != python_env.VENV_COMMAND: fail('PATH changes outside the admitted bootstrap forbidden')
            for message in env_write_errors(step): fail(message)
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
        if name != 'bootstrap' and env['CI_TOOLS'] != JOB_TOOLS.get((name, jid)):
            fail(f'CI_TOOLS differs from the reviewed selection {JOB_TOOLS.get((name, jid))!r}')
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
# GOENV is fresh_go.py's `off`: a per-user `go env -w` file could otherwise supply CC, flags or a toolchain.
CACHE_ENV = {'GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOFLAGS', 'GOENV', 'CARGO_TARGET_DIR', 'CARGO_HOME'}


def wrapper_id(run):
    """The selected ID a wrapper step passes with --id, or None for any other step."""
    match = re.search(r'run_selected\.py --id (?:"([^"]+)"|(\S+))', run)
    return (match[1] or match[2]) if match else None


def wrapper_toolchain(run, root):
    """Classify a wrapper step by its selected ID's toolchain in the checked tree; unknown IDs count as both."""
    target_id = wrapper_id(run)
    if target_id is None: return None
    if target_id.startswith('go-fuzz:'): return 'go'
    try: mode = run_selected.inventory(root)[target_id]['mode']
    except (KeyError, OSError, ValueError, TypeError): return 'unknown'
    return 'go' if mode.startswith('go') else 'cargo' if mode.startswith('rust') else 'other'


def cache_errors(data, root):
    """Require fresh compiler environments before every workflow consumer."""
    errors = []
    for jid, job in data.get('jobs', {}).items():
        steps = job.get('steps', [])
        def fail(message): errors.append(f'{jid}: {message}')
        for scope in (data, job, *steps):
            if CACHE_ENV & set(scope.get('env', {})):
                fail('compiler cache environment override forbidden')
        go_setups = [i for i, s in enumerate(steps) if s.get('uses', '').startswith('actions/setup-go@')]
        go_consumers = [i for i, s in enumerate(steps) if re.search(r'\bgo (?:test|vet|env|mod|build|run)\b', s.get('run', '')) or wrapper_toolchain(s.get('run', ''), root) in ('go', 'unknown')]
        cargo_consumers = [i for i, s in enumerate(steps) if re.search(r'\bcargo (?:metadata|build|test|clippy|fetch)\b', s.get('run', '')) or wrapper_toolchain(s.get('run', ''), root) in ('cargo', 'unknown')]
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
            if re.search(r'\benv\s+-i\b|\bunset\s+(?:GOCACHE|GOMODCACHE|GOFLAGS|GOTOOLCHAIN|GOENV|CARGO_TARGET_DIR|CARGO_HOME)\b|\b(?:GOCACHE|GOMODCACHE|GOFLAGS|GOTOOLCHAIN|GOENV|CARGO_TARGET_DIR|CARGO_HOME)\s*=', run):
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


def consumer_env_errors(scope):
    """A closure consumer's `env` must be a literal mapping whose names are all in CONSUMER_ENV."""
    if 'env' not in scope: return []
    env = scope['env']
    if not isinstance(env, dict): return ['environment must be a literal mapping in closure consumer']
    return [f'environment variable outside the closure consumer allowlist: {key}' for key in env if key not in CONSUMER_ENV]


def step_text(step):
    """Everything a step or scope executes or passes on, as the raw strings joined by newlines; display names are not executed.

    Raw strings, not JSON: escaping would turn a line start, tab or continuation into `\\n`, `\\t` or `\\\\` glued to the
    next token, which hides `which`, `validator/` or `sys.executable` from the word-boundary patterns.
    """
    parts = []
    def walk(value):
        if isinstance(value, dict):
            for key, child in value.items(): parts.append(str(key)); walk(child)
        elif isinstance(value, list):
            for child in value: walk(child)
        else:
            parts.append(str(value))
    walk({key: value for key, value in step.items() if key != 'name'})
    return '\n'.join(parts)


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
            run, shell = step.get('run', ''), step.get('shell', '')
            if not isinstance(shell, str) or not isinstance(run, str) or BYPASS_TOKEN.search(shell):
                fail('ad hoc Python environment or package installation forbidden')
                continue
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
            # The receipt step (the aggregate's final verifier, or the end of the Copilot job) follows the re-check
            # directly, so no interpreter, shell or action runs between the verified state and the receipt.
            proofs = [i for i, s in enumerate(steps) if s.get('id') == 'proof']
            receipt = proofs[0] if proofs else len(steps) - 1 if jid == 'ci-required' else len(steps)
            if len(checks) != 1 or checks[0] <= installs[0] or checks[0] + 1 != receipt:
                fail('terminal re-check must immediately precede the receipt')
        for i in venvs + installs + checks:
            step = steps[i]
            if (any(k in step for k in ('if', 'continue-on-error', 'env')) or step.get('shell') != python_env.ADMISSION_SHELL
                    or step.get('working-directory') != '.'):
                fail('closure admission steps must be unconditional at root with the privileged-mode admission shell')
        for scope in (job, *steps):
            for message in consumer_env_errors(scope): fail(message)
        for message in scope_errors(step_text({key: value for key, value in job.items() if key != 'steps'})):
            fail(f'job settings: {message}')
        for scope in (data, job):
            shell = (run_defaults(scope) or {}).get('shell', 'bash')
            if shell != 'bash': fail('closure consumer default shell must be bash')
        for step in steps:
            run, text = step.get('run', ''), step_text(step)
            if step.get('shell', 'bash') not in CONSUMER_SHELLS:
                fail('closure consumer step shell must be bash or the admission shell')
            if WHOLE_GITHUB.search(text):
                fail('whole github context forbidden in closure consumer')
            if PATH_FILE.search(text) and run != python_env.VENV_COMMAND:
                fail('PATH changes outside the admitted venv step forbidden in closure consumer')
            # Besides the fresh cache helpers, only the exact step applying the admitted bootstrap's environment file writes
            # GITHUB_ENV; bootstrap_errors closes its name, keys, inputs and position directly after the bootstrap.
            if ENV_FILE.search(text) and run not in (GO_FRESH, CARGO_FRESH, APPLY_COMMAND):
                fail('environment writes outside the fresh cache helper and admitted bootstrap forbidden in closure consumer')
            if names_venv(text) and run != python_env.VENV_COMMAND:
                fail('validator venv named outside its admitted step in closure consumer')
            if SITE_PROBE.search(text):
                fail('site-packages, scripts directory, base interpreter or start-up hook located in closure consumer')
            for script in (run, step.get('shell', '')):
                for name in shell_env_names(script):
                    fail(f'shell environment forbidden in closure consumer: {name}')
                if ALLEXPORT.search(script):
                    fail('shell allexport forbidden in closure consumer')
    if consuming_workflow:
        for message in consumer_env_errors(data): errors.append(f'workflow: {message}')
        for message in scope_errors(step_text({key: value for key, value in data.items() if key != 'jobs'})):
            errors.append(f'workflow settings: {message}')
    return errors


def scope_errors(text):
    """Runner files, the whole github context, the venv or site probes named in job or workflow settings."""
    found = [label for label, hit in (('runner PATH file', PATH_FILE.search(text)), ('runner environment file', ENV_FILE.search(text)),
                                      ('whole github context', WHOLE_GITHUB.search(text)), ('validator venv', names_venv(text)),
                                      ('site probe', SITE_PROBE.search(text))) if hit]
    return [f'{label} named in closure consumer' for label in found]


def fuzz_evidence_errors(job, root, native_parser=False):
    """Preserve exact fuzz selection, failure exit and minimized corpora."""
    command = COMMANDS[('server', 'loader-gate-a' if native_parser else 'fuzz')][-1]
    try: fuzz_ids = {i for i, t in run_selected.inventory(root).items() if t['mode'] == 'go-fuzz'}
    except (KeyError, OSError, ValueError, TypeError): fuzz_ids = {'loader-fuzz'}
    def fuzzing(run):
        target_id = wrapper_id(run)
        return '-fuzz=' in run or (target_id is not None and (target_id.startswith('go-fuzz:') or target_id in fuzz_ids))
    selected = [step for step in job.get('steps', []) if fuzzing(step.get('run', ''))]
    expected = ({'name': 'Fuzz parser qualification for 60 seconds', 'shell': 'bash', 'working-directory': '.', 'run': command} if native_parser else
                {'name': 'Fuzz for 60 seconds', 'shell': 'bash', 'working-directory': '.',
                 'env': {'FUZZ_PACKAGE': '${{ matrix.package }}', 'FUZZ_TARGET': '${{ matrix.target }}'}, 'run': command})
    errors = []
    if selected != [expected]: errors.append('exact unconditional fuzz command required')
    corpus = {'name': 'Upload failing corpus', 'if': 'failure()', 'uses': UPLOAD,
              'with': {'name': 'loader-gate-a-${{ matrix.os }}' if native_parser else 'go-fuzz-${{ strategy.job-index }}-${{ matrix.target }}',
                       'path': 'server/internal/extensions/loader/testdata/fuzz/FuzzParserQualification/**' if native_parser else '${{ matrix.corpus }}',
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
        matches = [i for i, step in enumerate(steps) if step == {'name': name, 'shell': 'bash', 'working-directory': '.', 'run': run}]
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


def ingest_evidence_errors(job, root):
    """Pin the composite proof, both required inventories and retained diagnostics."""
    errors = []
    expected = [
        {'name': 'Ingest cost model', 'shell': 'bash', 'working-directory': '.', 'run': wrapper('ingest-cost-model')},
        {'name': 'Verify ingest measurement log', 'if': 'always()',
         'run': 'set -euo pipefail\ntest -s "$RUNNER_TEMP/ingest-measurements/cost-model.log"\n'},
        {'name': 'Upload ingest measurements', 'if': 'always()', 'uses': UPLOAD,
         'with': {'name': 'ingest-measurements-${{ github.run_id }}-${{ github.run_attempt }}',
                  'path': '${{ runner.temp }}/ingest-measurements/cost-model.log', 'retention-days': '30', 'if-no-files-found': 'error'}},
    ]
    steps = job.get('steps', [])
    for row in expected:
        if [s for s in steps if s.get('name') == row['name']] != [row]: errors.append('exact ingest proof step required: ' + row['name'])
    positions = [next((i for i,s in enumerate(steps) if s.get('name')==row['name']), -1) for row in expected]
    if positions != sorted(set(positions)) or -1 in positions: errors.append('ingest evidence order changed')
    proof = [s for s in steps if s.get('id')=='proof']
    try: checks = json.loads(proof[0]['env']['CHECKS']) if len(proof)==1 else []
    except (KeyError, ValueError): checks = []
    if checks.count('ingest-cost-model') != 1: errors.append('server-validate must require ingest-cost-model')
    # Parse only the literal CHECKS assignment; do not execute a candidate file.
    import ast
    try:
        tree=ast.parse((root/'scripts/ci/inventory.py').read_text())
        rows=[ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CHECKS' for t in node.targets)]
        if len(rows)!=1 or rows[0].get('server-validate',[]).count('ingest-cost-model')!=1: errors.append('inventory omits ingest-cost-model')
    except (OSError,SyntaxError,ValueError,TypeError): errors.append('invalid ingest check inventory')
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
        for error in cache_errors(data, root): fail(name, error)
        for error in python_errors(data): fail(name, error)
        for error in bootstrap_errors(data, name): fail(name, error)
        for error in cargo_override_errors(data): fail(name, error)
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
    errors += selected_errors(root)
    errors += framing_errors(root)
    errors += cargo_config_errors(root)
    try: selected_ids = set(run_selected.inventory(root))
    except (OSError, ValueError, KeyError, TypeError): selected_ids = set(SELECTED_COMMANDS)
    required_names = {'ci', 'design', 'server', 'agent', 'console', 'bootstrap'}
    for name in required_names - set(workflows): fail(name, 'missing required workflow')
    if not required_names <= set(workflows): return errors
    if not observer_command_valid(root):
        errors.append('scripts/ci/semgrep_observer.py: exact Code/Supply Chain Pro command required')
    errors += ['server: ' + e for e in ingest_evidence_errors(workflows['server'].get('jobs',{}).get('validate',{}),root)]
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
            if unit == 'agent':
                for error in agent_native_errors(job): fail(name, jid + ': ' + error)
            for command in COMMANDS.get((name, jid), ()):
                matches = [s for s in steps if command in s.get('run', '')]
                if not matches or any('if' in step or 'continue-on-error' in step for step in matches):
                    fail(name, f'{jid}: missing unconditional command: {command}')
            proofs = [s for s in steps if s.get('id') == 'proof']
            native = unit in ('loader', 'loader-gate-b', 'ocsf', 'agent', 'bootstrap')
            wanted = (['go-fuzz:${{ matrix.package }}:${{ matrix.target }}'] if jid == 'fuzz' else
                      inventory.checks('agent:windows-x64' if unit == 'agent' else unit + ':linux-x64' if native else unit))
            if len(proofs) != 1 or proofs[0].get('env', {}).get('UNIT') != unit:
                fail(name, f'{jid}: missing leaf proof')
            else:
                try: actual = json.loads(proofs[0].get('env', {}).get('CHECKS', 'null'))
                except ValueError: actual = None
                if actual != wanted or 'if' in proofs[0] or 'required.receipt(' not in proofs[0].get('run', ''):
                    fail(name, f'{jid}: receipt checks mismatch')
                elif (any(check in selected_ids or check.startswith('go-fuzz:') for check in actual)
                      and (AGENT_RECEIPT if unit == 'agent' else RECEIPT_WITH_EVIDENCE) not in proofs[0]['run']):
                    fail(name, f'{jid}: receipt must bind verified selected-run evidence')
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
    helper = [s for s in jobs.get('ci-contracts', {}).get('steps', []) if 'go vet .' in s.get('run', '')]
    if len(helper) != 1 or helper[0].get('working-directory') != 'scripts/ci/gotestdecls' or helper[0].get('shell') != 'bash' or 'if' in helper[0]:
        fail('ci', 'ci-contracts: the Go declaration helper must be formatted and vetted in scripts/ci/gotestdecls')
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
                   or re.search(r'\bgo\s+test\b|run_selected\.py', step.get('run', ''))]
    if race_checks != [{'name': 'Test with race detector', 'shell': 'bash', 'working-directory': '.',
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
        for error in fuzz_evidence_errors(server.get(jid, {}), root, native_parser):
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

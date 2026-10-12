"""Observe four pinned CLI callbacks without changing requests or results.

Account-triaged ignored findings are removed by the vendor before normal JSON.
They remain owner-managed policy authority outside the local finding gate.
"""
import functools
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tomllib

COMMAND = ['semgrep', 'ci', '--code', '--supply-chain', '--pro', '--no-suppress-errors',
           '--verbose', '--disable-nosem', '--disable-version-check', '--metrics=off',
           '--json-output=/out/semgrep.json']
REPOSITORY = 'ricevanta/ricevanta'
STAGE = 'startup'
CALLBACK_FAILURE = None
SUMMARY_OVERFLOW = None
EXCEPTION_CLASSES = {'ValueError','TypeError','KeyError','AttributeError','RuntimeError','PermissionError',
    'FileNotFoundError','JSONDecodeError','UnicodeDecodeError','ImportError','ModuleNotFoundError',
    'SemgrepError','SemgrepCoreError','UnknownLanguageError','InvalidRuleSchemaError',
    'HTTPError','SSLError','ConnectionError','Timeout','TimeoutExpired','CalledProcessError','SystemExit','other'}
# File names and maximum lines verified against the admitted 1.178.0 package.
# They describe vendor code only; no captured path, function or source is kept.
NATIVE_TRACE_MODULES = {'commands/ci.py':1394,'commands/wrapper.py':86,'meta.py':1327,'git.py':609,
    'app/project_config.py':150,'app/scans.py':950,'app/session.py':231,'state.py':170,'settings.py':158,
    'error_handler.py':122,'cli.py':95,'main.py':146,'env.py':210,'util.py':496,
    'verbose_logging.py':69,'console.py':126,'error.py':591,'app/auth.py':116}
NATIVE_OUTPUT_MARKERS = {'scan-initialization':rb'Could not start scan: ',
    'git-command-failed':rb'Command failed with exit code: [0-9]+\r?\n-----\r?\nCommand failed with output:',
    'permission-denied':rb'\[Errno 13\] Permission denied',
    'read-only-filesystem':rb'\[Errno 30\] Read-only file system'}
NATIVE_CORE_ERROR_TYPES = {'LexicalError':'Lexical error','ParseError':'Syntax error','OtherParseError':'Other syntax error',
    'AstBuilderError':'AST builder error','RuleParseError':'Rule parse error','SemgrepWarning':'SemgrepWarning',
    'SemgrepError':'SemgrepError','InvalidRuleSchemaError':'InvalidRuleSchemaError','UnknownLanguageError':'UnknownLanguageError',
    'InvalidYaml':'Invalid YAML','MatchingError':'Internal matching error','SemgrepMatchFound':'Semgrep match found',
    'TooManyMatches_':'Too many matches','FatalError':'Fatal error','Timeout':'Timeout','OutOfMemory':'Out of memory',
    'FixpointTimeout':'Fixpoint timeout','StackOverflow':'Stack overflow','TimeoutDuringInterfile':'Timeout during interfile analysis',
    'OutOfMemoryDuringInterfile':'OOM during interfile analysis','MissingPlugin':'Missing plugin',
    'PatternParseError':'PatternParseError','PartialParsing':'PartialParsing','IncompatibleRule_':'IncompatibleRule',
    'PatternParseError0':'Pattern parse error','IncompatibleRule0':'Incompatible rule','DependencyResolutionError':'DependencyResolutionError'}
NATIVE_ERROR_TYPES = set(NATIVE_CORE_ERROR_TYPES.values())
SKIP_REASONS = {'always_skipped','semgrepignore_patterns_match','cli_include_flags_do_not_match',
                'cli_exclude_flags_match','exceeded_size_limit','analysis_failed_parser_or_internal_error',
                'excluded_by_config','wrong_language','too_big','minified','binary','irrelevant_rule',
                'too_many_matches','Gitignore_patterns_match','Dotfile','Nonexistent_file','insufficient_permissions'}
MAX_PLAN_PAIRS = 2_000_000
MAX_SUMMARY_BYTES = 4_000_000
SUMMARY_FIELDS = ('invocation','testedSha','scanId','products','upload','rules','configuredRules','targets',
    'dependencies','codeRuleLanguages','parserErrors','engine','ignoredTargets','codeWork','proVersion')
CODE_WORK_FIELDS = ('pairs','rules','targets','analyzers','skippedTargets','skippedRules')
SUMMARY_BYTE_FIELDS = SUMMARY_FIELDS + tuple('codeWork.'+field for field in CODE_WORK_FIELDS)
SUMMARY_COUNT_FIELDS = ('configuredSastRules','configuredScaRules','relevantRules','targets','dependencies',
    'ignoredTargets','codePairs','codeRules','codeTargets','codeAnalyzers','coreSkippedTargets','coreSkippedRules',
    'configuredCodeRuleLanguages')


def json_bytes(value):
    return sum(len(chunk.encode('utf-8')) for chunk in json.JSONEncoder(sort_keys=True).iterencode(value))


def summary_size_projection(value):
    if not isinstance(value,dict) or set(value) != {'bytes','fieldBytes','counts'}:return None
    if type(value['bytes']) is not int or not MAX_SUMMARY_BYTES < value['bytes'] <= 2**63-1:return None
    for field,keys in (('fieldBytes',SUMMARY_BYTE_FIELDS),('counts',SUMMARY_COUNT_FIELDS)):
        rows=value[field]
        if not isinstance(rows,dict) or set(rows) != set(keys):return None
        if any(type(number) is not int or not 0 <= number <= 2**63-1 for number in rows.values()):return None
    if any(number > value['bytes'] for number in value['fieldBytes'].values()):return None
    return value


def publish_summary(summary,path):
    global SUMMARY_OVERFLOW
    SUMMARY_OVERFLOW = None
    size = json_bytes(summary)
    if size > MAX_SUMMARY_BYTES:
        work=summary['codeWork'];configured=summary['configuredRules']
        fields={key:json_bytes(summary[key]) for key in SUMMARY_FIELDS}
        fields.update({'codeWork.'+key:json_bytes(work[key]) for key in CODE_WORK_FIELDS})
        counts=dict(configuredSastRules=configured['sast'],configuredScaRules=configured['sca'],
            relevantRules=len(summary['rules']),targets=len(summary['targets']),dependencies=len(summary['dependencies']),
            ignoredTargets=len(summary['ignoredTargets']),codePairs=work['pairs'],codeRules=len(work['rules']),
            codeTargets=len(work['targets']),codeAnalyzers=len(work['analyzers']),coreSkippedTargets=len(work['skippedTargets']),
            coreSkippedRules=len(work['skippedRules']),configuredCodeRuleLanguages=len(summary['codeRuleLanguages']))
        SUMMARY_OVERFLOW = summary_size_projection(dict(bytes=size,fieldBytes=fields,counts=counts))
        raise ValueError('observer-summary-size')
    pending=path.with_suffix('.tmp')
    pending.write_text(json.dumps(summary,sort_keys=True),encoding='utf-8')
    pending.replace(path)


def native_output_projection(stdout,stderr):
    frames=[];seen=set();exceptions=set();categories=set()
    frame_pattern = rb'^  File "/usr/lib/python3\.12/site-packages/semgrep/([a-z_/]+\.py)", line ([0-9]{1,4}), in '
    exception_pattern = rb'^(?:[A-Za-z_][A-Za-z0-9_]*\.)*(' + b'|'.join(name.encode() for name in sorted(EXCEPTION_CLASSES-{'other'})) + rb')(?::|$)'
    for stream in (stdout,stderr):
        for match in re.finditer(frame_pattern,stream,re.MULTILINE):
            if len(frames)==32:break
            module=match[1].decode('ascii');line=int(match[2]);identity=(module,line)
            if module in NATIVE_TRACE_MODULES and 0 < line <= NATIVE_TRACE_MODULES[module] and identity not in seen:
                seen.add(identity);frames.append(dict(module=module,line=line))
        for match in re.finditer(exception_pattern,stream,re.MULTILINE):exceptions.add(match[1].decode('ascii'))
        for name,pattern in NATIVE_OUTPUT_MARKERS.items():
            if re.search(pattern,stream):categories.add(name)
    return dict(frames=frames,exceptionClasses=sorted(exceptions),categories=sorted(categories))


def native_failure_trace(exc):
    # The pinned CLI already captures this traceback even with fail-open off.
    # Its Click context is gone after exit. Read the original error handler
    # still referenced by the admitted wrapper's SystemExit traceback frame.
    # Never resolve a new state or read request headers/bodies/account data.
    try:
        traceback=exc.__traceback__
        for _ in range(64):
            if traceback is None:break
            frame=traceback.tb_frame
            if (frame.f_code.co_filename == '/usr/lib/python3.12/site-packages/semgrep/commands/wrapper.py'
                    and frame.f_code.co_name == 'wrapper' and traceback.tb_lineno == 84):
                handler=frame.f_locals.get('error_handler')
                if handler is None:return None
                error=handler.payload.get('error')
                if type(error) is str and len(error)<=4_000_000:
                    return native_output_projection(b'',error.encode('utf-8'))
                return None
            traceback=traceback.tb_next
    except Exception:pass
    return None


def control_command(mode):
    names = {'required':('code-rules.yaml','code-controls.json'),
             'rust':('code-rules-rust.yaml','code-rust-probe.json'),
             'vue':('code-rules-vue.yaml','code-vue-probe.json')}
    config,report = names[mode]
    return ['semgrep','scan','--oss-only','--no-rewrite-rule-ids','--strict','--disable-nosem',
            '--disable-version-check','--metrics=off','--config=/control/fixtures/security/'+config,
            '--json-output=/out/'+report,'/src']


def rule_id(value):
    if not isinstance(value,str) or not re.fullmatch('[A-Za-z0-9_.:/-]{1,500}',value):
        raise ValueError('observer-rule-id')
    return value


def relative(path):
    value = str(path)
    if value.startswith('/src/'): value = value[5:]
    p = PurePosixPath(value)
    if p.is_absolute() or '..' in p.parts or not p.parts or '\\' in value or any(ord(c)<32 for c in value):
        raise ValueError('observer-path')
    return p.as_posix()


def core_error_projection(errors,converted,rules,paths):
    if not isinstance(errors,list) or not isinstance(converted,list):return dict(status='rejected')
    safe=[]
    for error in errors[:32]:
        kind=getattr(getattr(error,'error_type',None),'kind',None)
        level=getattr(getattr(error,'severity',None),'kind',None)
        row=dict(type=NATIVE_CORE_ERROR_TYPES.get(kind,'unknown') if isinstance(kind,str) else 'unknown',
                 level={'Error_':'error','Warning_':'warn','Info_':'info'}.get(level,'unknown') if isinstance(level,str) else 'unknown')
        rule=getattr(getattr(error,'rule_id',None),'value',None)
        if isinstance(rule,str) and rule in rules:row['rule']=rule
        path=getattr(getattr(getattr(error,'location',None),'path',None),'value',None)
        if isinstance(path,str):
            try:
                path=relative(path)
                # Bound JSON content including escapes, plus its two quotes.
                if path in paths and len(json.dumps(path,ensure_ascii=False).encode('utf-8'))<=1002:row['path']=path
            except (ValueError,UnicodeError):pass
        safe.append(row)
    return dict(status='present',errorCount=len(errors),convertedErrorCount=len(converted),errors=safe)


class Observer:
    def __init__(self, invocation, sha):
        if not re.fullmatch('[0-9a-f]{32}', invocation) or not re.fullmatch('[0-9a-f]{40}', sha):
            raise ValueError('observer-identity')
        self.invocation = invocation
        self.sha = sha
        self.handler = None
        self.scan_id = None
        self.started = False
        self.finished = False
        self.data = {}
        self.core_seen = False
        self.core_active = False
        self.plan_seen = False
        self.core_rules = None
        self.plan_tasks = []
        self.plan_paths = set()
        self.code_work = None
        self.failure = None
        self.core_errors = None

    def observe(self, callback, *args):
        try:return callback(*args)
        except BaseException as exc:
            if self.failure is None:
                reason = exc.args[0] if type(exc) is ValueError and exc.args and isinstance(exc.args[0],str) and exc.args[0] in FAILURE_REASONS else 'observer-native-failure'
                name = type(exc).__name__
                self.failure = dict(reason=reason,stage=STAGE,exceptionClass=name if name in EXCEPTION_CLASSES else 'other')
                if self.core_errors is not None:self.failure['coreErrors']=self.core_errors
            raise

    def start(self, handler, metadata, config, original):
        global STAGE
        if self.started: raise ValueError('observer-duplicate-start')
        self.started = True
        STAGE = 'start-scan-request'
        returned = original(handler, metadata, config)
        STAGE = 'start-scan-validation'
        if (metadata.commit is None or metadata.commit.value != self.sha or metadata.repository != REPOSITORY
                or metadata.is_full_scan is not True or metadata.is_code_scan is not True
                or metadata.is_sca_scan is not True or metadata.is_secrets_scan is not False):
            raise ValueError('observer-project-identity')
        requested = [p.to_json() for p in handler.scan_metadata.requested_products]
        if sorted(requested) != ['sast','sca'] or sorted(handler.enabled_products) != ['sast','sca']:
            raise ValueError('observer-products')
        if handler.dry_run or handler.load_saved_scan_config_path is not None or handler.is_partial_scan or handler.project_merge_base is not None:
            raise ValueError('observer-full-scan-mode')
        if type(handler.scan_id) is not int or handler.scan_id <= 0: raise ValueError('observer-scan-id')
        self.handler = handler
        self.scan_id = handler.scan_id
        STAGE = 'scan-configured'
        return returned

    def complete(self, handler, kwargs, original):
        global STAGE
        STAGE = 'report-validation'
        if not self.started or self.handler is not handler or handler.scan_id != self.scan_id or self.finished:
            raise ValueError('observer-completion-identity')
        self.finished = True
        if self.code_work is None or self.core_active: raise ValueError('observer-code-execution-missing')
        if kwargs['dependency_parser_errors'] or kwargs['skipped_paths'] or not kwargs['engine_requested'].is_pro:
            raise ValueError('observer-incomplete-scan')
        rules = {};languages = {};configured = dict(sast=0,sca=0)
        for rule in kwargs['rules']:
            identity = rule_id(rule.id)
            product = rule.product.to_json()
            if product not in ('sast','sca') or identity in rules: raise ValueError('observer-rule-product')
            rules[identity] = product;configured[product] += 1
            for language in set(rule.languages):
                if not isinstance(language,str) or not re.fullmatch('[a-z0-9_+-]{1,40}',language): raise ValueError('observer-rule-product')
                if product == 'sast':
                    languages[language] = languages.get(language,0) + 1
        targets = sorted({relative(t.fpath) for t in kwargs['targets']})
        if any(rules.get(rule) != 'sast' for rule in self.code_work['rules']) or not set(self.code_work['targets']) <= set(targets):
            raise ValueError('observer-code-execution-mismatch')
        relevant = set(self.code_work['rules']) | set(self.code_work['skippedRules'])
        relevant.update(row['rule'] for row in self.code_work['skippedTargets'] if 'rule' in row)
        for partition in (kwargs['matches_by_rule'].kept,kwargs['matches_by_rule'].removed):
            if not isinstance(partition,dict):raise ValueError('observer-rule-product')
            for rule,matches in partition.items():
                if not isinstance(matches,list):raise ValueError('observer-rule-product')
                if not matches:continue
                identity = rule_id(rule.id)
                if rules.get(identity) != rule.product.to_json() or any(match.rule_id != identity for match in matches):
                    raise ValueError('observer-rule-product')
                relevant.add(identity)
        if not relevant <= set(rules):raise ValueError('observer-rule-product')
        rules = {identity:rules[identity] for identity in relevant}
        dependencies = {}
        for path, packages in kwargs['lockfile_dependencies'].items():
            path = relative(path)
            if path in dependencies or not isinstance(packages,list): raise ValueError('observer-dependencies')
            if path == 'branding/requirements-build.txt':
                if len(packages) != 1:raise ValueError('observer-dependencies')
                try:
                    package = packages[0]
                    if package.package != 'defusedxml' or package.version != '0.7.1' or package.ecosystem.to_json() != 'pypi':
                        raise ValueError('observer-package-version')
                except (AttributeError,TypeError) as exc:
                    raise ValueError('observer-package-version') from exc
            if any(not isinstance(p.package,str) or not p.package or not isinstance(p.version,str) or not p.version for p in packages):
                raise ValueError('observer-package-version')
            dependencies[path] = len(packages)
        if 'branding/requirements-build.txt' not in dependencies:raise ValueError('observer-dependencies')
        ignored = sorted({relative(t.fpath) for t in kwargs['ignored_targets']})
        STAGE = 'upload-request'
        returned = original(handler, **kwargs)
        STAGE = 'upload-validation'
        if returned.success is not True: raise ValueError('observer-upload-incomplete')
        if handler.scan_id != self.scan_id: raise ValueError('observer-scan-id-changed')
        self.data = dict(invocation=self.invocation, testedSha=self.sha, scanId=self.scan_id,
                         products=['sast','sca'], upload=True, rules=rules, configuredRules=configured, targets=targets,
                         dependencies=dependencies, codeRuleLanguages=languages, parserErrors=0, engine='PRO', ignoredTargets=ignored)
        self.data['codeWork'] = self.code_work
        STAGE = 'upload-complete'
        return returned

    def plan(self, plan, original):
        global STAGE
        if self.core_active: STAGE = 'plan-serialization'
        returned = original(plan)
        # Display-only serialization carries no execution authority.
        if not self.core_active: return returned
        STAGE = 'plan-validation'
        if self.plan_seen or plan.rules is not self.core_rules: raise ValueError('observer-plan-identity')
        self.plan_seen = True
        payload = returned.to_json()
        if not isinstance(payload,list) or len(payload) != 2 or payload[0] != 'Targets' or not isinstance(payload[1],list) or len(payload[1]) != len(plan.target_mappings):
            raise ValueError('observer-plan-evidence')
        identities = [rule_id(rule.id) for rule in plan.rules]
        if len(set(identities)) != len(identities): raise ValueError('observer-plan-evidence')
        products = [rule.product.to_json() for rule in plan.rules]
        if any(product not in ('sast','sca') for product in products): raise ValueError('observer-plan-evidence')
        total = 0;seen = set()
        for task,encoded in zip(plan.target_mappings,payload[1]):
            if not isinstance(encoded,list) or len(encoded) != 2 or encoded[0] != 'CodeTarget': raise ValueError('observer-plan-evidence')
            row = encoded[1]
            path = relative(row['path']['fpath']);language = row['analyzer']
            if not isinstance(language,str) or not re.fullmatch('[a-z0-9_+-]{1,40}',language): raise ValueError('observer-plan-evidence')
            native_products = row['products']
            if not isinstance(native_products,list) or any(p not in ('sast','sca') for p in native_products) or len(set(native_products)) != len(native_products):
                raise ValueError('observer-plan-evidence')
            if path != relative(task.path.fpath) or language != task.analyzer or set(native_products) != {p.to_json() for p in task.products}:
                raise ValueError('observer-plan-evidence')
            if (path,language) in seen: raise ValueError('observer-plan-evidence')
            seen.add((path,language))
            indices = task.rule_nums
            if not isinstance(indices,tuple) or any(type(i) is not int or i < 0 or i >= len(identities) for i in indices) or len(set(indices)) != len(indices):
                raise ValueError('observer-plan-rule-index')
            if any(products[i] not in native_products for i in indices): raise ValueError('observer-plan-evidence')
            code_rules = tuple(identities[i] for i in indices if products[i] == 'sast')
            total += len(code_rules)
            if total > MAX_PLAN_PAIRS or len(seen) > 100_000: raise ValueError('observer-plan-budget')
            if code_rules: self.plan_tasks.append((path,language,code_rules))
        self.plan_paths={path for path,language in seen}
        STAGE = 'plan-complete'
        return returned

    def core(self, runner, args, kwargs, original):
        global STAGE
        STAGE = 'core-invocation'
        if self.handler is None or self.finished or self.core_seen: raise ValueError('observer-core-identity')
        bound = inspect.signature(original).bind(runner,*args,**kwargs).arguments
        if not bound['engine'].is_pro or bound['run_secrets'] or bound['target_mode_config'].is_historical_scan:
            raise ValueError('observer-core-mode')
        self.core_seen = True;self.core_active = True;self.core_rules = bound['rules']
        try: returned = original(runner,*args,**kwargs)
        finally: self.core_active = False
        STAGE = 'core-result-validation'
        if not self.plan_seen or not isinstance(returned,tuple) or len(returned) != 3:
            raise ValueError('observer-code-execution-missing')
        core = returned[2].core
        if returned[1] or core.errors:
            try:self.core_errors=core_error_projection(core.errors,returned[1],{rule.id for rule in self.core_rules},self.plan_paths)
            except Exception:self.core_errors=dict(status='rejected')
            raise ValueError('observer-core-errors')
        if not isinstance(core.paths.scanned,list) or not isinstance(core.skipped_rules,list) or core.paths.skipped is not None and not isinstance(core.paths.skipped,list):
            raise ValueError('observer-core-evidence')
        scanned = {relative(p.value) for p in core.paths.scanned}
        known_rules = {rule_id(rule.id) for rule in self.core_rules}
        skipped_rules = {rule_id(r.rule_id.value) for r in core.skipped_rules}
        if not skipped_rules <= known_rules: raise ValueError('observer-core-evidence')
        skip_pairs = set();skips = []
        for skip in core.paths.skipped or []:
            path = relative(skip.path.value);reason = skip.reason.to_json()
            if not isinstance(reason,str) or reason not in SKIP_REASONS: raise ValueError('observer-core-evidence')
            rule = None if skip.rule_id is None else rule_id(skip.rule_id.value)
            if rule is not None and rule not in known_rules: raise ValueError('observer-core-evidence')
            skip_pairs.add((path,rule))
            row = dict(path=path,reason=reason)
            if rule is not None: row['rule'] = rule
            skips.append(row)
        rules = set();targets = set();analyzers = {};pairs = 0
        for path,language,task_rules in self.plan_tasks:
            if path not in scanned or (path,None) in skip_pairs: continue
            retained = [rule for rule in task_rules if rule not in skipped_rules and (path,rule) not in skip_pairs]
            if not retained: continue
            count = analyzers.setdefault(language,dict(pairs=0,rules=set(),targets=set()))
            count['pairs'] += len(retained);count['rules'].update(retained);count['targets'].add(path)
            pairs += len(retained);rules.update(retained);targets.add(path)
        if not pairs: raise ValueError('observer-code-work-empty')
        self.code_work = dict(pairs=pairs,rules=sorted(rules),targets=sorted(targets),
            analyzers={language:dict(pairs=count['pairs'],rules=len(count['rules']),targets=len(count['targets'])) for language,count in analyzers.items()},
            skippedTargets=skips,skippedRules=sorted(skipped_rules))
        self.plan_tasks = [];self.plan_paths = set();self.core_rules = None
        STAGE = 'core-complete'
        return returned

    def summary(self):
        if not self.data: raise ValueError('observer-missing-completion')
        return self.data

    def install(self, handler_class, runner_class, plan_class):
        start = handler_class.start_scan
        complete = handler_class.report_findings
        if list(inspect.signature(start).parameters) != ['self','project_metadata','project_config']:
            raise ValueError('observer-start-interface')
        expected = ['self','matches_by_rule','rules','targets','skipped_paths','renamed_targets',
                    'ignored_targets','cli_suggested_exit_code','parse_rate','total_time','commit_date',
                    'lockfile_dependencies','dependency_parser_errors','changed_dependency_sources',
                    'all_subprojects','contributions','engine_requested','progress_bar','disable_nosem']
        if list(inspect.signature(complete).parameters) != expected: raise ValueError('observer-complete-interface')
        core = runner_class.invoke_semgrep_core;plan = plan_class.to_targets
        core_expected = ['self','target_manager','rules','dump_command_for_core','time_flag','matching_explanations',
                         'engine','strict','run_secrets','disable_secrets_validation','target_mode_config','all_subprojects','x_parmap']
        if list(inspect.signature(core).parameters) != core_expected or list(inspect.signature(plan).parameters) != ['self']:
            raise ValueError('observer-core-interface')
        @functools.wraps(start)
        def observed_start(handler, project_metadata, project_config):
            return self.observe(self.start,handler,project_metadata,project_config,start)
        @functools.wraps(complete)
        def observed_complete(handler, **kwargs):
            return self.observe(self.complete,handler,kwargs,complete)
        handler_class.start_scan = observed_start
        handler_class.report_findings = observed_complete
        @functools.wraps(core)
        def observed_core(runner,*args,**kwargs):
            return self.observe(self.core,runner,args,kwargs,core)
        @functools.wraps(plan)
        def observed_plan(instance):
            return self.observe(self.plan,instance,plan)
        runner_class.invoke_semgrep_core = observed_core
        plan_class.to_targets = observed_plan


def admitted_pro(lock):
    from semgrep import __VERSION__
    from semgrep.engine import EngineType
    from semgrep.semgrep_core import SemgrepCore
    pin = lock['pro']
    if __VERSION__ != lock['semgrep']['version']: raise ValueError('observer-cli-version')
    path = Path(pin['path'])
    if path.is_symlink() or not path.is_file() or path.stat().st_size != pin['bytes']:
        raise ValueError('observer-pro-size')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while block := stream.read(1024*1024): digest.update(block)
    if digest.hexdigest() != pin['sha256']: raise ValueError('observer-pro-digest')
    if SemgrepCore.pro_path() != path or SemgrepCore.pro_version_stamp_path().read_bytes() != pin['marker'].encode():
        raise ValueError('observer-pro-marker')
    engine = EngineType.PRO_INTERFILE
    if not engine.check_if_installed() or not engine.check_is_correct_pro_version(): raise ValueError('observer-pro-installation')
    version = engine.get_pro_version()
    if not isinstance(version,str) or not re.fullmatch('[A-Za-z0-9_.+ -]{1,100}',version):
        raise ValueError('observer-pro-version')
    return version


def invoke_scanner(observer,handler_class,runner_class,plan_class,entrypoint):
    global CALLBACK_FAILURE
    CALLBACK_FAILURE = None
    observer.install(handler_class,runner_class,plan_class)
    previous = sys.argv
    sys.argv = COMMAND[:]
    try:
        try: entrypoint()
        except SystemExit as exc:
            if exc.code not in (None,0): raise
        return observer.summary()
    except BaseException:
        CALLBACK_FAILURE = observer.failure
        raise
    finally:
        sys.argv = previous


def main():
    global STAGE
    STAGE = 'startup'
    allowed = {'HOME','PATH','SEMGREP_APP_TOKEN','SEMGREP_REPO_NAME','SEMGREP_REPO_URL',
               'SEMGREP_COMMIT','SEMGREP_BRANCH','SEMGREP_JOB_URL'}
    environment = {k:v for k,v in os.environ.items() if k in allowed}
    os.environ.clear();os.environ.update(environment)
    if sys.argv[1:] != ['--scan'] and 'SEMGREP_APP_TOKEN' in os.environ:
        raise ValueError('observer-control-credential')
    home = Path(os.environ['HOME'])
    home.mkdir(parents=True,exist_ok=True)
    (home/'.gitconfig').write_text('[safe]\n\tdirectory = /src\n')
    lock = tomllib.loads(Path('/control/security-tools.toml').read_text())
    STAGE = 'bundled-pro'
    version = admitted_pro(lock)
    if sys.argv[1:] == ['--admission']:
        Path('/out/pro.json').write_text(json.dumps({'version':version,'sha256':lock['pro']['sha256']}))
        return
    cold_modes = {'--controls':'required','--probe-rust':'rust','--probe-vue':'vue'}
    if len(sys.argv) == 2 and sys.argv[1] in cold_modes:
        STAGE = 'code-controls'
        sys.argv = control_command(cold_modes[sys.argv[1]])
        from semgrep.main import main as semgrep_main
        semgrep_main()
        return
    if sys.argv[1:] != ['--scan']: raise ValueError('observer-command')
    context = json.loads(Path('/out/context.json').read_text())
    observer = Observer(context['invocation'],context['testedSha'])
    from semgrep.app.scans import ScanHandler
    from semgrep.core_runner import CoreRunner
    from semgrep.core_targets_plan import Plan
    from semgrep.main import main as semgrep_main
    STAGE = 'authenticated-scan'
    summary = invoke_scanner(observer,ScanHandler,CoreRunner,Plan,semgrep_main)
    summary['proVersion'] = version
    publish_summary(summary,Path('/out/observer.json'))


FAILURE_REASONS = {'observer-pro-marker', 'observer-path', 'observer-scan-id-changed', 'observer-pro-version', 'observer-missing-completion', 'observer-pro-digest', 'observer-duplicate-start', 'observer-incomplete-scan', 'observer-dependencies', 'observer-full-scan-mode', 'observer-pro-size', 'observer-project-identity', 'observer-command', 'observer-rule-id', 'observer-pro-installation', 'observer-start-interface', 'observer-summary-size', 'observer-upload-incomplete', 'observer-scan-id', 'observer-rule-product', 'observer-completion-identity', 'observer-products', 'observer-cli-version', 'observer-package-version', 'observer-identity', 'observer-complete-interface'}
FAILURE_REASONS.update({'observer-code-execution-missing','observer-code-execution-mismatch','observer-code-work-empty',
    'observer-plan-identity','observer-plan-evidence','observer-plan-rule-index','observer-plan-budget',
    'observer-core-identity','observer-core-mode','observer-core-errors','observer-core-evidence','observer-core-interface',
    'observer-control-credential'})

def run():
    global CALLBACK_FAILURE, SUMMARY_OVERFLOW
    CALLBACK_FAILURE = None
    SUMMARY_OVERFLOW = None
    exit_status = 1
    try: main()
    except SystemExit as exc:
        if exc.code in (None,0): raise
        native_exception=exc
        failure = dict(reason='observer-cli-exit',stage=STAGE,exceptionKind='cli-exit')
        if type(exc.code) is int:
            failure['processExit'] = exc.code
            exit_status = exc.code
    except Exception as exc:
        native_exception=exc
        reason = exc.args[0] if type(exc) is ValueError and exc.args and isinstance(exc.args[0],str) and exc.args[0] in FAILURE_REASONS else 'observer-native-failure'
        kind = {ValueError:'value',ImportError:'import',ModuleNotFoundError:'import',FileNotFoundError:'file',PermissionError:'permission',json.JSONDecodeError:'json'}.get(type(exc),'native')
        failure = dict(reason=reason,stage=STAGE,exceptionKind=kind)
    else: return
    if CALLBACK_FAILURE is not None: failure['callback'] = CALLBACK_FAILURE
    if failure['reason'] == 'observer-summary-size' and SUMMARY_OVERFLOW is not None:
        failure['summarySize'] = SUMMARY_OVERFLOW
    if STAGE == 'authenticated-scan':
        trace=native_failure_trace(native_exception)
        if trace is not None:failure['trace']=trace
    try: Path('/out/observer-failure.json').write_text(json.dumps(failure,ensure_ascii=False),encoding='utf-8')
    except OSError: pass
    print('Semgrep evidence qualification failed: ' + failure['reason'],file=sys.stderr)
    raise SystemExit(exit_status)


if __name__ == '__main__': run()

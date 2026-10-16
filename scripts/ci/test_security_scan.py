"""Scanner boundary tests use synthetic bytes, never service credentials."""
import unittest
import inventory
import required

class MandatorySecurityTests(unittest.TestCase):
    def test_docs_select_both_direct_scanners(self):
        self.assertTrue({'gitleaks', 'semgrep'} <= set(inventory.select_groups(['README.md'])))
        self.assertEqual(inventory.checks('gitleaks'), ['gitleaks-admission', 'gitleaks-history', 'gitleaks-tree', 'gitleaks-gate'])
        self.assertEqual(inventory.checks('semgrep'), ['semgrep-admission', 'semgrep-code', 'semgrep-supply-chain', 'semgrep-gate'])

    def test_aggregate_requires_scanners(self):
        self.assertTrue({'gitleaks', 'semgrep'} <= set(required.NEEDS))


class AdmissionTests(unittest.TestCase):
    def module(self):
        import security_scan
        return security_scan

    def test_exact_payload_bytes(self):
        import hashlib
        scan = self.module()
        payload = b'synthetic executable'
        pin = {'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}
        scan.verify_bytes(payload, pin)
        for bad in (dict(pin, bytes=1), dict(pin, sha256='0'*64)):
            with self.assertRaises(ValueError): scan.verify_bytes(payload, bad)

    def test_archive_traversal_and_links(self):
        import io, tarfile, tempfile
        from pathlib import Path
        scan = self.module()
        for name, kind in (('../gitleaks', tarfile.REGTYPE), ('gitleaks', tarfile.SYMTYPE)):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                member = tarfile.TarInfo(name); member.type = kind; member.linkname = '/bin/sh'
                member.size = 1 if kind == tarfile.REGTYPE else 0
                archive.addfile(member, io.BytesIO(b'x'))
            with tempfile.TemporaryDirectory() as tmp, self.assertRaises(ValueError):
                scan.extract_gitleaks(stream.getvalue(), Path(tmp))

    def test_archive_rejects_nonregular_members_and_size_count_limits_before_extraction(self):
        import io,tarfile,tempfile
        from pathlib import Path
        from unittest.mock import patch
        scan=self.module()
        stream=io.BytesIO()
        with tarfile.open(fileobj=stream,mode='w:gz'):pass
        regular=tarfile.TarInfo('gitleaks')
        oversized=tarfile.TarInfo('gitleaks');oversized.size=40_000_001
        cases=[[],[regular]*101,[oversized]]
        for kind in (tarfile.DIRTYPE,tarfile.LNKTYPE,tarfile.FIFOTYPE,tarfile.CHRTYPE):
            member=tarfile.TarInfo('gitleaks');member.type=kind;cases.append([member])
        for name in ('/gitleaks','nested/gitleaks'):
            cases.append([tarfile.TarInfo(name)])
        for members in cases:
            with self.subTest(count=len(members)),tempfile.TemporaryDirectory() as tmp, \
                 patch.object(tarfile.TarFile,'getmembers',return_value=members), \
                 patch.object(tarfile.TarFile,'extractall') as extract, self.assertRaises(ValueError):
                scan.extract_gitleaks(stream.getvalue(),Path(tmp))
            extract.assert_not_called()

    def test_valid_archive_preserves_file_bytes_and_executable_mode(self):
        import io,os,stat,tarfile,tempfile
        from pathlib import Path
        scan=self.module();stream=io.BytesIO();payload=b'synthetic executable'
        with tarfile.open(fileobj=stream,mode='w:gz') as archive:
            member=tarfile.TarInfo('gitleaks');member.size=len(payload)
            archive.addfile(member,io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as tmp:
            binary=scan.extract_gitleaks(stream.getvalue(),Path(tmp))
            self.assertEqual(binary.read_bytes(),payload)
            if os.name!='nt':self.assertEqual(stat.S_IMODE(binary.stat().st_mode),0o700)

    def test_fork_dependabot_and_tag_preflight(self):
        from copy import deepcopy
        scan = self.module()
        env = {'GITHUB_REPOSITORY': 'ricevanta/ricevanta', 'GITHUB_REPOSITORY_ID': '123'}
        event = {'repository': {'id': 123, 'full_name': env['GITHUB_REPOSITORY']},
                 'number': 7, 'pull_request': {'user': {'login': 'maintainer'},
                 'base': {'repo': {'id': 123}}, 'head': {'repo': {'id': 123}}}}
        self.assertEqual(scan.preflight('pull_request', event, env), 7)
        fork = deepcopy(event); fork['pull_request']['head']['repo']['id'] = 124
        bot = deepcopy(event); bot['pull_request']['user']['login'] = 'dependabot[bot]'
        for bad in (fork, bot):
            with self.assertRaises(ValueError): scan.preflight('pull_request', bad, env)
        with self.assertRaises(ValueError): scan.preflight('push', dict(event, ref='refs/tags/v1'), env)
        self.assertIsNone(scan.preflight('push', dict(event, ref='refs/heads/master'), env))

    def test_duplicate_json_and_nonfinite(self):
        scan = self.module()
        for text in ('{"results":[],"results":[]}', '{"x":NaN}', '', '[] trailing'):
            with self.assertRaises(ValueError): scan.decode_json(text)

    def test_environment_never_inherits_github_or_overrides(self):
        scan = self.module()
        env = scan.scanner_environment({'testedSha': 'a'*40, 'runId': '123', 'runAttempt': '2'}, 7, 'synthetic')
        self.assertEqual(env['SEMGREP_COMMIT'], 'a'*40)
        self.assertEqual(env['SEMGREP_BRANCH'], 'ci/pr/7/' + 'a'*40)
        self.assertFalse(any(key.startswith('GITHUB_') for key in env))
        self.assertEqual(env['SEMGREP_APP_TOKEN'], 'synthetic')
        self.assertNotIn('SEMGREP_BASELINE_COMMIT', env)

    def test_nonzero_timeout_and_output_are_private(self):
        import sys
        scan = self.module()
        for code in ('print("synthetic-sensitive");raise SystemExit(1)', 'import time; time.sleep(2)'):
            with self.assertRaises(ValueError) as caught:
                scan.execute([sys.executable, '-c', code], {}, timeout=.05)
            self.assertNotIn('synthetic-sensitive', str(caught.exception))

    def test_stdout_and_stderr_have_one_hard_private_capture_budget(self):
        import sys
        from unittest.mock import patch
        scan = self.module()
        with patch.object(scan,'MAX_CAPTURE_BYTES',4096,create=True):
            for code in ('import os;os.write(1,b"s"*4097)',
                         'import os;os.write(2,b"s"*4097)',
                         'import os;os.write(1,b"s"*3000);os.write(2,b"s"*3000)'):
                with self.subTest(code=code):
                    with self.assertRaises(ValueError) as caught:
                        scan.captured_process([sys.executable,'-c',code],{},timeout=5)
                    self.assertEqual(scan.failure_code(caught.exception),'scanner-output-limit-exceeded')
            process=scan.captured_process([sys.executable,'-c','import os;os.write(1,b"a"*2048);os.write(2,b"b"*2048)'],{},timeout=5)
            self.assertEqual(process.stdout,b'a'*2048)
            self.assertEqual(process.stderr,b'b'*2048)


class ScannerEvidenceTests(unittest.TestCase):
    def test_lock_closed_and_platform_version(self):
        import security_scan as scan
        from copy import deepcopy
        pin = scan.load_lock(inventory.ROOT)
        self.assertEqual(pin['gitleaks']['version'], '8.30.1')
        for tool, key, val in (('semgrep', 'version', 'latest'), ('pro', 'bytes', 0),
                               ('gitleaks', 'url', 'https://attacker.invalid/tool'), ('pro', 'extra', 1)):
            bad = deepcopy(pin); bad[tool][key] = val
            with self.assertRaises(ValueError): scan.validate_lock(bad)
        good = {'Id': pin['semgrep']['config'], 'Os': 'linux', 'Architecture': 'amd64'}
        scan.validate_image([good], pin['semgrep'])
        for key, val in (('Id', 'sha256:'+'0'*64), ('Os', 'windows'), ('Architecture', 'arm64')):
            with self.assertRaises(ValueError): scan.validate_image([dict(good, **{key: val})], pin['semgrep'])

    def test_gitleaks_completion_and_redaction(self):
        import security_scan as scan
        scan.gitleaks_evidence([], b'INF 3 commits scanned.\nINF no leaks found', 'git')
        scan.gitleaks_evidence([], b'INF scanned ~40 bytes\nINF no leaks found', 'dir')
        for report, log, mode in (([], b'', 'git'), ([], b'0 commits scanned.\nno leaks found', 'git'),
                                  ([], b'no leaks found', 'dir'), ([{'Secret':'synthetic'}], b'', 'git')):
            with self.assertRaises(ValueError): scan.gitleaks_evidence(report, log, mode)

    def test_findings_gate_monitor_mode_rust_and_lower_severity(self):
        import security_scan as scan
        result = {'check_id': 'synthetic-rule', 'path': 'agent/example.rs', 'start': {'line': 2},
                  'extra': {'severity': 'HIGH', 'metadata': {'product': 'sca', 'dev.semgrep.actions': ['monitor']},
                            'lines': 'private synthetic source', 'message': 'private synthetic text'}}
        with self.assertRaises(ValueError): scan.findings_gate([result])
        result['extra']['severity'] = 'WARNING'
        safe = scan.findings_gate([result])
        self.assertEqual(safe, [{'rule': 'synthetic-rule', 'path': 'agent/example.rs', 'line': 2,
                                 'severity': 'WARNING', 'product': 'sca'}])
        self.assertNotIn('private', str(safe))
        for key, value in (('severity', 'unknown'), ('metadata', {'product': 'secrets'})):
            bad = dict(result, extra=dict(result['extra'], **{key:value}))
            with self.assertRaises(ValueError): scan.findings_gate([bad])

    def test_high_finding_evidence_validates_all_results_and_prioritizes_blockers(self):
        import security_scan as scan
        def finding(severity):
            return dict(check_id='synthetic-rule',path='server/a.go',start={'line':2},
                extra=dict(severity=severity,metadata={'product':'sast','token':'synthetic-sensitive-token'},
                           message='private source',lines='account-config'))
        results=[finding('WARNING') for _ in range(40)]+[finding('HIGH')]
        with self.assertRaises(scan.GateFailure) as caught:scan.findings_gate(results)
        evidence=caught.exception.safe
        self.assertEqual(scan.failure_code(caught.exception),'active-high-findings')
        self.assertEqual(evidence['total'],41);self.assertEqual(evidence['blocking'],1);self.assertEqual(evidence['lower'],40)
        self.assertEqual(evidence['byProduct'],{'sast':41,'sca':0})
        self.assertEqual(evidence['bySeverity']['HIGH'],1);self.assertEqual(evidence['bySeverity']['WARNING'],40)
        self.assertEqual(evidence['sampleLimit'],32);self.assertEqual(evidence['sampleCount'],32);self.assertEqual(evidence['omittedCount'],9)
        self.assertEqual(evidence['identities'][0],dict(rule='synthetic-rule',path='server/a.go',line=2,severity='HIGH',product='sast'))
        for severity in ('UNKNOWN',None):
            with self.subTest(severity=severity),self.assertRaises(ValueError) as malformed:
                scan.findings_gate([finding('HIGH'),finding(severity)])
            self.assertNotIsInstance(malformed.exception,scan.GateFailure)

    def test_high_finding_metadata_has_full_escaped_byte_bound_and_explicit_omissions(self):
        import json
        from copy import deepcopy
        import security_scan as scan
        path='repo/'+('"'*123+'/')*4+'a'*7
        self.assertEqual(len(json.dumps(path).encode()),1002)
        result=dict(check_id='r'*500,path=path,start={'line':2**63-1},
            extra=dict(severity='CRITICAL',metadata={'product':'sca','sca-vuln-database-identifier':'CVE-2026-'+'9'*19},
                       message='synthetic-sensitive-token',lines='private source'))
        with self.assertRaises(scan.GateFailure) as caught:scan.findings_gate([deepcopy(result) for _ in range(32)])
        evidence=caught.exception.safe;self.assertEqual(evidence['sampleCount'],32)
        worst=deepcopy(evidence)
        for field in ('total','high','excepted','blocking','lower','sampleCount','omittedCount'):worst[field]=2**63-1
        for field in ('byProduct','bySeverity'):
            worst[field]={key:2**63-1 for key in worst[field]}
        envelope=dict(unit='semgrep',phase='scan',result='failure',reason='active-high-findings',findings=worst)
        # EXPERIMENT is the longest allowed severity spelling; include the output newline.
        for row in worst['identities']:row['severity']='EXPERIMENT'
        self.assertLessEqual(len(json.dumps(envelope).encode())+1,65536)
        for value in ('synthetic-sensitive-token','private source'):
            self.assertNotIn(value,json.dumps(evidence))
        oversized=deepcopy(result);oversized['path']='repo/'+('"'*124+'/')*7+'"'*120
        huge_line=deepcopy(result);huge_line['start']['line']=2**63
        with self.assertRaises(scan.GateFailure) as omitted:scan.findings_gate([oversized,huge_line,result])
        self.assertEqual(omitted.exception.safe['total'],3);self.assertEqual(omitted.exception.safe['blocking'],3)
        self.assertEqual(omitted.exception.safe['sampleCount'],1);self.assertEqual(omitted.exception.safe['omittedCount'],2)

    def test_sca_failure_samples_project_only_canonical_advisory_identifiers(self):
        import json
        import security_scan as scan
        cases=[('CVE-2026-93687','recognized'),('CVE-2026-'+'9'*19,'recognized'),
               ('GHSA-vfj7-8cjw-p6xm','recognized'),(None,'unrecognized'),(False,'unrecognized'),
               (17,'unrecognized'),({'token':'synthetic-sensitive-token'},'unrecognized'),
               ('synthetic-sensitive-token'*10000,'unrecognized'),('prefix-CVE-2026-93687','unrecognized'),
               ('CVE-2026-93687-suffix','unrecognized'),('CVE-2026-93687\n','unrecognized'),
               ('cve-2026-93687','unrecognized'),('CVE-2026-123','unrecognized'),
               ('CVE-2026-'+'9'*20,'unrecognized'),('GHSA-aaaa-aaaa-aaaa','unrecognized')]
        for value,status in cases:
            metadata={'product':'sca','sca-vuln-database-identifier':value,'token':'synthetic-sensitive-token'}
            result=dict(check_id='synthetic-sca',path='console/pnpm-lock.yaml',start={'line':870},
                extra=dict(severity='HIGH',metadata=metadata,message='private source',lines='account-config'))
            with self.subTest(valueType=type(value).__name__,status=status),self.assertRaises(scan.GateFailure) as caught:
                scan.findings_gate([result])
            advisory=caught.exception.safe['identities'][0].get('advisory')
            self.assertEqual(advisory,dict(status=status,id=value) if status=='recognized' else dict(status=status))
            for private in ('synthetic-sensitive-token','private source','account-config','prefix','suffix'):
                self.assertNotIn(private,json.dumps(caught.exception.safe))
        del metadata['sca-vuln-database-identifier']
        with self.assertRaises(scan.GateFailure) as missing:scan.findings_gate([result])
        self.assertEqual(missing.exception.safe['identities'][0]['advisory'],{'status':'missing'})
        metadata['product']='sast';metadata['sca-vuln-database-identifier']='CVE-2026-93687'
        with self.assertRaises(scan.GateFailure) as sast:scan.findings_gate([result])
        self.assertNotIn('advisory',sast.exception.safe['identities'][0])
        metadata['product']='sca';result['extra']['severity']='WARNING'
        self.assertEqual(scan.findings_gate([result]),[dict(rule='synthetic-sca',path='console/pnpm-lock.yaml',
            line=870,severity='WARNING',product='sca')])

    def test_sca_advisory_sampling_keeps_full_validation_and_private_omitted_rows(self):
        import json
        from copy import deepcopy
        import security_scan as scan
        result=dict(check_id='synthetic-sca',path='console/pnpm-lock.yaml',start={'line':870},
            extra=dict(severity='HIGH',metadata={'product':'sca','sca-vuln-database-identifier':'CVE-2026-93687'}))
        rows=[deepcopy(result) for _ in range(32)]
        private=deepcopy(result);private['extra']['metadata']['sca-vuln-database-identifier']='synthetic-sensitive-token'
        rows.append(private)
        with self.assertRaises(scan.GateFailure) as caught:scan.findings_gate(rows)
        evidence=caught.exception.safe
        self.assertEqual((evidence['total'],evidence['blocking'],evidence['sampleCount'],evidence['omittedCount']),(33,33,32,1))
        self.assertTrue(all(row.get('advisory')=={'status':'recognized','id':'CVE-2026-93687'} for row in evidence['identities']))
        self.assertNotIn('synthetic-sensitive-token',json.dumps(evidence))
        private['extra']['severity']='UNKNOWN'
        with self.assertRaises(ValueError) as invalid:scan.findings_gate(rows)
        self.assertNotIsInstance(invalid.exception,scan.GateFailure)

class SemgrepExceptionTests(unittest.TestCase):
    """Synthetic native identities qualify the matcher, never a live exception."""
    def setUp(self):
        import hashlib,json,shutil,tempfile
        from pathlib import Path,PurePosixPath
        self.temp=tempfile.TemporaryDirectory(prefix='ricevanta-sca-exception-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.source=self.root/'source';self.source.mkdir()
        paths=json.loads((Path(__file__).parent/'fixtures/security/semgrep-console-paths.json').read_text())
        self.assertIsInstance(paths,list);self.assertEqual(len(paths),124,'fixture must model the frozen full console')
        self.assertTrue(all(isinstance(path,str) for path in paths));self.assertEqual(len(set(paths)),124)
        self.hashes={};self.modes={}
        for relative in paths:
            parsed=PurePosixPath(relative)
            self.assertTrue(relative.startswith('console/') and parsed.as_posix()==relative and '..' not in parsed.parts
                and '\\' not in relative and not any(ord(c)<32 or 127<=ord(c)<=159 for c in relative),'invalid pinned fixture path')
            self.assertFalse(any(part.startswith('.env') for part in parsed.parts),'never read environment files')
            path=inventory.ROOT/relative
            self.assertFalse(any(parent.is_symlink() for parent in (path,*path.parents)
                if parent.is_relative_to(inventory.ROOT/'console')),'fixture source must not resolve through symlinks')
            self.assertTrue(path.is_file(),'missing pinned console fixture source');target=self.source/relative
            target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            self.hashes[relative]=hashlib.sha256(target.read_bytes()).hexdigest();self.modes[relative]='100644'
        self.entry=dict(advisoryId='CVE-2026-93687',osvAdvisoryId='GHSA-vfj7-8cjw-p6xm',product='sca',severity='ERROR',
            rule='ssc-dc89f360-8dea-4ff2-92c4-e67670eb22ef',package='braces',packageVersion='3.0.3',ecosystem='npm',
            path='console/pnpm-lock.yaml',line=870,consoleFiles=124,
            consoleSha256='11e45e4e42c78ced832fd814e1e4ce5f0619ab5d4a2fe00780881e0beff62303',
            rationale='CVE-2026-93687 consumes only reviewed repository build patterns.',
            provenance='console/security/osv-exceptions.json; docs/specs/console-foundation.md')
        self.document=dict(version=1,scanner='1.178.0',exception=[self.entry])
        self.finding=dict(check_id=self.entry['rule'],path=self.entry['path'],start={'line':870},
            extra=dict(severity='ERROR',metadata={'product':'sca','sca-vuln-database-identifier':'CVE-2026-93687',
                'token':'synthetic-sensitive-token'},message='private-source',lines='account-config',
                sca_info={'dependency_match':{'lockfile':'console/pnpm-lock.yaml','found_dependency':
                    {'package':'braces','version':'3.0.3','ecosystem':'npm','lockfile_path':'console/pnpm-lock.yaml'}}}))

    def gate(self,rows):
        import security_scan as scan
        return scan.findings_gate(rows,exceptions=[self.entry])

    def test_fixture_ignores_untracked_generated_files(self):
        from pathlib import Path
        from unittest.mock import patch
        generated=('console/node_modules/dependency/index.js','console/dist/bundle.js','console/.cache/generated.txt')
        for name in generated:
            path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'harmless generated fixture')
        fixture=SemgrepExceptionTests('test_exact_synthetic_identity_remains_visible_and_other_high_still_blocks')
        self.addCleanup(fixture.doCleanups)
        with patch.object(inventory,'ROOT',self.source), \
             patch.object(Path,'rglob',side_effect=AssertionError('fixture must not traverse untracked trees')):fixture.setUp()
        self.assertEqual(fixture.hashes,self.hashes)
        self.assertEqual(fixture.modes,self.modes)
        for name in generated:self.assertFalse((fixture.source/name).exists())

    def test_exact_synthetic_identity_remains_visible_and_other_high_still_blocks(self):
        import json
        from copy import deepcopy
        import security_scan as scan
        rows=self.gate([self.finding])
        self.assertEqual(rows,[dict(rule=self.entry['rule'],path=self.entry['path'],line=870,severity='ERROR',product='sca',
            advisory={'status':'recognized','id':'CVE-2026-93687'},disposition='excepted')])
        other=deepcopy(self.finding);other['check_id']='other-rule';other['extra']['severity']='HIGH'
        with self.assertRaises(scan.GateFailure) as caught:self.gate([self.finding,other])
        safe=caught.exception.safe
        self.assertEqual((safe['total'],safe['high'],safe['excepted'],safe['blocking'],safe['lower']),(2,2,1,1,0))
        self.assertEqual(safe['identities'][0]['rule'],'other-rule')
        self.assertEqual(safe['identities'][1]['disposition'],'excepted')
        for private in ('synthetic-sensitive-token','private-source','account-config'):self.assertNotIn(private,json.dumps(safe))

    def test_closed_exception_document_and_missing_file(self):
        from copy import deepcopy
        import security_scan as scan
        self.assertEqual(scan.validate_semgrep_exceptions(self.document),[self.entry])
        self.assertEqual(scan.validate_semgrep_exceptions(dict(version=1,scanner='1.178.0',exception=[])),[])
        cases=[dict(self.document,extra=True),dict(self.document,version=True),dict(self.document,scanner='latest'),
            dict(self.document,exception=[self.entry,self.entry]),dict(self.document,exception=None)]
        for field in self.entry:
            missing=deepcopy(self.document);del missing['exception'][0][field];cases.append(missing)
            wrong=deepcopy(self.document);wrong['exception'][0][field]=None;cases.append(wrong)
        for field,value in (('advisoryId','CVE-2026-00000'),('rule','*'),('packageVersion','*'),('line',True),
                ('consoleFiles',116),('consoleSha256','0'*64),('rationale',''),('provenance','')):
            wrong=deepcopy(self.document);wrong['exception'][0][field]=value;cases.append(wrong)
        extra=deepcopy(self.document);extra['exception'][0]['extra']='synthetic-sensitive-token';cases.append(extra)
        for document in cases:
            with self.assertRaises(ValueError):scan.validate_semgrep_exceptions(document)
        with self.assertRaises(ValueError):scan.load_semgrep_exceptions(self.root)
        table=self.root/'scripts/ci/semgrep-exceptions.toml';table.parent.mkdir(parents=True)
        for payload in (b'',b'#'+b'x'*65536,b'version=1\nversion=1\n',b'\xff'):
            table.write_bytes(payload)
            with self.assertRaises(ValueError):scan.load_semgrep_exceptions(self.root)

    def test_stale_duplicate_and_every_wrong_or_missing_native_identity_fail(self):
        from copy import deepcopy
        cases=[]
        for field,value in (('check_id','other-rule'),('path','console/./pnpm-lock.yaml')):
            wrong=deepcopy(self.finding);wrong[field]=value;cases.append(wrong)
        for field,value in (('severity','HIGH'),('severity','WARNING'),
                ('metadata',{'product':'sast','sca-vuln-database-identifier':'CVE-2026-93687'}),
                ('metadata',{'product':'sca'}),('metadata',{'product':'sca','sca-vuln-database-identifier':'GHSA-vfj7-8cjw-p6xm'})):
            wrong=deepcopy(self.finding);wrong['extra'][field]=value;cases.append(wrong)
        wrong=deepcopy(self.finding);wrong['start']['line']=871;cases.append(wrong)
        for field in ('sca_info','dependency_match','found_dependency'):
            for value in (None,[],{}):
                wrong=deepcopy(self.finding)
                parent=wrong['extra'] if field=='sca_info' else wrong['extra']['sca_info'] if field=='dependency_match' else wrong['extra']['sca_info']['dependency_match']
                parent[field]=value;cases.append(wrong)
            wrong=deepcopy(self.finding)
            parent=wrong['extra'] if field=='sca_info' else wrong['extra']['sca_info'] if field=='dependency_match' else wrong['extra']['sca_info']['dependency_match']
            del parent[field];cases.append(wrong)
        for field in ('package','version','ecosystem','lockfile_path'):
            for value in (None,[],{},'synthetic-sensitive-token'):
                wrong=deepcopy(self.finding);wrong['extra']['sca_info']['dependency_match']['found_dependency'][field]=value;cases.append(wrong)
            wrong=deepcopy(self.finding);del wrong['extra']['sca_info']['dependency_match']['found_dependency'][field];cases.append(wrong)
        for value in (None,[],{},'/src/console/pnpm-lock.yaml','console/./pnpm-lock.yaml'):
            wrong=deepcopy(self.finding);wrong['extra']['sca_info']['dependency_match']['lockfile']=value;cases.append(wrong)
        wrong=deepcopy(self.finding);del wrong['extra']['sca_info']['dependency_match']['lockfile'];cases.append(wrong)
        for rows in ([],[self.finding,self.finding],*[ [wrong] for wrong in cases ]):
            with self.assertRaises(ValueError) as caught:self.gate(rows)
            self.assertNotIn('synthetic-sensitive-token',str(caught.exception))
        invalid=deepcopy(self.finding);invalid['extra']['severity']='UNKNOWN'
        with self.assertRaises(ValueError):self.gate([self.finding]*32+[invalid])

    def test_complete_console_inventory_bytes_modes_and_mutations(self):
        import hashlib
        from copy import deepcopy
        import security_scan as scan
        boundary=scan.verify_console_boundary(self.source,self.hashes,self.modes,[self.entry])
        self.assertEqual(boundary,dict(files=124,canonicalBytes=12728,sha256=self.entry['consoleSha256']))
        cases=[(dict(self.hashes,**{'console/new-runtime.ts':'0'*64}),self.modes),
            ({p:h for p,h in self.hashes.items() if p!='console/vite.config.ts'},self.modes),
            (dict(self.hashes,**{'console/./alias.ts':'0'*64}),self.modes),
            (self.hashes,{}),(self.hashes,dict(self.modes,**{'console/new-runtime.ts':'100644'})),
            (self.hashes,dict(self.modes,**{'console/package.json':'120000'})),
            (self.hashes,dict(self.modes,**{'console/package.json':None})),
            (self.hashes,dict(self.modes,**{'console/package.json':'synthetic-sensitive-token'})),
            (dict(self.hashes,**{'./console/package.json':'0'*64}),self.modes),
            (dict(self.hashes,**{'console/control\x7f.ts':'0'*64}),self.modes)]
        for hashes,modes in cases:
            with self.assertRaises(ValueError):scan.verify_console_boundary(self.source,hashes,modes,[self.entry])
        for name in ('console/package.json','console/pnpm-lock.yaml','console/vite.config.ts',
                'console/security/osv-exceptions.json','console/src/app/main.ts',
                'console/scripts/finalize-install.ts','console/scripts/installed-packages.ts',
                'console/tests/fixtures/dependencies/install-tree.ts',
                'console/tests/fixtures/dependencies/lightningcss-LICENSE',
                'console/tests/fixtures/dependencies/vue-global-types.txt',
                'console/tests/unit/finalize-install.test.ts','console/tests/unit/installed-packages.test.ts',
                'console/scripts/audit-deps.ts','console/scripts/audit-dist.ts',
                'console/scripts/check-reproducible.ts','console/scripts/check-source.ts',
                'console/tests/unit/dependency-coverage.test.ts','console/tests/unit/output.test.ts',
                'console/tests/unit/platform-licenses.test.ts','console/tests/unit/reproducible.test.ts',
                'console/tests/unit/toolchain.test.ts','console/vitest.config.ts'):
            path=self.source/name
            original=path.read_bytes();path.write_bytes(original+b'\n')
            with self.assertRaises(ValueError):scan.verify_console_boundary(self.source,self.hashes,self.modes,[self.entry])
            forged=deepcopy(self.hashes);forged[name]=hashlib.sha256(path.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):scan.verify_console_boundary(self.source,forged,self.modes,[self.entry])
            path.write_bytes(original)
        path=self.source/'console/src/app/main.ts';renamed=path.with_name('renamed.ts');path.rename(renamed)
        hashes=dict(self.hashes);modes=dict(self.modes)
        hashes['console/src/app/renamed.ts']=hashes.pop('console/src/app/main.ts')
        modes['console/src/app/renamed.ts']=modes.pop('console/src/app/main.ts')
        with self.assertRaises(ValueError):scan.verify_console_boundary(self.source,hashes,modes,[self.entry])
        renamed.rename(path)
        name='console/package.json';path=self.source/name;original=path.read_bytes();path.unlink();path.mkdir()
        with self.assertRaises(ValueError):scan.verify_console_boundary(self.source,self.hashes,self.modes,[self.entry])
        path.rmdir();other=self.root/'other';other.write_bytes(original);path.symlink_to(other)
        with self.assertRaises(ValueError):scan.verify_console_boundary(self.source,self.hashes,self.modes,[self.entry])

    def report_fixture(self):
        fixture=SemgrepReportTests();fixture.setUp()
        fixture.hashes.update(self.hashes)
        import shutil
        for path in fixture.empty_paths:
            target=self.source/path;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(inventory.ROOT/path,target)
        fixture.source=self.source
        fixture.summary['rules']={'synthetic-rule':'sast',self.entry['rule']:'sca'}
        fixture.report['results']=[self.finding]
        return fixture

    def test_exception_follows_every_ordinary_evidence_check_and_empty_set_preserves_results(self):
        from copy import deepcopy
        import security_scan as scan
        fixture=self.report_fixture()
        def verify():
            return scan.semgrep_evidence(fixture.report,fixture.summary,fixture.sha,fixture.invocation,fixture.hashes,
                exceptions=[self.entry],source=self.source,console_modes=self.modes)
        evidence=verify()
        self.assertEqual(evidence['findingCounts'],dict(total=1,high=1,excepted=1,blocking=0,lower=0))
        self.assertEqual(evidence['findings'][0]['disposition'],'excepted')
        for owner,key,value in ((fixture.summary,'upload',False),(fixture.summary,'parserErrors',1),
                (fixture.report,'errors',[{'type':'Timeout'}]),(fixture.summary,'ignoredTargets',['foreign']),
                (fixture.summary,'codeRuleLanguages',{}),(fixture.summary,'dependencies',{})):
            original=deepcopy(owner[key]);owner[key]=value
            with self.assertRaises(ValueError):verify()
            owner[key]=original
        with self.assertRaises(ValueError):scan.semgrep_evidence(fixture.report,fixture.summary,fixture.sha,fixture.invocation,
            fixture.hashes,exceptions=[self.entry])
        fixture.report['results']=[]
        no_exception=scan.semgrep_evidence(fixture.report,fixture.summary,fixture.sha,fixture.invocation,fixture.hashes,source=fixture.source)
        self.assertEqual(no_exception['findings'],[]);self.assertNotIn('findingCounts',no_exception)
        with self.assertRaises(ValueError):verify()

    def test_snapshot_captures_modes_from_existing_git_inventory(self):
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        root=self.root/'checkout';root.mkdir();(root/'console').mkdir();(root/'console/a.ts').write_bytes(b'synthetic')
        (root/'.git').mkdir()
        for mode in ('100644','100755'):
            def git(path,*args):
                if args[0]=='ls-tree':return (mode+' blob '+'a'*40+'\tconsole/a.ts\0').encode()
                if args[0]=='cat-file':return b'synthetic'
                if args[0]=='rev-parse':return str(root/'.git').encode()
                raise AssertionError('unexpected Git call')
            modes={};destination=self.root/mode
            with patch.object(scan.routing,'git',side_effect=git):hashes=scan.snapshot(root,{'testedSha':'b'*40},destination,console_modes=modes)
            self.assertEqual(modes,{'console/a.ts':mode});self.assertEqual(set(hashes),{'console/a.ts'})

    def test_source_bound_exception_file_and_completion_mutation_fail_closed(self):
        import hashlib
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        table=self.source/'scripts/ci/semgrep-exceptions.toml';table.parent.mkdir(parents=True)
        table.write_bytes((inventory.ROOT/'scripts/ci/semgrep-exceptions.toml').read_bytes())
        fixture=self.report_fixture();fixture.hashes['scripts/ci/semgrep-exceptions.toml']=hashlib.sha256(table.read_bytes()).hexdigest()
        self.assertEqual(len(scan.load_semgrep_exceptions(self.source,fixture.hashes)),1)
        with self.assertRaises(ValueError):scan.load_semgrep_exceptions(self.source,{})
        lock=scan.load_lock(inventory.ROOT);value={'testedSha':fixture.sha};output=self.root/'scan';output.mkdir()
        # Use the real source/mode boundary, with synthetic unrelated source hashes.
        admission_dir=self.root/'security-semgrep-admission';admission_dir.mkdir()
        self.source.rename(admission_dir/'source');self.source=admission_dir/'source'
        scan.write_json(admission_dir/'admission.json',dict(route=value,tools=lock,sourceHashes=fixture.hashes,
            controls={'emptyManifests':synthetic_empty_qualification(lock,fixture.hashes)},
            consoleModes=self.modes,overlay={scan.AUXILIARY_PATH:scan.AUXILIARY_SHA256},pro=dict(version='1.178.0')))
        (self.source/scan.AUXILIARY_PATH).write_bytes(scan.AUXILIARY_BYTES)
        scan.write_json(output/'context.json',dict(invocation=fixture.invocation))
        scan.write_json(output/'semgrep.json',fixture.report);scan.write_json(output/'observer.json',fixture.summary)
        result=scan.semgrep_evidence(fixture.report,fixture.summary,fixture.sha,fixture.invocation,fixture.hashes,
            frozenset({scan.AUXILIARY_PATH}),exceptions=[self.entry],source=self.source,console_modes=self.modes)
        scan.write_json(output/'complete.json',dict(unit='semgrep',route=value,tools=lock,result=result))
        with patch.object(scan,'verify_snapshot'):
            self.assertEqual(scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock),result)
            (self.source/'console/vite.config.ts').write_bytes(b'changed input')
            with self.assertRaises(ValueError):scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock)

    def test_boundary_mutation_before_or_during_scan_cannot_issue_completion(self):
        import hashlib
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        table=self.source/'scripts/ci/semgrep-exceptions.toml';table.parent.mkdir(parents=True)
        table.write_bytes((inventory.ROOT/'scripts/ci/semgrep-exceptions.toml').read_bytes())
        fixture=self.report_fixture();fixture.hashes['scripts/ci/semgrep-exceptions.toml']=hashlib.sha256(table.read_bytes()).hexdigest()
        admission_dir=self.root/'security-semgrep-admission';admission_dir.mkdir()
        self.source.rename(admission_dir/'source');self.source=admission_dir/'source'
        (self.source/scan.AUXILIARY_PATH).write_bytes(scan.AUXILIARY_BYTES)
        lock=scan.load_lock(inventory.ROOT);value={'testedSha':fixture.sha}
        record=dict(route=value,tools=lock,sourceHashes=fixture.hashes,
            controls={'emptyManifests':synthetic_empty_qualification(lock,fixture.hashes)},consoleModes=self.modes,
            overlay={scan.AUXILIARY_PATH:scan.AUXILIARY_SHA256},pro=dict(version='1.178.0'))
        scan.write_json(admission_dir/'admission.json',record)
        path=self.source/'console/vite.config.ts';original=path.read_bytes()
        for phase in ('before','after','missing-mode','forged-mode'):
            path.write_bytes(original);record['consoleModes']=dict(self.modes)
            if phase=='before':path.write_bytes(original+b'\n')
            if phase=='missing-mode':del record['consoleModes']['console/package.json']
            if phase=='forged-mode':record['consoleModes']['console/package.json']='120000'
            scan.write_json(admission_dir/'admission.json',record)
            output=self.root/phase;output.mkdir()
            def native(*args,**kwargs):
                if phase=='after':path.write_bytes(original+b'\n')
                scan.write_json(output/'semgrep.json',fixture.report);scan.write_json(output/'observer.json',fixture.summary)
            with patch.object(scan,'verify_snapshot'),patch.object(scan,'admitted_image',return_value='admitted'), \
                 patch.object(scan,'container_command',return_value=['admitted']),patch.object(scan,'scanner_environment',return_value={}), \
                 patch.object(scan,'execute',side_effect=native) as invocation, \
                 patch.object(scan.os,'urandom',return_value=bytes.fromhex(fixture.invocation)):
                with self.subTest(phase=phase),self.assertRaises(ValueError):scan.run_semgrep(inventory.ROOT,value,None,output,lock,'synthetic-token')
                self.assertEqual(invocation.call_count,1 if phase=='after' else 0)
            self.assertFalse((output/'complete.json').exists())

    def test_excepted_sample_and_maximum_escaped_failure_envelope_stay_private_and_bounded(self):
        import json
        from copy import deepcopy
        import security_scan as scan
        blocker=dict(check_id='r'*500,path='repo/'+('"'*123+'/')*4+'a'*7,start={'line':2**63-1},
            extra=dict(severity='CRITICAL',metadata={'product':'sca','sca-vuln-database-identifier':'CVE-2026-'+'9'*19},
                       message='synthetic-sensitive-token',lines='private-source'))
        with self.assertRaises(scan.GateFailure) as caught:self.gate([deepcopy(blocker) for _ in range(31)]+[self.finding])
        evidence=caught.exception.safe
        self.assertEqual(evidence['identities'][-1]['disposition'],'excepted')
        self.assertEqual((evidence['high'],evidence['excepted'],evidence['blocking']),(32,1,31))
        for row in evidence['identities']:
            row.update(rule='r'*500,path=blocker['path'],line=2**63-1,severity='EXPERIMENT',
                       advisory={'status':'recognized','id':'CVE-2026-'+'9'*19},disposition='excepted')
        for field in ('total','high','excepted','blocking','lower','sampleCount','omittedCount'):evidence[field]=2**63-1
        for field in ('byProduct','bySeverity'):evidence[field]={key:2**63-1 for key in evidence[field]}
        envelope=dict(unit='semgrep',phase='scan',result='failure',reason='active-high-findings',findings=evidence)
        self.assertLessEqual(len(json.dumps(envelope).encode())+1,65536)
        self.assertNotIn('synthetic-sensitive-token',json.dumps(envelope))

class SourceAndOutputTests(unittest.TestCase):
    def test_output_must_be_fresh_outside_repository(self):
        import security_scan as scan
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp); root=base/'repo'; root.mkdir()
            scan.fresh_output(root, base/'out')
            for output in (base/'out', root/'out'):
                with self.assertRaises(ValueError): scan.fresh_output(root, output)
            (base/'link').symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError): scan.fresh_output(root, base/'link'/'out')

    def test_snapshot_rejects_submodule_escape_and_mutated_tree(self):
        import security_scan as scan
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); (root/'source.py').write_text('synthetic')
            for mode,path,payload in (('160000','submodule',b''), ('120000','link',b'../escape'),
                                       ('100644','source.py',b'different')):
                with self.assertRaises(ValueError): scan.validate_source_entry(root, mode, path, payload)
            scan.validate_source_entry(root, '100644', 'source.py', b'synthetic')

class GitleaksInvocationTests(unittest.TestCase):
    def test_tree_scan_preserves_native_relative_exception_identity(self):
        from copy import deepcopy
        import json, subprocess, tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        history = json.loads((inventory.ROOT/'scripts/ci/fixtures/security/gitleaks-history.json').read_text())
        tree = json.loads((inventory.ROOT/'scripts/ci/fixtures/security/gitleaks-tree.json').read_text())
        digest = '020860808f72ce3119a8a2c168ce57ccd98a1fd9de3f85c152f36d605c57e085'
        def snapshot(root, value, destination):
            destination.mkdir()
            return {}
        def native_process(argv, env, *, timeout, cwd=None):
            mode = argv[1]
            report = deepcopy(history if mode == 'git' else tree)
            if mode == 'dir':
                for row in report:
                    from pathlib import PurePosixPath
                    row['File'] = str(PurePosixPath(argv[2])/row['File'])
                    row['Fingerprint'] = row['File']+':generic-api-key:'+str(row['StartLine'])
            path = next(arg.split('=',1)[1] for arg in argv if arg.startswith('--report-path='))
            scan.write_json(Path(path),report)
            log = b'INF 13 commits scanned\nWRN leaks found: 13' if mode == 'git' else b'INF scanned ~40 bytes\nWRN leaks found: 13'
            return subprocess.CompletedProcess(argv,1,b'',log)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)/'output';output.mkdir()
            with patch.object(scan,'download',return_value=b''), patch.object(scan,'extract_gitleaks',return_value=Path('/admitted/gitleaks')), \
                 patch.object(scan,'execute',return_value=(b'8.30.1\n',b'')), patch.object(scan.routing,'git',return_value=b'false'), \
                 patch.object(scan,'gitleaks_controls',return_value={}), patch.object(scan,'snapshot',side_effect=snapshot), \
                 patch.object(scan,'exception_blobs',return_value={('git',scan.EXCEPTION_PATH):digest,('dir',scan.EXCEPTION_PATH):digest}), \
                 patch.object(scan,'captured_process',side_effect=native_process):
                result = scan.run_gitleaks(inventory.ROOT,{'testedSha':'a'*40},output,scan.load_lock(inventory.ROOT))
            self.assertEqual(result['gates']['dir']['excepted'],13)
            self.assertEqual(result['gates']['dir']['identities'],tree)

    def test_history_and_tree_use_defaults_and_no_suppressions(self):
        import security_scan as scan
        from pathlib import PurePosixPath as Path
        for mode in ('git', 'dir'):
            argv = scan.gitleaks_command(Path('/admitted/gitleaks'), mode, Path('/source'), Path('/private'), 'a'*40)
            self.assertIn('--ignore-gitleaks-allow', argv)
            self.assertIn('--no-color',argv)
            self.assertIn('--redact=100', argv)
            self.assertIn('--exit-code=1', argv)
            self.assertIn('--config=/private/gitleaks.toml', argv)
            self.assertIn('--gitleaks-ignore-path=/private/empty.ignore', argv)
            self.assertNotIn('--baseline-path', ' '.join(argv))
            if mode == 'git': self.assertIn('--log-opts='+'a'*40, argv)

class ObserverTests(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace as N
        import semgrep_observer as observer
        self.N=N; self.Rule=type('FixtureRule',(N,),{'__hash__':object.__hash__})
        self.observer=observer.Observer('f'*32, 'a'*40)
        self.handler=N(scan_id=42, enabled_products=['sast','sca'], dry_run=False,
            load_saved_scan_config_path=None, is_partial_scan=False, project_merge_base=None,
            scan_metadata=N(requested_products=[N(to_json=lambda:'sast'),N(to_json=lambda:'sca')]))
        self.metadata=N(commit=N(value='a'*40), repository='ricevanta/ricevanta', is_full_scan=True,
                        is_code_scan=True, is_sca_scan=True, is_secrets_scan=False)
        self.calls=[]
        self.kwargs=dict(rules=[self.Rule(id='synthetic-rule',product=N(to_json=lambda:'sast'),languages=['go'])],
            targets=[N(fpath='server/a.go')],skipped_paths=set(),ignored_targets=set(),
            lockfile_dependencies={'server/go.mod':[N(package='synthetic',version='1.0')],
                'branding/requirements-build.txt':[N(package='defusedxml',version='0.7.1',ecosystem=N(to_json=lambda:'pypi'))]},
            dependency_parser_errors=[],engine_requested=N(is_pro=True),matches_by_rule=N(kept={},removed={}))
        self.plan=N(rules=self.kwargs['rules'],target_mappings=[N(path=N(fpath='server/a.go'),analyzer='go',
                    products=[N(to_json=lambda:'sast')],rule_nums=(0,))])
        self.native_targets=N(to_json=lambda:['Targets',[['CodeTarget',dict(path=dict(fpath='server/a.go',ppath='/server/a.go'),analyzer='go',products=['sast'])]]])
        self.native_core=N(paths=N(scanned=[N(value='server/a.go')],skipped=[]),skipped_rules=[],errors=[])
        self.core_result=({},[],N(core=self.native_core))
        self.serialize=True
        self.serialization_count=1
        self.core_error=None

    def start(self):
        def original(handler, metadata, config):
            self.calls.append((handler, metadata, config)); return self.metadata
        return self.observer.start(self.handler, self.metadata, 'configuration', original)

    def complete(self, success=True):
        if not self.observer.core_seen: self.core()
        result=self.N(success=success)
        def original(handler, **kwargs): self.calls.append((handler,kwargs)); return result
        returned=self.observer.complete(self.handler, self.kwargs, original)
        self.assertIs(returned,result)
        return self.observer.summary()

    def core(self):
        def original(runner,target_manager,rules,dump_command_for_core,time_flag,matching_explanations,engine,
                     strict,run_secrets,disable_secrets_validation,target_mode_config,all_subprojects,x_parmap):
            if self.serialize:
                for _ in range(self.serialization_count):
                    returned=self.observer.plan(self.plan,lambda plan:self.native_targets)
                    self.assertIs(returned,self.native_targets)
            if self.core_error is not None: raise self.core_error
            return self.core_result
        args=(None,self.kwargs['rules'],False,False,False,self.N(is_pro=True),True,False,False,self.N(is_historical_scan=False),[],False)
        returned=self.observer.core(self.N(),args,{},original)
        self.assertIs(returned,self.core_result)
        return returned

    def test_original_identity_calls_and_sanitized_summary(self):
        self.assertIs(self.start(), self.metadata)
        evidence=self.complete()
        self.assertEqual(len(self.calls),2)
        self.assertIs(self.calls[0][0],self.handler)
        self.assertIs(self.calls[1][1]['rules'],self.kwargs['rules'])
        self.assertEqual(evidence['dependencies'], {'server/go.mod':1,'branding/requirements-build.txt':1})
        self.assertEqual(evidence['scanId'],42)
        self.assertEqual(evidence['codeRuleLanguages'],{'go':1})
        self.assertNotIn('configuration', str(evidence))
        with self.assertRaises(ValueError): self.start()
        with self.assertRaises(ValueError): self.complete()

    def test_branding_parser_requires_actual_singleton_package_version_and_ecosystem(self):
        N=self.N
        valid=N(package='defusedxml',version='0.7.1',ecosystem=N(to_json=lambda:'pypi'))
        cases=[('missing',None),('empty',[]),('duplicate',[valid,valid]),('malformed',[{}]),
            ('not-list',{}),('package',[N(package='synthetic-sensitive-token',version='0.7.1',ecosystem=valid.ecosystem)]),
            ('version',[N(package='defusedxml',version='synthetic-sensitive-token',ecosystem=valid.ecosystem)]),
            ('ecosystem',[N(package='defusedxml',version='0.7.1',ecosystem=N(to_json=lambda:'npm'))]),
            ('missing-ecosystem',[N(package='defusedxml',version='0.7.1')]),
            ('malformed-ecosystem',[N(package='defusedxml',version='0.7.1',ecosystem='pypi')])]
        for name,packages in cases:
            self.setUp();self.start()
            if packages is None:del self.kwargs['lockfile_dependencies']['branding/requirements-build.txt']
            else:self.kwargs['lockfile_dependencies']['branding/requirements-build.txt']=packages
            with self.subTest(case=name):
                with self.assertRaises(ValueError) as caught:self.complete()
                self.assertNotIn('synthetic-sensitive-token',str(caught.exception))
                self.assertEqual(len(self.calls),1,'invalid package must fail before upload')
        self.setUp();self.start()
        packages=self.kwargs['lockfile_dependencies']['branding/requirements-build.txt']
        summary=self.complete()
        self.assertEqual(summary['dependencies']['branding/requirements-build.txt'],1)
        self.assertIs(self.calls[-1][1]['lockfile_dependencies']['branding/requirements-build.txt'],packages)

    def test_branding_normalized_native_source_keys_preserve_exact_arguments(self):
        for path in ('branding/requirements-build.txt','/src/branding/requirements-build.txt'):
            self.setUp();self.start()
            native=self.kwargs['lockfile_dependencies']
            packages=native.pop('branding/requirements-build.txt');native[path]=packages
            with self.subTest(nativePath=path):
                summary=self.complete()
                self.assertEqual(summary['dependencies'],{'server/go.mod':1,'branding/requirements-build.txt':1})
                self.assertIs(self.calls[-1][1]['lockfile_dependencies'],native)
                self.assertIs(native[path],packages)
                self.assertEqual(set(native),{'server/go.mod',path})
        self.setUp();self.start()
        native=self.kwargs['lockfile_dependencies']
        native['/src/branding/requirements-build.txt']=native['branding/requirements-build.txt']
        with self.assertRaises(ValueError):self.complete()
        self.assertEqual(len(self.calls),1,'duplicate normalized input must fail before upload')

    def test_large_unused_catalog_keeps_full_counts_and_real_code_evidence(self):
        import json,tempfile
        from pathlib import Path
        import semgrep_observer as observer
        import security_scan as scan
        report=SemgrepReportTests();report.setUp()
        self.kwargs['lockfile_dependencies']={p:[self.N(package='synthetic',version='1.0')] for p in report.paths}
        self.kwargs['lockfile_dependencies']['branding/requirements-build.txt']=[
            self.N(package='defusedxml',version='0.7.1',ecosystem=self.N(to_json=lambda:'pypi'))]
        for index in range(8192):
            self.kwargs['rules'].append(self.Rule(id='sca.'+str(index).zfill(5)+'.'+'x'*490,
                product=self.N(to_json=lambda:'sca'),languages=['go']))
        self.kwargs['matches_by_rule'].kept={rule:[] for rule in self.kwargs['rules']}
        old_map={rule.id:rule.product.to_json() for rule in self.kwargs['rules']}
        self.assertGreater(len(json.dumps(old_map).encode()),4_000_000)
        self.start();summary=self.complete();summary['proVersion']='1.178.0'
        self.assertLessEqual(len(json.dumps(summary,sort_keys=True).encode()),4_000_000)
        self.assertEqual(summary['configuredRules'],{'sast':1,'sca':8192})
        self.assertEqual(summary['rules'],{'synthetic-rule':'sast'})
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'observer.json';observer.publish_summary(summary,path)
            self.assertLess(path.stat().st_size,1000)
            admitted=scan.read_private(path,4_000_000)
            result=scan.semgrep_evidence(report.report,admitted,report.sha,report.invocation,report.hashes,source=report.source)
        self.assertEqual(result['configuredCodeRules'],1)
        self.assertEqual(result['configuredSupplyChainRules'],8192)
        self.assertEqual(result['codePairs'],1);self.assertEqual(result['dependencies'],{p:1 for p in report.paths})
        self.assertEqual(len(self.calls),2)

    def test_unused_configured_rules_are_validated_before_projection(self):
        for kind in ('id','product','duplicate','language'):
            self.setUp()
            rule=self.Rule(id='unused',product=self.N(to_json=lambda:'sca'),languages=['go'])
            if kind=='id':rule.id='synthetic private source'
            elif kind=='product':rule.product=self.N(to_json=lambda:'secrets')
            elif kind=='duplicate':rule.id='synthetic-rule'
            else:rule.languages=['synthetic private source']
            self.kwargs['rules'].append(rule);self.start()
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.complete()
            self.assertEqual(len(self.calls),1)

    def test_relevant_rule_union_preserves_findings_and_every_core_skip(self):
        import json
        rules=[self.Rule(id=name,product=self.N(to_json=lambda:'sca'),languages=['go'])
               for name in ('kept','removed','skipped','pair-skipped','unused')]
        self.kwargs['rules'].extend(rules)
        self.kwargs['matches_by_rule']=self.N(kept={rules[0]:[self.N(rule_id='kept',message='synthetic-sensitive-token')]},
            removed={rules[1]:[self.N(rule_id='removed',message='private source')],rules[4]:[]})
        self.native_core.skipped_rules=[self.N(rule_id=self.N(value='skipped'))]
        self.native_core.paths.skipped=[self.N(path=self.N(value='server/skip.go'),
            reason=self.N(to_json=lambda:'irrelevant_rule'),rule_id=self.N(value='pair-skipped'))]
        self.start();summary=self.complete()
        self.assertEqual(summary['configuredRules'],{'sast':1,'sca':5})
        self.assertEqual(summary['rules'],dict({'synthetic-rule':'sast'},**{name:'sca' for name in ('kept','removed','skipped','pair-skipped')}))
        self.assertEqual(summary['codeWork']['skippedRules'],['skipped'])
        self.assertEqual(summary['codeWork']['skippedTargets'],[dict(path='server/skip.go',reason='irrelevant_rule',rule='pair-skipped')])
        self.assertNotIn('synthetic-sensitive-token',json.dumps(summary));self.assertNotIn('private source',json.dumps(summary))

    def test_unknown_or_conflicting_relevant_finding_rules_fail(self):
        for kind in ('unknown','product','match-id'):
            self.setUp()
            rule=self.Rule(id='unknown' if kind=='unknown' else 'synthetic-rule',
                product=self.N(to_json=lambda:'sca' if kind=='product' else 'sast'),languages=['go'])
            self.kwargs['matches_by_rule'].kept={rule:[self.N(rule_id='unknown' if kind=='match-id' else rule.id)]}
            self.start()
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.complete()

    def test_identity_products_and_modes_fail_closed(self):
        from copy import deepcopy
        for key,val in (('scan_id',None), ('enabled_products',['sast']), ('enabled_products',['sast','sca','secrets']),
                        ('dry_run',True), ('load_saved_scan_config_path','config'), ('is_partial_scan',True),
                        ('project_merge_base','b'*40)):
            saved=deepcopy(self.handler); setattr(self.handler,key,val)
            with self.subTest(key=key), self.assertRaises(ValueError): self.start()
            self.handler=saved
            import semgrep_observer as observer
            self.observer=observer.Observer('f'*32,'a'*40)
        for key,val in (('commit',self.N(value='b'*40)), ('repository','attacker/repo'),('is_full_scan',False)):
            saved=deepcopy(self.metadata);setattr(self.metadata,key,val)
            with self.assertRaises(ValueError): self.start()
            self.metadata=saved
            import semgrep_observer as observer
            self.observer=observer.Observer('f'*32,'a'*40)

    def test_missing_completion_upload_errors_and_handler_swaps(self):
        with self.assertRaises(ValueError): self.observer.summary()
        self.start()
        with self.assertRaises(ValueError): self.observer.summary()
        with self.assertRaises(ValueError): self.complete(False)

    def test_exceptions_propagate_without_summary(self):
        error=RuntimeError('synthetic private error')
        def original(*args): raise error
        with self.assertRaises(RuntimeError) as caught:
            self.observer.start(self.handler,self.metadata,None,original)
        self.assertIs(caught.exception,error)
        with self.assertRaises(ValueError): self.observer.summary()

class CoreObservationTests(unittest.TestCase):
    def test_quote_heavy_core_error_paths_fit_private_reader(self):
        import json,tempfile
        from pathlib import Path
        import semgrep_observer as observer
        import security_scan as scan
        N=self.fixture.N;rule='r'*500
        oversized='repo/'+('"'*124+'/')*7+'"'*120
        boundary='repo/'+('"'*123+'/')*4+'a'*7
        self.assertEqual(len(oversized.encode('utf-8')),1000)
        self.assertEqual(len(json.dumps(boundary,ensure_ascii=False).encode('utf-8'))-2,1000)
        for path in (oversized,boundary):
            error=N(error_type=N(kind='TimeoutDuringInterfile'),severity=N(kind='Error_'),rule_id=N(value=rule),
                    location=N(path=N(value='/src/'+path)),message='synthetic-sensitive-token',details='private-source')
            core=observer.core_error_projection([error]*32,[N(core=error)]*32,{rule},{path})
            failure=dict(reason='observer-cli-exit',stage='core-result-validation',exceptionKind='cli-exit',processExit=2,
                callback=dict(reason='observer-core-errors',stage='core-result-validation',exceptionClass='ValueError',coreErrors=core))
            encoded=json.dumps(failure,ensure_ascii=False).encode('utf-8')
            with self.subTest(pathCase='oversized' if path==oversized else 'boundary'):
                self.assertLessEqual(len(encoded),65536)
                self.assertEqual(core['errorCount'],32);self.assertEqual(core['convertedErrorCount'],32)
                self.assertEqual(len(core['errors']),32)
                if path==oversized:self.assertNotIn('path',core['errors'][0])
                else:self.assertEqual(core['errors'][0]['path'],boundary)
                with tempfile.TemporaryDirectory() as temp:
                    output=Path(temp)/'failure.json';output.write_bytes(encoded)
                    admitted=scan.read_private(output,65536)
                    self.assertEqual(scan.observer_failure_projection(admitted)['nativeCoreErrors'],core)
                self.assertNotIn(b'synthetic-sensitive-token',encoded);self.assertNotIn(b'private-source',encoded)
        core['errors'][0]['path']=oversized
        self.assertTrue(scan.core_failure_projection(core) is None)

    def test_native_core_error_metadata_survives_failure_without_private_payload(self):
        import json
        import security_scan as scan
        f=self.fixture;N=f.N
        def forbidden():raise AssertionError('compound payload must stay private')
        error=N(error_type=N(kind='PartialParsing',to_json=forbidden,value='synthetic-sensitive-token'),
                severity=N(kind='Warning_'),message='synthetic-sensitive-token',details='private-source account-config',
                location=N(path=N(value='/src/server/a.go')),rule_id=N(value='synthetic-rule'))
        malformed=N(error_type=N(kind='synthetic-sensitive-token'),severity=N(kind='account-config'),
                    location=N(path=N(value='/tmp/private-source')),rule_id=N(value='synthetic-sensitive-token'))
        f.native_core.errors=[error,malformed]+[error]*38
        f.core_result[1].extend([N(core=row) for row in f.native_core.errors])
        errors=f.native_core.errors;converted=f.core_result[1]
        with self.assertRaisesRegex(ValueError,'^observer-core-errors$'):
            f.observer.observe(f.core)
        safe=scan.observer_failure_projection(dict(reason='observer-cli-exit',stage='core-result-validation',
            exceptionKind='cli-exit',processExit=2,callback=f.observer.failure))
        projection=safe['nativeCoreErrors']
        self.assertEqual(projection['errorCount'],40);self.assertEqual(projection['convertedErrorCount'],40)
        self.assertEqual(len(projection['errors']),32)
        self.assertEqual(projection['errors'][0],dict(type='PartialParsing',level='warn',rule='synthetic-rule',path='server/a.go'))
        self.assertEqual(projection['errors'][1],dict(type='unknown',level='unknown'))
        for private in ('synthetic-sensitive-token','private-source','account-config','/src','/tmp'):
            self.assertNotIn(private,json.dumps(f.observer.failure));self.assertNotIn(private,json.dumps(safe))
        self.assertIs(f.native_core.errors,errors);self.assertIs(f.core_result[1],converted)
        self.assertEqual(errors[0].message,'synthetic-sensitive-token')
        self.assertFalse(f.observer.finished)
        with self.assertRaises(ValueError):f.observer.summary()
        from copy import deepcopy
        native=dict(reason='observer-cli-exit',stage='core-result-validation',exceptionKind='cli-exit',callback=f.observer.failure)
        for field,value in (('message','synthetic-sensitive-token'),('type',['private-source']),('path','../private-source'),('rule','unsafe rule')):
            bad=deepcopy(native);bad['callback']['coreErrors']['errors'][0][field]=value
            with self.subTest(field=field):self.assertIsNone(scan.observer_failure_projection(bad))

    def setUp(self):
        self.fixture=ObserverTests();self.fixture.setUp();self.fixture.start()

    def test_native_serialized_supported_code_pair_with_no_finding_passes(self):
        self.fixture.core()
        result=self.fixture.complete()
        self.assertEqual(result['codeWork']['pairs'],1)
        self.assertEqual(result['codeWork']['rules'],['synthetic-rule'])
        self.assertEqual(result['codeWork']['targets'],['server/a.go'])
        self.assertEqual(result['codeWork']['analyzers'],{'go':dict(pairs=1,rules=1,targets=1)})

    def test_unused_code_rule_and_sca_only_pair_fail(self):
        f=self.fixture;N=f.N
        f.kwargs['rules'].append(N(id='sca-rule',product=N(to_json=lambda:'sca'),languages=['go']))
        f.kwargs['rules'][0].languages=['java']
        f.plan.target_mappings[0].rule_nums=(1,)
        f.plan.target_mappings[0].products=[N(to_json=lambda:'sca')]
        f.native_targets=N(to_json=lambda:['Targets',[['CodeTarget',dict(path=dict(fpath='server/a.go',ppath='/server/a.go'),analyzer='go',products=['sca'])]]])
        with self.assertRaises(ValueError):f.core()

    def test_missing_display_only_duplicate_and_invalid_serialization_fail(self):
        f=self.fixture
        f.observer.plan(f.plan,lambda plan:f.native_targets)
        f.serialize=False
        with self.assertRaises(ValueError):f.core()
        for indices in ((-1,),(True,),(1,),(0,0)):
            self.setUp();f=self.fixture;f.plan.target_mappings[0].rule_nums=indices
            with self.subTest(indices=indices),self.assertRaises(ValueError):f.core()
        self.setUp();f=self.fixture;f.core()
        with self.assertRaises(ValueError):f.core()
        self.setUp();f=self.fixture;f.serialization_count=2
        with self.assertRaises(ValueError):f.core()

    def test_native_skips_and_errors_cannot_count_as_completed_code_pairs(self):
        N=self.fixture.N
        for field,value in (('paths',N(scanned=[],skipped=[])),('skipped_rules',[N(rule_id=N(value='synthetic-rule'))]),
                            ('paths',N(scanned=[N(value='server/a.go')],skipped=[N(path=N(value='server/a.go'),reason=N(to_json=lambda:'excluded_by_config'),rule_id=None)])),
                            ('errors',[N(message='synthetic private text')])):
            self.setUp();setattr(self.fixture.native_core,field,value)
            with self.subTest(field=field),self.assertRaises(ValueError):self.fixture.core()

    def test_native_core_exception_propagates_without_summary(self):
        error=RuntimeError('synthetic private native exception')
        self.fixture.core_error=error
        with self.assertRaises(RuntimeError) as caught:self.fixture.core()
        self.assertIs(caught.exception,error)
        with self.assertRaises(ValueError):self.fixture.observer.summary()

    def test_completion_without_core_and_serialized_mismatch_fail(self):
        f=self.fixture
        with self.assertRaises(ValueError):f.observer.complete(f.handler,f.kwargs,lambda handler,**kwargs:f.N(success=True))
        self.setUp();f=self.fixture
        f.native_targets=f.N(to_json=lambda:['Targets',[['CodeTarget',dict(path=dict(fpath='server/different.go',ppath='/server/different.go'),analyzer='go',products=['sast'])]]])
        with self.assertRaises(ValueError):f.core()


class SemgrepReportTests(unittest.TestCase):
    def setUp(self):
        self.sha='a'*40;self.invocation='f'*32
        self.paths=['server/go.mod','agent/Cargo.lock','console/pnpm-lock.yaml','.github/requirements-design.txt',
                    'branding/requirements-build.txt']
        self.summary=dict(invocation=self.invocation,testedSha=self.sha,scanId=42,products=['sast','sca'],
                          upload=True,rules={'synthetic-rule':'sast','synthetic-sca':'sca'},targets=['server/a.go'],
                          configuredRules={'sast':1,'sca':1},dependencies={p:1 for p in self.paths},codeRuleLanguages={'go':1},parserErrors=0,engine='PRO',ignoredTargets=[],proVersion='1.178.0')
        self.summary['codeWork']=dict(pairs=1,rules=['synthetic-rule'],targets=['server/a.go'],
            analyzers={'go':dict(pairs=1,rules=1,targets=1)},skippedTargets=[],skippedRules=[])
        self.report=dict(version='1.178.0',results=[],errors=[],paths={'scanned':['server/a.go'],'skipped':[]},
            engine_requested='PRO',subprojects=[{'dependency_sources':[p], 'resolved':True,
            'resolved_stats':{'dependency_count':1,'resolution_method':'LockfileParsing','ecosystem':'Go'}} for p in self.paths])
        self.hashes={p:'b'*64 for p in self.paths+['server/a.go']}
        self.report['subprojects'][-1]['resolved_stats']['ecosystem']='pypi'
        import hashlib
        self.source=inventory.ROOT
        self.empty_paths=['scripts/ci/gotestdecls/go.mod','scripts/ci/fixtures/selected/tiny-go/go.mod']
        for path in self.empty_paths:
            self.hashes[path]=hashlib.sha256((self.source/path).read_bytes()).hexdigest()
            self.report['subprojects'].append(dict(dependency_sources=[path],resolved=True,
                resolved_stats=dict(dependency_count=0,resolution_method='LockfileParsing',ecosystem='gomod')))

    def verify(self):
        import security_scan as scan
        return scan.semgrep_evidence(self.report,self.summary,self.sha,self.invocation,self.hashes,
                                    auxiliary=getattr(self,'auxiliary',frozenset()),source=self.source)

    def test_synthetic_contract_positive_no_claim_of_live_upload(self):
        result=self.verify()
        self.assertEqual(result['dependencies'], {p:1 for p in self.paths})
        self.assertNotIn('targetInventory',result)

    def test_branding_dependency_input_is_required_and_must_resolve(self):
        import security_scan as scan
        self.assertEqual(scan.expected_dependencies(self.hashes),sorted(self.paths+self.empty_paths))
        del self.summary['dependencies']['branding/requirements-build.txt']
        with self.assertRaises(ValueError):self.verify()
        self.summary['dependencies']['branding/requirements-build.txt']=1
        self.report['subprojects'][4]['resolved']=False
        with self.assertRaises(ValueError):self.verify()
        self.report['subprojects'][4]['resolved']=True
        self.report['subprojects'][4]['resolved_stats']['dependency_count']=0
        with self.assertRaises(ValueError):self.verify()

    def test_target_membership_failures_keep_gate_and_report_only_closed_counts(self):
        import json
        import security_scan as scan
        for case in ('report-empty','observer-empty','report-only-tracked','report-only-foreign','overlay','other-foreign'):
            self.setUp()
            private='synthetic-sensitive-token/private-source/account-config'
            if case=='report-empty':self.report['paths']['scanned']=[]
            elif case=='observer-empty':self.summary['targets']=[]
            elif case=='report-only-tracked':
                self.report['paths']['scanned'].append('server/extra.go');self.hashes['server/extra.go']='b'*64
            elif case=='report-only-foreign':self.report['paths']['scanned'].append(private)
            else:
                path='.semgrepignore' if case=='overlay' else private
                self.report['paths']['scanned'].append(path);self.summary['targets'].append(path)
            with self.subTest(case=case),self.assertRaises(ValueError) as caught:self.verify()
            self.assertIs(type(caught.exception),scan.TargetInventoryFailure)
            self.assertEqual(scan.failure_code(caught.exception),'scanned-targets-missing-or-foreign')
            evidence=caught.exception.safe
            self.assertEqual(set(evidence),{'reportTargetCount','observerTargetCount','sourceFileCount',
                'reportNotObservedCount','observerNotSourceCount','reportNotSourceCount',
                'reportNotObservedTrackedCount','reportNotObservedOverlayCount','reportNotObservedOtherCount',
                'observerNotSourceOverlayCount','observerNotSourceOtherCount','reportNotSourceOverlayCount',
                'reportNotSourceOtherCount','reportHasSemgrepignore','observerHasSemgrepignore'})
            self.assertTrue(all(type(value) in (int,bool) for value in evidence.values()))
            self.assertLess(len(json.dumps(evidence).encode()),2048)
            for secret in ('synthetic-sensitive-token','private-source','account-config','server/extra.go'):
                self.assertNotIn(secret,json.dumps(evidence));self.assertNotIn(secret,str(caught.exception))
            if case=='report-empty':self.assertEqual(evidence['reportTargetCount'],0)
            elif case=='observer-empty':self.assertEqual(evidence['observerTargetCount'],0)
            elif case=='report-only-tracked':self.assertEqual(evidence['reportNotObservedTrackedCount'],1)
            elif case=='report-only-foreign':self.assertEqual(evidence['reportNotObservedOtherCount'],1)
            elif case=='overlay':
                self.assertEqual(evidence['observerNotSourceOverlayCount'],1)
                self.assertEqual(evidence['observerNotSourceOtherCount'],0)
                self.assertTrue(evidence['reportHasSemgrepignore']);self.assertTrue(evidence['observerHasSemgrepignore'])
            else:
                self.assertEqual(evidence['observerNotSourceOtherCount'],1)
                self.assertEqual(evidence['observerNotSourceOverlayCount'],0)
                self.assertFalse(evidence['observerHasSemgrepignore'])

    def test_unsafe_or_malformed_target_paths_fail_before_membership_diagnostics(self):
        import security_scan as scan
        for location in ('report','observer'):
            for path in (None,{},'../synthetic-sensitive-token','/private/synthetic-sensitive-token','bad\\synthetic-sensitive-token'):
                self.setUp()
                if location=='report':self.report['paths']['scanned'].append(path)
                else:self.summary['targets'].append(path)
                with self.subTest(location=location,pathType=type(path).__name__),self.assertRaises(ValueError) as caught:self.verify()
                self.assertNotIsInstance(caught.exception,scan.TargetInventoryFailure)
                self.assertNotIn('synthetic-sensitive-token',str(caught.exception))

    def test_sca_without_relevant_rule_and_full_configured_counts(self):
        self.summary['rules']={'synthetic-rule':'sast'}
        self.summary['configuredRules']['sca']=8192
        self.assertEqual(self.verify()['configuredSupplyChainRules'],8192)

    def test_missing_or_malformed_full_configured_counts_fail(self):
        from copy import deepcopy
        original=deepcopy(self.summary)
        for value in (None,{'sast':1},{'sast':True,'sca':1},{'sast':0,'sca':1},{'sast':1,'sca':-1},{'sast':1,'sca':1,'secrets':1}):
            self.summary=deepcopy(original);self.summary['configuredRules']=value
            with self.subTest(value=value),self.assertRaises(ValueError):self.verify()
        self.summary=deepcopy(original);del self.summary['configuredRules']
        with self.assertRaises(ValueError):self.verify()
        self.summary=deepcopy(original);self.summary['rules']['extra-code']='sast'
        with self.assertRaises(ValueError):self.verify()

    def test_final_report_unknown_rule_and_product_conflict_fail(self):
        self.report['results']=[dict(check_id='synthetic-sca',path='server/a.go',start={'line':1},
            extra=dict(severity='WARNING',metadata={}))]
        self.assertEqual(self.verify()['findings'][0]['product'],'sca')
        self.report['results'][0]['check_id']='unknown'
        with self.assertRaises(ValueError):self.verify()
        self.report['results'][0]['check_id']='synthetic-sca'
        self.report['results'][0]['extra']['metadata']['product']='sast'
        with self.assertRaises(ValueError):self.verify()

    def test_configured_java_code_with_only_go_sca_targets_fails(self):
        self.summary['rules']={'java-code':'sast','go-sca':'sca'}
        self.summary['codeRuleLanguages']={'java':1}
        with self.assertRaises(ValueError):self.verify()

    def test_missing_products_rules_targets_dependencies_and_sha(self):
        from copy import deepcopy
        for key,value in (('products',['sast']),('upload',False),('rules',{'synthetic-sca':'sca'}),('targets',[]),
                           ('testedSha','b'*40),('invocation','e'*32),('parserErrors',1)):
            saved=deepcopy(self.summary);self.summary[key]=value
            with self.subTest(key=key), self.assertRaises(ValueError):self.verify()
            self.summary=saved
        for path in self.paths:
            saved=deepcopy(self.summary); del self.summary['dependencies'][path]
            with self.subTest(path=path),self.assertRaises(ValueError):self.verify()
            self.summary=saved

    def test_native_error_unresolved_and_empty_reports(self):
        from copy import deepcopy
        for key,value in (('errors',[{'type':'Timeout'}]),('paths',{'scanned':[]}),('subprojects',[]),('version','wrong')):
            saved=deepcopy(self.report);self.report[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify()
            self.report=saved
        self.report['subprojects'][0]['resolved']=False
        with self.assertRaises(ValueError):self.verify()

    def test_zero_exit_with_warning_or_interfile_error_still_fails_evidence(self):
        import subprocess
        from unittest.mock import patch
        import security_scan as scan
        for kind,level in (('PartialParsing','warn'),('Timeout during interfile analysis','error')):
            self.report['errors']=[dict(type=kind,level=level,code=2)]
            process=subprocess.CompletedProcess(scan.SEMGREP_COMMAND,0,b'',b'')
            with self.subTest(kind=kind),patch.object(scan,'captured_process',return_value=process):
                self.assertEqual(scan.execute(scan.SEMGREP_COMMAND,{},stage='semgrep-scan'),(b'',b''))
                with self.assertRaises(ValueError) as caught:self.verify()
            self.assertEqual(scan.failure_code(caught.exception),'scan-errors-or-engine-version')

    def test_native_skipped_targets_keep_reasons_and_discard_details(self):
        self.hashes.update({'server/oversized.go':'b'*64,'server/excluded.go':'b'*64})
        self.report['paths']['skipped'] = [dict(path='server/oversized.go',reason='exceeded_size_limit',details='synthetic private source'),
                                          dict(path='server/excluded.go',reason='excluded_by_config')]
        result=self.verify()
        self.assertEqual(result['skippedTargets'],[dict(path='server/oversized.go',reason='exceeded_size_limit'),
                                                  dict(path='server/excluded.go',reason='excluded_by_config')])
        self.assertEqual(result['skippedTargetCount'],2)
        self.assertNotIn('synthetic private source',str(result))

    def test_absent_malformed_or_unknown_native_skip_evidence_fails(self):
        for skipped in (None,{},[{}],[dict(path='../escape',reason='excluded_by_config')],
                        [dict(path='server/a.go',reason='synthetic private reason')]):
            self.report['paths']['skipped']=skipped
            with self.subTest(skipped=skipped),self.assertRaises(ValueError):self.verify()
        del self.report['paths']['skipped']
        with self.assertRaises(ValueError):self.verify()

class AuxiliaryInputTests(unittest.TestCase):
    path='.semgrepignore'
    payload=b'# Reviewed full tracked-tree scan; no exclusion patterns.\n'
    digest='c8133eb012efe9edb83ce4df1e6106c1e110e8836e4c09b4c20a99a61dc1177a'

    def source(self,root):
        from pathlib import Path
        source=Path(root)/'source';source.mkdir()
        (source/self.path).write_bytes(self.payload)
        table=source/'scripts/ci/semgrep-exceptions.toml';table.parent.mkdir(parents=True)
        table.write_bytes(b'version = 1\nscanner = "1.178.0"\nexception = []\n')
        return source

    def test_fixed_singleton_rejects_metadata_aliases_collision_and_file_changes(self):
        import hashlib,tempfile
        import security_scan as scan
        self.assertEqual(len(self.payload),58);self.assertEqual(hashlib.sha256(self.payload).hexdigest(),self.digest)
        with tempfile.TemporaryDirectory() as temp:
            source=self.source(temp);record={self.path:self.digest};file=source/self.path
            self.assertEqual(scan.verify_auxiliary(source,{},record),frozenset({self.path}))
            for metadata in (None,{}, {self.path:'0'*64},{'./'+self.path:self.digest},{self.path+'/':self.digest},
                             {self.path:self.digest,'other':self.digest}):
                with self.subTest(metadata=metadata),self.assertRaises(ValueError):scan.verify_auxiliary(source,{},metadata)
            with self.assertRaises(ValueError):scan.verify_auxiliary(source,{self.path:self.digest},record)
            for payload in (self.payload[:-1]+b'x',self.payload+b'x'):
                file.write_bytes(payload)
                with self.subTest(bytes=len(payload)),self.assertRaises(ValueError):scan.verify_auxiliary(source,{},record)
            file.unlink()
            with self.assertRaises(ValueError):scan.verify_auxiliary(source,{},record)
            file.mkdir()
            with self.assertRaises(ValueError):scan.verify_auxiliary(source,{},record)
            file.rmdir();target=source/'other';target.write_bytes(self.payload);file.symlink_to(target)
            with self.assertRaises(ValueError):scan.verify_auxiliary(source,{},record)

    def test_verified_singleton_preserves_records_totals_and_git_code_authority(self):
        import tempfile
        from copy import deepcopy
        import security_scan as scan
        fixture=SemgrepReportTests();fixture.setUp();original=deepcopy(fixture.hashes)
        with tempfile.TemporaryDirectory() as temp:
            source=self.source(temp)
            fixture.auxiliary=scan.verify_auxiliary(source,fixture.hashes,{self.path:self.digest})
            fixture.report['paths']['scanned'].append(self.path);fixture.summary['targets'].append(self.path)
            fixture.report['paths']['skipped']=[dict(path=self.path,reason='wrong_language')]
            fixture.summary['ignoredTargets']=[self.path]
            fixture.summary['rules']['synthetic-generic']='sast';fixture.summary['configuredRules']['sast']=2
            fixture.summary['codeRuleLanguages']['generic']=1
            work=fixture.summary['codeWork'];work['pairs']=2;work['rules'].append('synthetic-generic');work['targets'].append(self.path)
            work['analyzers']['generic']=dict(pairs=1,rules=1,targets=1)
            work['skippedTargets']=[dict(path=self.path,reason='wrong_language',rule='synthetic-sca')]
            fixture.report['results']=[dict(check_id='synthetic-generic',path=self.path,start={'line':1},
                extra=dict(severity='WARNING',metadata={},lines='private source',message='synthetic-sensitive-token'))]
            result=fixture.verify()
            self.assertEqual(fixture.hashes,original);self.assertNotIn(self.path,fixture.hashes)
            self.assertEqual(result['mixedTargets'],2);self.assertEqual(result['codeTargets'],2);self.assertEqual(result['codePairs'],2)
            self.assertEqual(result['gitCodeTargets'],1);self.assertEqual(result['auxiliaryCodeTargets'],1)
            self.assertEqual(result['auxiliaryInput'],dict(path=self.path,bytes=58,sha256=self.digest,
                targets=1,skippedTargets=1,coreSkippedTargets=1,ignoredTargets=1,findings=1,codeTargets=1))
            self.assertEqual(result['skippedTargetCount'],1);self.assertEqual(result['unsupportedTargets'],[self.path])
            self.assertEqual(result['findings'][0]['path'],self.path)
            fixture.report['results'][0]['extra']['severity']='HIGH'
            with self.assertRaisesRegex(ValueError,'active high severity findings'):fixture.verify()
            fixture.report['results']=[];work['pairs']=1;work['rules']=['synthetic-generic'];work['targets']=[self.path]
            work['analyzers']={'generic':dict(pairs=1,rules=1,targets=1)}
            with self.assertRaises(ValueError):fixture.verify()

    def test_singleton_cannot_authorize_other_foreign_records_or_dependencies(self):
        import tempfile
        import security_scan as scan
        for location in ('target','mismatch','skip','core-skip','ignored','finding','dependency'):
            fixture=SemgrepReportTests();fixture.setUp()
            with tempfile.TemporaryDirectory() as temp:
                fixture.auxiliary=scan.verify_auxiliary(self.source(temp),fixture.hashes,{self.path:self.digest})
                other='other-foreign'
                if location=='target':fixture.summary['targets'].append(other);fixture.report['paths']['scanned'].append(other)
                elif location=='mismatch':fixture.report['paths']['scanned'].append(self.path)
                elif location=='skip':fixture.report['paths']['skipped']=[dict(path=other,reason='wrong_language')]
                elif location=='core-skip':fixture.summary['codeWork']['skippedTargets']=[dict(path=other,reason='wrong_language')]
                elif location=='ignored':fixture.summary['ignoredTargets']=[other]
                elif location=='finding':fixture.report['results']=[dict(check_id='synthetic-rule',path=other,start={'line':1},extra=dict(severity='WARNING',metadata={}))]
                else:fixture.summary['dependencies'][self.path]=1
                with self.subTest(location=location),self.assertRaises(ValueError):fixture.verify()

    def test_mutation_before_after_scan_and_completion_cannot_pass(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        for phase in ('before','after','completion'):
            fixture=SemgrepReportTests();fixture.setUp();value={'testedSha':fixture.sha,'runId':'1','runAttempt':'1'};lock=scan.load_lock(inventory.ROOT)
            with tempfile.TemporaryDirectory() as temp:
                admission_dir=Path(temp)/'security-semgrep-admission';admission_dir.mkdir();source=self.source(admission_dir)
                import hashlib
                fixture.hashes['scripts/ci/semgrep-exceptions.toml']=hashlib.sha256((source/'scripts/ci/semgrep-exceptions.toml').read_bytes()).hexdigest()
                for path in fixture.empty_paths:
                    target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((inventory.ROOT/path).read_bytes())
                output=Path(temp)/'scan';output.mkdir()
                scan.write_json(admission_dir/'admission.json',dict(route=value,tools=lock,sourceHashes=fixture.hashes,
            controls={'emptyManifests':synthetic_empty_qualification(lock,fixture.hashes)},
                    overlay={self.path:self.digest},pro=dict(version='1.178.0')))
                scan.write_json(output/'context.json',dict(invocation=fixture.invocation))
                scan.write_json(output/'complete.json',dict(unit='semgrep',route=value,tools=lock,result={}))
                def execute(*args,**kwargs):
                    if phase=='after':(source/self.path).write_bytes(self.payload[:-1]+b'x')
                if phase!='after':(source/self.path).write_bytes(self.payload[:-1]+b'x')
                with patch.object(scan,'verify_snapshot'),patch.object(scan,'admitted_image',return_value='admitted'), \
                     patch.object(scan,'container_command',return_value=['admitted']),patch.object(scan,'execute',side_effect=execute) as native:
                    with self.subTest(phase=phase),self.assertRaisesRegex(ValueError,'invalid generated scanner input'):
                        if phase=='completion':scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock)
                        else:scan.run_semgrep(inventory.ROOT,value,None,output,lock,'synthetic-token')
                    self.assertEqual(native.call_count,1 if phase=='after' else 0)

    def test_admission_checks_fixed_bytes_and_preserves_git_only_hashes(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        lock=scan.load_lock(inventory.ROOT)
        for case in ('valid','collision','mutated-during-admission'):
            with tempfile.TemporaryDirectory() as temp:
                output=Path(temp)/'admission';output.mkdir()
                hashes={'server/a.go':'b'*64}
                if case=='collision':hashes[self.path]='b'*64
                def snapshot(root,value,destination,**kwargs):
                    destination.mkdir()
                    import hashlib
                    for path in ('scripts/ci/gotestdecls/go.mod','scripts/ci/fixtures/selected/tiny-go/go.mod'):
                        target=destination/path;target.parent.mkdir(parents=True,exist_ok=True)
                        payload=(inventory.ROOT/path).read_bytes();target.write_bytes(payload)
                        hashes[path]=hashlib.sha256(payload).hexdigest()
                    return dict(hashes)
                def controls(*args):
                    if case=='mutated-during-admission':(output/'source'/self.path).write_bytes(self.payload[:-1]+b'x')
                    return {}
                scan.write_json(output/'pro.json',dict(version='1.178.0',sha256=lock['pro']['sha256']))
                with patch.object(scan,'snapshot',side_effect=snapshot),patch.object(scan,'admitted_image',return_value='admitted'), \
                     patch.object(scan,'load_semgrep_exceptions',return_value=[]), \
                     patch.object(scan,'container_command',return_value=['admitted']),patch.object(scan,'execute'), \
                     patch.object(scan,'semgrep_controls',side_effect=controls),patch.object(scan,'runner_inputs',return_value={}), \
                     patch.object(scan,'empty_parser_controls',return_value={}):
                    if case!='valid':
                        with self.subTest(case=case),self.assertRaises(ValueError):scan.admit_semgrep(inventory.ROOT,{},output,lock)
                        self.assertFalse((output/'admission.json').exists())
                    else:
                        scan.admit_semgrep(inventory.ROOT,{},output,lock)
                        admission=scan.read_private(output/'admission.json')
                        self.assertEqual(admission['sourceHashes'],hashes)
                        self.assertEqual(admission['overlay'],{self.path:self.digest})
                        self.assertEqual((output/'source'/self.path).read_bytes(),self.payload)

    def test_valid_scan_completion_then_overlay_mutation_is_rejected(self):
        import hashlib,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        fixture=SemgrepReportTests();fixture.setUp();lock=scan.load_lock(inventory.ROOT)
        value=dict(testedSha=fixture.sha,runId='1',runAttempt='1')
        fixture.report['paths']['scanned'].append(self.path);fixture.summary['targets'].append(self.path)
        with tempfile.TemporaryDirectory() as temp:
            admission_dir=Path(temp)/'security-semgrep-admission';admission_dir.mkdir();source=self.source(admission_dir)
            payload=b'synthetic source'
            fixture.hashes={path:hashlib.sha256(payload).hexdigest() for path in fixture.hashes}
            for path in fixture.hashes:
                file=source/path;file.parent.mkdir(parents=True,exist_ok=True)
                contents=(inventory.ROOT/path).read_bytes() if path in fixture.empty_paths else payload
                file.write_bytes(contents);fixture.hashes[path]=hashlib.sha256(contents).hexdigest()
            fixture.hashes['scripts/ci/semgrep-exceptions.toml']=hashlib.sha256((source/'scripts/ci/semgrep-exceptions.toml').read_bytes()).hexdigest()
            output=Path(temp)/'scan';output.mkdir()
            scan.write_json(admission_dir/'admission.json',dict(route=value,tools=lock,sourceHashes=fixture.hashes,
            controls={'emptyManifests':synthetic_empty_qualification(lock,fixture.hashes)},
                overlay={self.path:self.digest},pro=dict(version='1.178.0')))
            def native(*args,**kwargs):
                scan.write_json(output/'observer.json',fixture.summary);scan.write_json(output/'semgrep.json',fixture.report)
            with patch.object(scan,'admitted_image',return_value='admitted'),patch.object(scan,'container_command',return_value=['admitted']), \
                 patch.object(scan,'execute',side_effect=native),patch.object(scan.os,'urandom',return_value=bytes.fromhex(fixture.invocation)):
                result=scan.run_semgrep(inventory.ROOT,value,None,output,lock,'synthetic-token')
            self.assertEqual(result['gitCodeTargets'],1);self.assertEqual(result['auxiliaryCodeTargets'],0)
            self.assertEqual(result['auxiliaryInput']['targets'],1)
            scan.write_json(output/'complete.json',dict(unit='semgrep',route=value,tools=lock,result=result))
            self.assertEqual(scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock),result)
            (source/self.path).write_bytes(self.payload[:-1]+b'x')
            with self.assertRaisesRegex(ValueError,'invalid generated scanner input'):
                scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock)

class ContainerTests(unittest.TestCase):
    def test_container_identity_preserves_private_mount_and_home_access(self):
        import security_scan as scan
        from pathlib import PurePosixPath as Path
        argv=scan.container_command('admitted',Path('/source'),Path('/out'),Path('/control'),scan=False,identity=(1001,1001))
        self.assertEqual(argv[argv.index('--user')+1],'1001:1001')
        self.assertIn('/home/security:rw,nosuid,nodev,size=64m,uid=1001,gid=1001,mode=0700',argv)
        self.assertIn('--network',argv);self.assertIn('none',argv)
        self.assertIn('--read-only',argv);self.assertIn('--cap-drop',argv);self.assertIn('ALL',argv)
        self.assertNotIn('--cap-add',argv)

    def test_token_value_never_in_argv_and_repository_trap_not_started(self):
        import security_scan as scan
        from pathlib import PurePosixPath as Path
        argv = scan.container_command('semgrep/semgrep@sha256:'+'a'*64, Path('/private/source'),
                                      Path('/private/output'), Path('/reviewed/control'), scan=True,identity=(1001,1001))
        self.assertIn('--read-only',argv);self.assertIn('--pull=never',argv)
        self.assertIn('ALL',argv);self.assertIn('no-new-privileges',argv)
        self.assertIn('SEMGREP_APP_TOKEN',argv)
        self.assertNotIn('synthetic-sensitive-token',' '.join(argv))
        self.assertNotIn('npm',' '.join(argv));self.assertNotIn('cargo',' '.join(argv))
        self.assertNotIn('--privileged',argv)
        self.assertIn('/usr/bin/python3',argv); self.assertIn('-I',argv)
        self.assertNotIn('/source/trap',' '.join(argv))
        self.assertIn('/private/source:/src:ro',argv)

    def test_missing_token_and_whitespace_token_rejected(self):
        import security_scan as scan
        for token in (None,'','  ','token\nvalue'):
            with self.assertRaises(ValueError):scan.require_token(token)
        self.assertEqual(scan.require_token('synthetic-token'),'synthetic-token')

class ColdControlTests(unittest.TestCase):
    def report(self,paths,rule='qualification',errors=None):
        return dict(version='1.178.0',engine_requested='OSS',errors=errors or [],
                    results=[dict(check_id=rule,path='/src/'+path) for path in paths],
                    paths=dict(scanned=['/src/'+path for path in paths],skipped=[]))

    def test_cold_commands_are_explicit_oss_without_rule_rewrite_or_credentials(self):
        import semgrep_observer as observer
        for mode,config,report in (('required','code-rules.yaml','code-controls.json'),
                                   ('rust','code-rules-rust.yaml','code-rust-probe.json'),
                                   ('vue','code-rules-vue.yaml','code-vue-probe.json')):
            command=observer.control_command(mode)
            self.assertIn('--oss-only',command);self.assertIn('--no-rewrite-rule-ids',command)
            self.assertIn('--strict',command)
            self.assertIn('--config=/control/fixtures/security/'+config,command)
            self.assertIn('--json-output=/out/'+report,command)
            self.assertNotIn('--pro',command);self.assertNotIn('--error',command)
        from unittest.mock import patch
        import os,sys
        with patch.dict(os.environ,{'HOME':'/private','SEMGREP_APP_TOKEN':'synthetic-token'},clear=True), \
             patch.object(sys,'argv',['observer','--controls']):
            with self.assertRaisesRegex(ValueError,'observer-control-credential'):observer.main()

    def test_optional_probe_limits_never_hide_unrelated_errors(self):
        import security_scan as scan
        supported=self.report(['control.rs'],'qualification-rust')
        self.assertEqual(scan.verify_optional_control(supported,0,'rust')['status'],'supported')
        empty=self.report([],'qualification-vue')
        self.assertEqual(scan.verify_optional_control(empty,0,'vue')['status'],'unqualified')
        unsupported=self.report([],errors=[dict(type='Missing plugin',code=2,level='error',rule_id='qualification-rust',path='/src/control.rs',message='synthetic private message')])
        safe=scan.verify_optional_control(unsupported,2,'rust')
        self.assertEqual(safe['status'],'unsupported')
        self.assertNotIn('synthetic private message',str(safe))
        for error in (dict(type='SemgrepError',code=2,level='error'),dict(type='ParseError',code=3,level='error'),
                      dict(type='Missing plugin',code=2,level='error',rule_id='unrelated',path='/src/control.rs')):
            report=self.report([],errors=[error])
            with self.subTest(error=error),self.assertRaises(ValueError):scan.verify_optional_control(report,2,'rust')

    def test_native_optional_exit_survives_observer_and_unrelated_error_still_fails(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        import semgrep_observer as observer
        unsupported=self.report([],errors=[dict(type='Missing plugin',code=2,level='error',rule_id='qualification-rust',path='/src/control.rs')])
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(observer,'main',side_effect=SystemExit(2)),patch.object(observer,'STAGE','code-controls'), \
                 patch.object(observer,'Path',return_value=Path(temp)/'failure.json'),patch('sys.stderr'):
                with self.assertRaises(SystemExit) as caught:observer.run()
            self.assertEqual(scan.verify_optional_control(unsupported,caught.exception.code,'rust')['status'],'unsupported')
            unrelated=self.report([],errors=[dict(type='SemgrepError',code=2,level='error')])
            with self.assertRaises(ValueError):scan.verify_optional_control(unrelated,caught.exception.code,'rust')

    def test_redacted_positive_control_rejects_leaks_or_absent_detection(self):
        import security_scan as scan
        secret='synthetic-sensitive'
        scan.verify_gitleaks_control(1,b'redacted console',[{'Secret':'REDACTED','Match':'REDACTED'}],secret)
        for status,log,report in ((0,b'',[]),(1,secret.encode(),[{}]),(1,b'', [{'Secret':secret}]),(2,b'',[])):
            with self.assertRaises(ValueError):scan.verify_gitleaks_control(status,log,report,secret)

    def test_code_positive_controls_and_vendor_limit_reporting(self):
        import security_scan as scan
        report=self.report(['control.go','control.py','control.ts'])
        report['paths']['scanned'].append('/src/negative.ts')
        result=scan.verify_code_controls(report)
        self.assertEqual(result,dict(engine='OSS',inputs='synthetic',required=dict(status='supported',rule='qualification',targets=['control.go','control.py','control.ts'],negative='negative.ts')))
        report['results'].pop()
        with self.assertRaises(ValueError):scan.verify_code_controls(report)

class ExactExceptionTests(unittest.TestCase):
    def setUp(self):
        import json
        self.history=json.loads((inventory.ROOT/'scripts/ci/fixtures/security/gitleaks-history.json').read_text())
        self.tree=json.loads((inventory.ROOT/'scripts/ci/fixtures/security/gitleaks-tree.json').read_text())
        self.path='schemas/dsse/v1/vectors.json'
        self.digest='020860808f72ce3119a8a2c168ce57ccd98a1fd9de3f85c152f36d605c57e085'

    def gate(self,mode,report,status=1,hashes=None):
        import security_scan as scan
        exceptions=scan.load_exceptions(inventory.ROOT)
        hashes=hashes if hashes is not None else {('git',self.path):self.digest,('dir',self.path):self.digest}
        return scan.gitleaks_gate(report,status,mode,exceptions,hashes)

    def test_real_sanitized_identities_are_counted_not_hidden(self):
        for mode,report in (('git',self.history),('dir',self.tree)):
            result=self.gate(mode,report)
            self.assertEqual((result['total'],result['excepted'],result['blocking'],result['disabled']), (13,13,0,0))
        with self.assertRaises(ValueError):self.gate('git',self.history,0)
        with self.assertRaises(ValueError):self.gate('dir',[],1)
        self.assertEqual(self.gate('dir',[],0)['total'],0)

    def test_new_commit_changed_byte_new_finding_and_duplicate_block(self):
        from copy import deepcopy
        for key,value in (('Commit','a'*40),('StartColumn',8),('File','./'+self.path),('RuleID','new-rule')):
            report=deepcopy(self.history);report[0][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.gate('git',report)
        with self.assertRaises(ValueError):self.gate('git',self.history+self.history[:1])
        with self.assertRaises(ValueError):self.gate('dir',self.tree,hashes={('git',self.path):self.digest,('dir',self.path):'a'*64})
        self.assertEqual(self.gate('dir',[],0,hashes={})['disabled'],13)

class DiagnosticTests(unittest.TestCase):
    def test_blocking_findings_emit_only_existing_safe_metadata_and_counts(self):
        import contextlib,io,json,os,sys,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        fixture=SemgrepReportTests();fixture.setUp()
        fixture.report['results']=[dict(check_id='synthetic-sca',path='server/a.go',start={'line':3},
            extra=dict(severity='HIGH',metadata={'token':'synthetic-sensitive-token','dev.semgrep.actions':['monitor'],
                       'sca-vuln-database-identifier':'CVE-2026-93687'},
                       lines='private source',message='account-config',matched='private match'))]
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'out';log=io.StringIO()
            argv=['security_scan.py','semgrep','--root',str(inventory.ROOT),'--route',str(Path(temp)/'route.json'),'--output',str(output)]
            with patch.object(sys,'argv',argv),patch.dict(os.environ,{'RUNNER_TEMP':temp},clear=True), \
                 patch.object(scan,'bind_route',return_value=({'testedSha':fixture.sha},None)), \
                 patch.object(scan.platform,'system',return_value='Linux'),patch.object(scan.platform,'machine',return_value='x86_64'), \
                 patch.object(scan,'run_semgrep',side_effect=lambda *args:fixture.verify()),contextlib.redirect_stdout(log):
                with self.assertRaises(SystemExit) as caught:scan.main()
            self.assertEqual(caught.exception.code,1)
            diagnostic=scan.read_private(output/'diagnostics.json',65536)
            self.assertEqual(diagnostic['reason'],'active-high-findings')
            evidence=diagnostic['findings'];self.assertEqual(evidence['total'],1);self.assertEqual(evidence['blocking'],1)
            self.assertEqual(evidence['identities'],[dict(rule='synthetic-sca',path='server/a.go',line=3,severity='HIGH',product='sca',
                advisory={'status':'recognized','id':'CVE-2026-93687'})])
            self.assertFalse((output/'complete.json').exists())
            for value in ('synthetic-sensitive-token','private source','account-config','private match'):
                self.assertNotIn(value,json.dumps(diagnostic));self.assertNotIn(value,log.getvalue())

    def test_target_membership_failure_publishes_only_bounded_numeric_diagnostics(self):
        import contextlib,io,json,os,sys,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        fixture=SemgrepReportTests();fixture.setUp()
        fixture.report['paths']['scanned'].append('synthetic-sensitive-token/private-source/account-config')
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)/'out';log=io.StringIO()
            argv=['security_scan.py','semgrep','--root',str(inventory.ROOT),'--route',str(Path(temp)/'route.json'),'--output',str(output)]
            with patch.object(sys,'argv',argv),patch.dict(os.environ,{'RUNNER_TEMP':temp},clear=True), \
                 patch.object(scan,'bind_route',return_value=({'testedSha':fixture.sha},None)), \
                 patch.object(scan.platform,'system',return_value='Linux'),patch.object(scan.platform,'machine',return_value='x86_64'), \
                 patch.object(scan,'run_semgrep',side_effect=lambda *args:fixture.verify()),contextlib.redirect_stdout(log):
                with self.assertRaises(SystemExit) as caught:scan.main()
            self.assertEqual(caught.exception.code,1)
            path=output/'diagnostics.json';self.assertLessEqual(path.stat().st_size,2048)
            diagnostic=scan.read_private(path,65536)
            self.assertEqual(diagnostic['reason'],'scanned-targets-missing-or-foreign')
            self.assertEqual(diagnostic['targetInventory']['reportNotObservedOtherCount'],1)
            self.assertFalse((output/'complete.json').exists())
            for secret in ('synthetic-sensitive-token','private-source','account-config'):
                self.assertNotIn(secret,json.dumps(diagnostic));self.assertNotIn(secret,log.getvalue())

    def test_essential_summary_overflow_fails_with_closed_private_size_evidence(self):
        import json,tempfile
        from copy import deepcopy
        from pathlib import Path
        from unittest.mock import patch
        import semgrep_observer as observer
        import security_scan as scan
        fixture=SemgrepReportTests();fixture.setUp();summary=fixture.summary
        summary['targets'].extend('server/synthetic-sensitive-token/'+('a'*100+'/')*5+str(index)+'.go' for index in range(8192))
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'observer.json';failure_path=Path(temp)/'observer-failure.json'
            with patch.object(observer,'main',side_effect=lambda:observer.publish_summary(summary,path)), \
                 patch.object(observer,'STAGE','upload-complete'),patch.object(observer,'Path',return_value=failure_path),patch('sys.stderr'):
                with self.assertRaises(SystemExit) as caught:observer.run()
            self.assertEqual(caught.exception.code,1);self.assertFalse(path.exists())
            self.assertLessEqual(failure_path.stat().st_size,65536)
            failure=scan.read_private(failure_path,65536);safe=scan.observer_failure_projection(failure)
            sizing=safe['observerSummarySize']
            self.assertGreater(sizing['bytes'],4_000_000)
            self.assertEqual(sizing['counts']['targets'],8193)
            self.assertGreater(sizing['fieldBytes']['targets'],4_000_000)
            self.assertNotIn('synthetic-sensitive-token',json.dumps(failure));self.assertNotIn('synthetic-sensitive-token',json.dumps(safe))
            for location,value in (('count',True),('field','synthetic-sensitive-token'),('extra',1),('reason','observer-native-failure')):
                bad=deepcopy(failure)
                if location=='count':bad['summarySize']['counts']['targets']=value
                elif location=='field':bad['summarySize']['fieldBytes']['targets']=value
                elif location=='extra':bad['summarySize']['extra']=value
                else:bad['reason']=value
                with self.subTest(location=location):self.assertIsNone(scan.observer_failure_projection(bad))

    def test_existing_native_error_payload_is_projected_without_extra_hook(self):
        import json,sys,tempfile
        from pathlib import Path
        from types import SimpleNamespace as N
        from unittest.mock import patch
        import semgrep_observer as observer
        import security_scan as scan
        trace=('Traceback (most recent call last):\n'
               '  File "/usr/lib/python3.12/site-packages/semgrep/commands/ci.py", line 622, in private_function\n'
               '  File "/usr/lib/python3.12/site-packages/semgrep/meta.py", line 250, in private_function\n'
               'PermissionError: [Errno 30] Read-only file system: synthetic-sensitive-token account-config\n')
        payload={'error':trace,'headers':{'Authorization':'synthetic-sensitive-token'},'body':'account-config'}
        state=N(get_state=lambda:(_ for _ in ()).throw(AssertionError('native context has already exited')))
        namespace={}
        exec(compile('\n'*82+'def wrapper(error_handler):\n    raise SystemExit(2)\n',
                     '/usr/lib/python3.12/site-packages/semgrep/commands/wrapper.py','exec'),namespace)
        def native_cli_exit():namespace['wrapper'](N(payload=payload))
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'failure.json'
            with patch.dict(sys.modules,{'semgrep.state':state}),patch.object(observer,'main',side_effect=native_cli_exit), \
                 patch.object(observer,'STAGE','authenticated-scan'),patch.object(observer,'Path',return_value=path),patch('sys.stderr'):
                with self.assertRaises(SystemExit) as caught:observer.run()
            failure=json.loads(path.read_text());safe=scan.observer_failure_projection(failure)
        self.assertEqual(caught.exception.code,2)
        self.assertEqual(safe['nativeErrorTrace'],dict(frames=[dict(module='commands/ci.py',line=622),dict(module='meta.py',line=250)],
            exceptionClasses=['PermissionError'],categories=['read-only-filesystem']))
        self.assertEqual(payload['error'],trace)
        for value in ('synthetic-sensitive-token','account-config','Authorization','private_function','/usr/lib'):
            self.assertNotIn(value,json.dumps(failure));self.assertNotIn(value,json.dumps(safe))
        failure['trace']['frames'][0]['module']='synthetic-sensitive-token'
        self.assertIsNone(scan.observer_failure_projection(failure))

    def test_failed_scan_projects_only_pinned_frames_and_closed_error_markers(self):
        import json,subprocess
        from unittest.mock import patch
        import security_scan as scan
        private=(b'Traceback (most recent call last):\n'
                 b'  File "/usr/lib/python3.12/site-packages/semgrep/commands/ci.py", line 622, in private_function\n'
                 b'    synthetic-sensitive-token private-source account-config\n'
                 b'  File "/usr/lib/python3.12/site-packages/semgrep/meta.py", line 250, in private_function\n'
                 b'  File "/usr/lib/python3.12/site-packages/semgrep/synthetic-sensitive-token.py", line 1, in private_function\n'
                 b'  File "/src/private-source.py", line 1, in private_function\n'
                 b'  File "/usr/lib/python3.12/site-packages/semgrep/meta.py", line 999999, in private_function\n'
                 b'PermissionError: [Errno 13] Permission denied: synthetic-sensitive-token\n'
                 b'Could not start scan: synthetic-sensitive-token\n'
                 b'Command failed with exit code: 128\n-----\nCommand failed with output:\naccount-config\n'
                 b'synthetic-sensitive-token: private-source\n')
        native=subprocess.CompletedProcess(['unchanged-command'],2,b'private-source',private)
        with patch.object(scan,'captured_process',return_value=native):
            with self.assertRaises(scan.ProcessFailure) as caught:scan.execute(['unchanged-command'],{},stage='semgrep-scan')
        self.assertEqual(caught.exception.output_evidence,dict(frames=[dict(module='commands/ci.py',line=622),dict(module='meta.py',line=250)],
            exceptionClasses=['PermissionError'],categories=['git-command-failed','permission-denied','scan-initialization']))
        encoded=json.dumps(caught.exception.__dict__)
        for value in ('synthetic-sensitive-token','private-source','account-config','private_function','/usr/lib','/src'):
            self.assertNotIn(value,encoded)
        with patch.object(scan,'captured_process',return_value=native):
            with self.assertRaises(scan.ProcessFailure) as caught:scan.execute(['unchanged-command'],{},stage='semgrep-code-controls')
        self.assertIsNone(caught.exception.output_evidence)
        safe=scan.native_output_projection(private*100,private*100)
        self.assertLessEqual(len(safe['frames']),32)
        self.assertNotIn('synthetic-sensitive-token',json.dumps(safe))

    def test_native_error_projection_discards_messages_paths_and_unknown_values(self):
        import security_scan as scan
        report=dict(errors=[dict(type='SemgrepError',code=2,level='error',message='Could not start scan: synthetic-sensitive-token',path='private-source'),
                            dict(type=['DependencyResolutionError',dict(secret='synthetic-sensitive-token')],code=2,level='error'),
                            dict(type='synthetic-sensitive-token',code=12345,level='private-source')])
        safe=scan.native_error_projection(report)
        self.assertEqual(safe['errorCount'],3)
        self.assertEqual(safe['errors'][0],dict(type='SemgrepError',code=2,level='error',category='scan-initialization'))
        self.assertEqual(safe['errors'][1]['type'],'DependencyResolutionError')
        self.assertEqual(safe['errors'][2],dict(type='unknown',code='unknown',level='unknown',category='unknown'))
        self.assertNotIn('synthetic-sensitive-token',str(safe));self.assertNotIn('private-source',str(safe))
        report['errors']*=100
        self.assertEqual(len(scan.native_error_projection(report)['errors']),32)

    def test_hook_failure_survives_native_cli_rewrap_without_sensitive_text(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import semgrep_observer as observer
        import security_scan as scan
        for private_error in (None,RuntimeError('synthetic-sensitive-token private-source account-config')):
            fixture=ObserverTests();fixture.setUp();fixture.handler.enabled_products=['sast']
            calls=[]
            class Handler:
                def start_scan(self,project_metadata,project_config):
                    calls.append((project_metadata,project_config))
                    if private_error is not None:raise private_error
                def report_findings(self,*,matches_by_rule,rules,targets,skipped_paths,renamed_targets,ignored_targets,
                        cli_suggested_exit_code,parse_rate,total_time,commit_date,lockfile_dependencies,dependency_parser_errors,
                        changed_dependency_sources,all_subprojects,contributions,engine_requested,progress_bar,disable_nosem):pass
            class Runner:
                def invoke_semgrep_core(self,target_manager,rules,dump_command_for_core,time_flag,matching_explanations,
                        engine,strict,run_secrets,disable_secrets_validation,target_mode_config,all_subprojects,x_parmap):pass
            class Plan:
                def to_targets(self):pass
            handler=Handler();handler.__dict__.update(fixture.handler.__dict__)
            def native_cli():
                try:handler.start_scan(fixture.metadata,'unchanged-config')
                except Exception:raise SystemExit(2) from None
            def observed_main():
                observer.invoke_scanner(fixture.observer,Handler,Runner,Plan,native_cli)
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/'failure.json'
                with patch.object(observer,'main',side_effect=observed_main),patch.object(observer,'Path',return_value=path),patch('sys.stderr'):
                    with self.assertRaises(SystemExit) as caught:observer.run()
                failure=json.loads(path.read_text());safe=scan.observer_failure_projection(failure)
            self.assertEqual(caught.exception.code,2);self.assertEqual(len(calls),1)
            self.assertEqual(safe['observerCallbackReason'],'observer-products' if private_error is None else 'observer-native-failure')
            self.assertEqual(safe['observerCallbackException'],'ValueError' if private_error is None else 'RuntimeError')
            self.assertEqual(safe['observerStage'],'start-scan-validation' if private_error is None else 'start-scan-request')
            self.assertNotIn('synthetic-sensitive-token',str(failure));self.assertNotIn('account-config',str(safe))

    def test_process_failure_preserves_only_closed_stage_and_numeric_exit(self):
        import sys
        import security_scan as scan
        with self.assertRaises(scan.ProcessFailure) as caught:
            scan.execute([sys.executable,'-c','raise SystemExit(7)'],{},stage='semgrep-pro-admission')
        self.assertEqual(caught.exception.stage,'semgrep-pro-admission')
        self.assertEqual(caught.exception.status,7)

    def test_observer_cli_exit_produces_safe_failure_evidence(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import semgrep_observer as observer
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'observer-failure.json'
            with patch.object(observer,'main',side_effect=SystemExit(2)), patch.object(observer,'STAGE','code-controls'), \
                 patch.object(observer,'Path',return_value=path), patch('sys.stderr'):
                with self.assertRaises(SystemExit) as caught: observer.run()
            self.assertEqual(caught.exception.code,2)
            self.assertEqual(json.loads(path.read_text()),dict(reason='observer-cli-exit',stage='code-controls',exceptionKind='cli-exit',processExit=2))

    def test_closed_failure_codes_never_include_exception_text(self):
        import security_scan as scan
        self.assertEqual(scan.failure_code(ValueError('incomplete products or upload')), 'products-or-upload-incomplete')
        self.assertEqual(scan.failure_code(RuntimeError('synthetic-sensitive-token')), 'security-evidence-rejected')
        self.assertNotIn('synthetic-sensitive-token', scan.failure_code(ValueError('synthetic-sensitive-token')))

class ObserverEngineTests(unittest.TestCase):
    def test_marker_hash_version_and_missing_engine_never_install(self):
        from types import SimpleNamespace as N
        from unittest.mock import patch
        from pathlib import Path
        import hashlib,tempfile,sys
        import semgrep_observer as observer
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'pro';path.write_bytes(b'synthetic engine');marker=Path(temp)/'marker';marker.write_bytes(b'1.178.0\n')
            pin={'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'marker':'1.178.0\n'}
            lock={'pro':pin,'semgrep':{'version':'1.178.0'}}
            engine=N(check_if_installed=lambda:True,check_is_correct_pro_version=lambda:True,get_pro_version=lambda:'1.178.0')
            modules={'semgrep':N(__VERSION__='1.178.0'),'semgrep.engine':N(EngineType=N(PRO_INTERFILE=engine)),
                     'semgrep.semgrep_core':N(SemgrepCore=N(pro_path=lambda:path,pro_version_stamp_path=lambda:marker))}
            with patch.dict(sys.modules,modules):
                self.assertEqual(observer.admitted_pro(lock),'1.178.0')
                marker.write_bytes(b'wrong\n')
                with self.assertRaises(ValueError):observer.admitted_pro(lock)
                marker.write_bytes(b'1.178.0\n');path.write_bytes(b'mutated engine')
                with self.assertRaises(ValueError):observer.admitted_pro(lock)
                path.write_bytes(b'synthetic engine');engine.check_if_installed=lambda:False
                with self.assertRaises(ValueError):observer.admitted_pro(lock)
                # No installer is present in the fake admitted package. Any
                # fallback import would fail this guarded admission boundary.
                self.assertNotIn('semgrep.commands.install',sys.modules)

    def test_same_process_entry_retains_hooks_dispatcher_without_hooks_fails(self):
        import semgrep_observer as observer
        import sys
        from types import SimpleNamespace as N
        fixture=ObserverTests();fixture.setUp()
        calls=[]
        class Handler:
            def start_scan(self,project_metadata,project_config): calls.append(('start',project_metadata,project_config));return project_metadata
            def report_findings(self, *, matches_by_rule, rules, targets, skipped_paths, renamed_targets,
                    ignored_targets, cli_suggested_exit_code, parse_rate, total_time, commit_date,
                    lockfile_dependencies, dependency_parser_errors, changed_dependency_sources, all_subprojects,
                    contributions, engine_requested, progress_bar, disable_nosem):
                calls.append(('complete',rules));return N(success=True)
        class Plan:
            def to_targets(self):calls.append(('plan',self));return fixture.native_targets
        plan=Plan();plan.__dict__.update(fixture.plan.__dict__)
        class Runner:
            def invoke_semgrep_core(self,target_manager,rules,dump_command_for_core,time_flag,matching_explanations,
                                    engine,strict,run_secrets,disable_secrets_validation,target_mode_config,all_subprojects,x_parmap):
                self_test.assertIs(rules,fixture.kwargs['rules'])
                self_test.assertIs(plan.to_targets(),fixture.native_targets)
                calls.append(('core',rules))
                return fixture.core_result
        self_test=self
        handler=Handler();handler.__dict__.update(fixture.handler.__dict__)
        kwargs=dict(fixture.kwargs,renamed_targets=set(),cli_suggested_exit_code=0,parse_rate=None,
                    total_time=1,commit_date='',changed_dependency_sources=None,all_subprojects=[],contributions=None,
                    progress_bar=None,disable_nosem=True)
        def main():
            self.assertEqual(sys.argv,observer.COMMAND)
            handler.start_scan(fixture.metadata,'unchanged-config')
            returned=Runner().invoke_semgrep_core(None,fixture.kwargs['rules'],False,False,False,N(is_pro=True),
                     True,False,False,N(is_historical_scan=False),[],False)
            self.assertIs(returned,fixture.core_result)
            handler.report_findings(**kwargs)
            raise SystemExit(0)
        result=observer.invoke_scanner(fixture.observer,Handler,Runner,Plan,main)
        self.assertEqual(result['scanId'],42);self.assertEqual([c[0] for c in calls],['start','plan','core','complete'])
        empty=observer.Observer('e'*32,'a'*40)
        class DispatcherHandler:
            start_scan=Handler.start_scan
            report_findings=Handler.report_findings
        with self.assertRaises(ValueError):observer.invoke_scanner(empty,DispatcherHandler,Runner,Plan,lambda:None)

class FunctionalBoundaryTests(unittest.TestCase):
    def test_snapshot_keeps_exact_tree_and_never_executes_repository_trap(self):
        import security_scan as scan
        from test_route import RouteTests
        from pathlib import Path
        fixture=RouteTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        marker=fixture.root.parent/(fixture.root.name+'-trap-ran')
        self.addCleanup(lambda: marker.unlink(missing_ok=True))
        trap=fixture.root/'trap';trap.write_text('#!/bin/sh\nprintf unsafe > '+str(marker)+'\n');trap.chmod(0o755)
        sha=fixture.commit()
        destination=fixture.root.parent/(fixture.root.name+'-snapshot')
        import shutil
        self.addCleanup(lambda:shutil.rmtree(destination,ignore_errors=True))
        hashes=scan.snapshot(fixture.root,{'testedSha':sha},destination)
        self.assertIn('trap',hashes);self.assertFalse(marker.exists())
        scan.verify_snapshot(destination,hashes)
        (destination/'README.md').write_text('modified')
        with self.assertRaises(ValueError):scan.verify_snapshot(destination,hashes)

    def test_native_main_command_has_no_local_build_or_secrets_and_hooks_match_admitted_source(self):
        import semgrep_observer as observer
        import security_scan as scan
        self.assertEqual(observer.COMMAND, scan.SEMGREP_COMMAND)
        self.assertNotIn('--strict',observer.COMMAND)
        self.assertNotIn('--secrets',observer.COMMAND)
        self.assertNotIn('--allow-local-builds',observer.COMMAND)
        self.assertIn('--no-suppress-errors',observer.COMMAND)
        self.assertIn('--pro',observer.COMMAND)

    def test_semgrep_completion_forgery_does_not_satisfy_verifier(self):
        import security_scan as scan
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);out=root/'scan';out.mkdir()
            scan.write_json(out/'complete.json',{'unit':'semgrep','route':{},'tools':{},'result':{'products':['sast','sca'],'upload':True}})
            with self.assertRaises(ValueError):scan.verified_completion(root,{},out,'semgrep',{})

class NegativeControlTests(unittest.TestCase):
    def test_code_control_rejects_false_positive_in_negative_fixture(self):
        import security_scan as scan
        report=ColdControlTests().report(['control.go','control.py','control.ts','negative.ts'])
        with self.assertRaises(ValueError):scan.verify_code_controls(report)




class EmptyManifestTests(unittest.TestCase):
    """Constructed native records exercise reconciliation, never image qualification."""
    profiles = {
        'scripts/ci/gotestdecls/go.mod': b'module ricevanta.invalid/gotestdecls\n\ngo 1.27.1\n',
        'scripts/ci/fixtures/selected/tiny-go/go.mod': b'module example.com/tiny\n\ngo 1.22\n',
    }

    def setUp(self):
        import tempfile, hashlib
        from pathlib import Path
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.source=Path(self.temp.name);self.hashes={}
        for path,payload in self.profiles.items():
            target=self.source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(payload)
            self.hashes[path]=hashlib.sha256(payload).hexdigest()

    def verify(self):
        import security_scan as scan
        return scan.verify_empty_manifests(self.source,self.hashes)

    def test_exact_profiles_and_permitted_blank_lines(self):
        import hashlib
        for path,payload in self.profiles.items():
            self.assertEqual(self.verify()[path],hashlib.sha256(payload).hexdigest())
            payload=payload+b'\n'*(4096-len(payload));(self.source/path).write_bytes(payload)
            self.hashes[path]=hashlib.sha256(payload).hexdigest()
        self.assertEqual(set(self.verify()),set(self.profiles))

    def test_full_consumption_and_size_reject_every_extra_directive(self):
        import hashlib
        for path,payload in self.profiles.items():
            bad=[payload[:-1],payload.replace(b'\n',b'\r\n'),payload+b'\0\n',payload+b'\xff\n',
                 payload+b'// comment\n',payload.replace(b'module ',b'module  '),payload.replace(b'go ',b'go\t'),
                 payload.replace(b'module ',b'module wrong/'),payload.replace(b'go ',b'go 0'),
                 payload.split(b'\n',1)[1],payload.split(b'\ngo ')[0]+b'\n',payload+payload,
                 payload+b'require example.com/added v1.0.0\n',payload.replace(b'\n',b';',1),
                 payload+b'\n'*4096,payload.replace(b'go ',b'go (')]
            bad += [payload+directive+b' invalid\n' for directive in
                    (b'require',b'replace',b'exclude',b'tool',b'toolchain',b'retract',b'godebug',b'unknown')]
            for value in bad:
                with self.subTest(path=path,value=value[:80]):
                    (self.source/path).write_bytes(value);self.hashes[path]=hashlib.sha256(value).hexdigest()
                    with self.assertRaises(ValueError):self.verify()
            (self.source/path).write_bytes(payload);self.hashes[path]=hashlib.sha256(payload).hexdigest()

    def test_inventory_digest_links_and_sibling_sum_fail(self):
        import os
        for path in self.profiles:
            target=self.source/path;payload=target.read_bytes();digest=self.hashes[path]
            del self.hashes[path]
            with self.assertRaises(ValueError):self.verify()
            self.hashes[path]='0'*64
            with self.assertRaises(ValueError):self.verify()
            self.hashes[path]=digest
            sibling=path[:-3]+'sum';self.hashes[sibling]='0'*64
            with self.assertRaises(ValueError):self.verify()
            del self.hashes[sibling]
            self.hashes['./'+path]=digest
            with self.assertRaises(ValueError):self.verify()
            del self.hashes['./'+path]
            target.unlink();target.symlink_to(inventory.ROOT/path)
            with self.assertRaises(ValueError):self.verify()
            target.unlink();target.write_bytes(payload)
            linked=target.with_name('linked');os.link(target,linked)
            with self.assertRaises(ValueError):self.verify()
            linked.unlink()
            parent=target.parent;renamed=parent.with_name(parent.name+'-real');parent.rename(renamed);parent.symlink_to(renamed)
            with self.assertRaises(ValueError):self.verify()
            parent.unlink();renamed.rename(parent)

    def test_synthetic_seven_input_union_preserves_native_omission_and_zero(self):
        from copy import deepcopy
        import security_scan as scan
        fixture=SemgrepReportTests();fixture.setUp()
        for explicit in (False,True):
            for path in self.profiles:
                if explicit:fixture.summary['dependencies'][path]=0
            original=deepcopy(fixture.summary['dependencies'])
            result=fixture.verify()
            self.assertEqual(result['dependencies'],original)
            self.assertEqual(result['emptyInputs'],{p:fixture.hashes[p] for p in self.profiles})
            self.assertEqual(fixture.summary['dependencies'],original)
            for path in self.profiles:
                native=result['emptyNativeInputs'][path]
                self.assertEqual(native,dict(resolved=True,resolutionMethod='LockfileParsing',ecosystem='gomod',
                    dependencyCount=0,mapPresent=explicit,**({'mapCount':0} if explicit else {})))

    def test_synthetic_empty_native_record_refusals(self):
        from copy import deepcopy
        fixture=SemgrepReportTests();fixture.setUp()
        for path in self.profiles:
            row=next(r for r in fixture.report['subprojects'] if r['dependency_sources']==[path])
            original=deepcopy(row)
            for field,values in (('dependency_count',[True,False,'0',1,-1,None]),
                                 ('ecosystem',['Go','pypi',None]),('resolution_method',['DynamicResolution',None])):
                for value in values:
                    row['resolved_stats'][field]=value
                    with self.subTest(path=path,field=field,value=value),self.assertRaises(ValueError):fixture.verify()
                row.clear();row.update(deepcopy(original))
            for field,value in (('resolved',False),('resolved',1),('unresolved_reason','error'),
                                ('dependency_sources',[path,'server/go.mod']),('dependency_sources',['./'+path]),
                                ('dependency_sources',[path,path])):
                row[field]=value
                with self.subTest(path=path,field=field),self.assertRaises(ValueError):fixture.verify()
                row.clear();row.update(deepcopy(original))
            for count in (True,'0',1,-1,None):
                fixture.summary['dependencies'][path]=count
                with self.subTest(path=path,count=count),self.assertRaises(ValueError):fixture.verify()
            del fixture.summary['dependencies'][path]
            fixture.report['subprojects'].append(deepcopy(row))
            with self.assertRaises(ValueError):fixture.verify()
            fixture.report['subprojects'].pop();fixture.report['subprojects'].remove(row)
            with self.assertRaises(ValueError):fixture.verify()
            fixture.report['subprojects'].append(row)

    def test_each_populated_input_still_requires_positive_matching_counts(self):
        fixture=SemgrepReportTests();fixture.setUp()
        for path in fixture.paths:
            for count in (None,0,True,'1',2):
                if count is None:del fixture.summary['dependencies'][path]
                else:fixture.summary['dependencies'][path]=count
                with self.subTest(path=path,count=count),self.assertRaises(ValueError):fixture.verify()
                fixture.summary['dependencies'][path]=1
        fixture.hashes['other/go.mod']='0'*64
        with self.assertRaises(ValueError):fixture.verify()

class EmptyParserQualificationTests(unittest.TestCase):
    def test_synthetic_qualification_is_image_and_full_input_bound(self):
        from copy import deepcopy
        import security_scan as scan
        hashes={p:__import__('hashlib').sha256((inventory.ROOT/p).read_bytes()).hexdigest() for p in scan.EMPTY_MANIFESTS}
        lock=scan.load_lock(inventory.ROOT)
        evidence=synthetic_empty_qualification(lock,hashes)
        scan.verify_empty_qualification(evidence,lock,hashes,inventory.ROOT)
        for field,value in (('image','sha256:'+'0'*64),('config','sha256:'+'0'*64),('version','1.0'),('inputs',{})):
            bad=deepcopy(evidence);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):scan.verify_empty_qualification(bad,lock,hashes,inventory.ROOT)
        for path in hashes:
            for field,value in (('sha256','0'*64),('dependencies',1),('errors',True),('errors',1),
                                ('populated',{}),('malformed',{})):
                bad=deepcopy(evidence);bad['inputs'][path][field]=value
                with self.subTest(path=path,field=field),self.assertRaises(ValueError):scan.verify_empty_qualification(bad,lock,hashes,inventory.ROOT)
            for case,field,value in (('populated','errors',1),('populated','dependencies',0),
                                    ('populated','package','wrong'),('populated','version','1.2.4'),
                                    ('populated','ecosystem','Go'),('malformed','errors',0),('malformed','errors',True)):
                bad=deepcopy(evidence);bad['inputs'][path][case][field]=value
                with self.subTest(case=case,field=field),self.assertRaises(ValueError):scan.verify_empty_qualification(bad,lock,hashes,inventory.ROOT)

    def test_isolated_command_uses_unmodified_parser_without_token_network_or_observer(self):
        import tempfile
        from pathlib import Path, PurePosixPath
        from unittest.mock import patch
        import security_scan as scan
        lock=scan.load_lock(inventory.ROOT)
        hashes={p:__import__('hashlib').sha256((inventory.ROOT/p).read_bytes()).hexdigest() for p in scan.EMPTY_MANIFESTS}
        with tempfile.TemporaryDirectory() as temp:
            output=Path(temp)
            def execute(command,env,**kwargs):
                self.assertIn('--network',command);self.assertEqual(command[command.index('--network')+1],'none')
                self.assertIn('--read-only',command);self.assertNotIn('--scan',command)
                self.assertNotIn('/control/semgrep_observer.py',command)
                self.assertEqual(command[-1],'/control/fixtures/security/qualify_empty_manifests.py')
                self.assertEqual(set(env),{'PATH','HOME'})
                report=synthetic_empty_qualification(lock,hashes)
                scan.write_json(output/'empty-parser.json',dict(version=report['version'],inputs=report['inputs']))
            real_container_command=scan.container_command
            def linux_container(image,source,out,control,*,scan):
                self.assertEqual(source,output/'empty-parser-source')
                self.assertEqual(out,output)
                self.assertEqual(control,inventory.ROOT/'scripts/ci')
                self.assertFalse(scan)
                # The scanner's command contract is Linux-only; filesystem staging
                # above still uses real files on the machine running this unit test.
                return real_container_command(image,PurePosixPath('/source'),PurePosixPath('/out'),
                                              PurePosixPath('/control'),scan=scan,identity=(1001,1001))
            with patch.object(scan,'execute',side_effect=execute), patch.object(scan,'container_command',side_effect=linux_container):
                result=scan.empty_parser_controls('admitted-image',inventory.ROOT,output,inventory.ROOT,hashes,lock)
            self.assertEqual(result,synthetic_empty_qualification(lock,hashes))


def synthetic_empty_qualification(lock,hashes):
    """Manufactured unit evidence only. Never native parser qualification."""
    import hashlib
    import security_scan as scan
    rows={}
    for path in scan.EMPTY_MANIFESTS:
        payload=(inventory.ROOT/path).read_bytes()
        rows[path]=dict(sha256=hashes[path],dependencies=0,errors=0,
            populated=dict(sha256=hashlib.sha256(payload+b'require example.com/semgrep-control v1.2.3\n').hexdigest(),
                dependencies=1,errors=0,package='example.com/semgrep-control',version='1.2.3',ecosystem='gomod'),
            malformed=dict(sha256=hashlib.sha256(payload+b'not_a_go_directive invalid\n').hexdigest(),dependencies=0,errors=1))
    return dict(version='1.178.0',image=lock['semgrep']['manifest'],config=lock['semgrep']['config'],inputs=rows)


class EmptyManifestLifecycleTests(unittest.TestCase):
    def test_snapshot_refuses_nonblob_mode_linked_file_and_linked_parent(self):
        import os
        from pathlib import Path
        import security_scan as scan
        fixture=EmptyManifestTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        for path,payload in fixture.profiles.items():
            for mode in ('120000','160000','100600'):
                with self.subTest(mode=mode),self.assertRaises(ValueError):scan.validate_source_entry(fixture.source,mode,path,payload)
            target=fixture.source/path;linked=target.with_name('linked');os.link(target,linked)
            with self.assertRaises(ValueError):scan.validate_source_entry(fixture.source,'100644',path,payload)
            linked.unlink()
            parent=target.parent;renamed=parent.with_name(parent.name+'-real');parent.rename(renamed);parent.symlink_to(renamed)
            with self.assertRaises(ValueError):scan.validate_source_entry(fixture.source,'100644',path,payload)
            parent.unlink();renamed.rename(parent)

    def test_independent_profile_repeats_at_scan_and_completion_and_refuses_mutation(self):
        import hashlib,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import security_scan as scan
        fixture=SemgrepReportTests();fixture.setUp();lock=scan.load_lock(inventory.ROOT)
        value=dict(testedSha=fixture.sha,runId='1',runAttempt='1')
        with tempfile.TemporaryDirectory() as temp:
            admission_dir=Path(temp)/'security-semgrep-admission';source=admission_dir/'source';source.mkdir(parents=True)
            for path in fixture.hashes:
                payload=(inventory.ROOT/path).read_bytes() if path in fixture.empty_paths else b'synthetic source'
                target=source/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(payload)
                fixture.hashes[path]=hashlib.sha256(payload).hexdigest()
            table=source/'scripts/ci/semgrep-exceptions.toml';table.write_bytes(b'version=1\nscanner="1.178.0"\nexception=[]\n')
            fixture.hashes['scripts/ci/semgrep-exceptions.toml']=hashlib.sha256(table.read_bytes()).hexdigest()
            (source/scan.AUXILIARY_PATH).write_bytes(scan.AUXILIARY_BYTES)
            admission=dict(route=value,tools=lock,sourceHashes=fixture.hashes,pro=dict(version='1.178.0'),
                overlay={scan.AUXILIARY_PATH:scan.AUXILIARY_SHA256},
                controls={'emptyManifests':synthetic_empty_qualification(lock,fixture.hashes)})
            scan.write_json(admission_dir/'admission.json',admission)
            output=Path(temp)/'scan';output.mkdir()
            def native(*args,**kwargs):
                scan.write_json(output/'observer.json',fixture.summary);scan.write_json(output/'semgrep.json',fixture.report)
            with patch.object(scan,'admitted_image',return_value='admitted'),patch.object(scan,'container_command',return_value=['admitted']), \
                 patch.object(scan,'execute',side_effect=native),patch.object(scan.os,'urandom',return_value=bytes.fromhex(fixture.invocation)), \
                 patch.object(scan,'verify_empty_manifests',wraps=scan.verify_empty_manifests) as profile:
                result=scan.run_semgrep(inventory.ROOT,value,None,output,lock,'synthetic-token')
                self.assertGreater(profile.call_count,0)
            scan.write_json(output/'complete.json',dict(unit='semgrep',route=value,tools=lock,result=result))
            with patch.object(scan,'verify_empty_manifests',wraps=scan.verify_empty_manifests) as profile:
                self.assertEqual(scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock),result)
                self.assertGreater(profile.call_count,0)
            for path in fixture.empty_paths:
                target=source/path;original=target.read_bytes();target.write_bytes(original+b'require example.com/added v1.0.0\n')
                # Isolate the independent proof from the ordinary snapshot digest gate.
                with patch.object(scan,'verify_snapshot'),self.assertRaises(ValueError):
                    scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock)
                target.write_bytes(original)
            del admission['controls']['emptyManifests'];scan.write_json(admission_dir/'admission.json',admission)
            with self.assertRaises(ValueError):scan.verified_completion(inventory.ROOT,value,output,'semgrep',lock)


if __name__ == '__main__': unittest.main()

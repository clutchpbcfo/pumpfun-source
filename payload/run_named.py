"""PROPOSED controller: never run locally; requires approved isolated Linux plan.

This file has only been parsed as source data. Its controls are not yet qualified.
"""
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest

if sys.platform != 'linux' or sys.argv[1:2] != ['--approved-isolated-run']:
    raise SystemExit('Disabled outside the separately approved isolated Linux run')
if len(sys.argv) != 7 or sys.argv[2] not in ('base', 'patched'):
    raise SystemExit('Expected flag, phase, source, work, manifest and draft receipt')
phase = sys.argv[2]
source, work, manifest_path, receipt_path = map(Path, sys.argv[3:])
source, work = source.resolve(), work.resolve()
manifest = json.loads(manifest_path.read_text())
receipt = json.loads(receipt_path.read_text())
admission = receipt['validation_proposal']
executable = set(admission['repository_python_modules_that_may_execute'])
names = executable | set(admission['repository_files_read_as_hash_inputs_only'])
assert len(names) == 10 and len(executable) == 6
assert not work.is_relative_to(source) and not source.is_relative_to(work)
assert os.getuid() != 0
assert os.readlink('/proc/self/ns/net') != os.environ['OUTER_NETNS']
assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
assert 'CapEff:\t0000000000000000' in Path('/proc/self/status').read_text()
assert not any(name in os.environ for name in ('GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'SSH_AUTH_SOCK'))
canary = Path('/case/readonly-canary.txt')
assert canary.read_text() == 'owned nonsecret readonly canary\n'
try:
    canary.write_text('must not write')
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise RuntimeError('Source mount is writable; no repository code admitted')

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

actual_names = set()
for path in source.rglob('*'):
    assert not path.is_symlink()
    if path.is_file():
        actual_names.add(path.relative_to(source).as_posix())
assert actual_names == names
before = {}
for name in names:
    expected = manifest[name]['sha256']
    if phase == 'patched' and name == receipt['changed_path']:
        expected = receipt['patched_source_sha256']
    before[name] = digest(source / name)
    assert before[name] == expected, name

work.mkdir(parents=True, exist_ok=True)
tempfile.tempdir = str(work)
os.chdir(source)
denied, executed = [], set()

def guard(event, args):
    if (event in ('subprocess.Popen', 'os.system', 'os.exec', 'os.fork', 'os.posix_spawn')
            or event.startswith('socket.')):
        denied.append(event)
        raise RuntimeError('Unapproved process or network event: ' + event)
    if event == 'import' and args[0].split('.')[0] in ('solders', 'solana', 'ctypes', 'cffi'):
        denied.append('import:' + args[0])
        raise RuntimeError('Unapproved native/VM import')
    if event == 'exec':
        filename = getattr(args[0], 'co_filename', '')
        if filename and not filename.startswith('<'):
            path = Path(filename).resolve()
            if path.is_relative_to(source):
                name = path.relative_to(source).as_posix()
                if name not in executable:
                    denied.append('exec:' + name)
                    raise RuntimeError('Unapproved repository module execution')
                executed.add(name)

sys.addaudithook(guard)
audit_canaries = []
for event, args in [('subprocess.Popen', ()), ('socket.__new__', ()),
                    ('import', ('solders', None, [], [], []))]:
    count = len(denied)
    try:
        sys.audit(event, *args)
    except RuntimeError:
        assert len(denied) == count + 1
    else:
        raise RuntimeError('Owned audit-event canary was not rejected')
    audit_canaries.append(denied.pop())
assert not denied and len(audit_canaries) == 3
path = source / 'scripts/amm_sell/test_sell_identity.py'
spec = importlib.util.spec_from_file_location('approved_identity_case', path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
methods = admission['methods']
assert methods == ['ImageIdentityTests.test_exact_all_three_files',
    'ImageIdentityTests.test_attempt_cache_separates_old_meaning_and_preserves_new_metrics']
suite = unittest.TestSuite([module.ImageIdentityTests(name.split('.')[1]) for name in methods])
assert suite.countTestCases() == 2
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
after = {name: digest(source / name) for name in names}
record = {'phase': phase, 'base': receipt['base'], 'tests_run': result.testsRun,
    'failures': [{'test': test.id(), 'trace': trace} for test, trace in result.failures],
    'errors': [{'test': test.id(), 'trace': trace} for test, trace in result.errors],
    'unittest_output': stream.getvalue(), 'denied_events': denied,
    'owned_synthetic_audit_canaries_rejected': audit_canaries,
    'repository_modules_executed': sorted(executed), 'source_before': before,
    'source_after': after, 'source_unchanged': before == after,
    'source_readonly_canary_rejected': True, 'nonroot_zero_effective_capabilities': True,
    'separate_network_namespace_loopback_only': True,
    'capture_files_in_bundle': 0, 'test_discovery': False,
    'python_version': sys.version, 'python_sha256': digest(Path(sys.executable).resolve())}
(work / 'result.json').write_text(json.dumps(record, indent=2) + '\n')
assert result.testsRun == 2 and not result.errors and not denied
assert before == after and executed == executable
if phase == 'base':
    assert len(result.failures) == 2
    assert all('6 != 5' in trace for _, trace in result.failures)
else:
    assert result.wasSuccessful()
print(json.dumps({'phase': phase, 'tests': result.testsRun,
                  'failures': len(result.failures), 'errors': len(result.errors)}))

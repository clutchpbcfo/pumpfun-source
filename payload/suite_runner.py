#!/usr/bin/env python3
"""Owned runner for nine explicitly named, hash-admitted regression modules."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PAYLOAD = Path(__file__).resolve().parent


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def flattened(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flattened(item)
        else:
            yield item


def run(phase, target):
    manifest = json.loads((PAYLOAD / 'SOURCE_MANIFEST.json').read_text())
    module_root = PAYLOAD / 'phases' / phase
    for relative, expected in manifest['repository_executable_files'][phase].items():
        if hashlib.sha256((module_root / relative).read_bytes()).hexdigest() != expected:
            raise RuntimeError('regression input hash mismatch: ' + relative)
    for relative, expected in manifest['hash_only_files'][phase].items():
        if hashlib.sha256((module_root / relative).read_bytes()).hexdigest() != expected:
            raise RuntimeError('regression data hash mismatch: ' + relative)
    temporary_root = target.parent / ('temporary-' + phase)
    temporary_root.mkdir()
    os.environ['TMPDIR'] = str(temporary_root)
    tempfile.tempdir = None
    launches = []
    allowed = {'git', 'python', 'python3', 'python3.12', 'bash', 'sh', 'env'}

    def audit(event, arguments):
        if event == 'subprocess.Popen':
            executable = os.fsdecode(arguments[0])
            name = Path(executable).name
            if name not in allowed:
                raise RuntimeError('unadmitted subprocess: ' + executable)
            if name.startswith('python') and any(Path(str(token)).name == 'search_dependency_commit.py' for token in arguments[1]):
                raise RuntimeError('hash-only fixture must not execute')
            launches.append({'executable': executable, 'argv': list(map(str, arguments[1]))})
        if event == 'exec':
            filename = getattr(arguments[0], 'co_filename', '')
            if filename and not filename.startswith('<'):
                executed = Path(filename).resolve()
                if executed.is_relative_to(module_root) and executed.relative_to(module_root).as_posix() not in manifest['repository_executable_files'][phase]:
                    raise RuntimeError('hash-only or unadmitted repository file must not execute')
        if event in ('socket.connect', 'socket.bind', 'socket.getaddrinfo'):
            raise RuntimeError('network operation is outside the regression workload')
        if event == 'import' and str(arguments[0]).split('.')[0] in {'solders', 'litesvm', 'solana', 'anchorpy', 'search_dependency_commit'}:
            raise RuntimeError('VM/SDK import is outside the regression workload')

    sys.addaudithook(audit)
    sys.path.insert(0, str(module_root / 'scripts'))
    modules = manifest['regression_modules']
    suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
    test_ids = [test.id() for test in flattened(suite)]
    if sorted(test_ids) != manifest['regression_test_ids'] or len(test_ids) != len(set(test_ids)):
        raise RuntimeError('loaded test set differs from the frozen named methods')
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    imported = {}
    for name, module in list(sys.modules.items()):
        filename = getattr(module, '__file__', None)
        if filename:
            path = Path(filename).resolve()
            if path.is_relative_to(module_root):
                imported[name] = path.relative_to(module_root).as_posix()
    if not set(imported.values()).issubset(manifest['repository_executable_files'][phase]):
        raise RuntimeError('unexpected repository import in regression run')
    report = {'phase': phase, 'test_ids': sorted(test_ids), 'tests_run': result.testsRun,
        'failures': [{'id': test.id(), 'traceback': trace} for test, trace in result.failures],
        'errors': [{'id': test.id(), 'traceback': trace} for test, trace in result.errors],
        'skipped': [{'id': test.id(), 'reason': reason} for test, reason in result.skipped],
        'unittest_was_successful': result.wasSuccessful(),
        'unittest_equivalent_exit': 0 if result.wasSuccessful() else 1,
        'imported_repository_files': imported, 'direct_subprocess_launches': launches,
        'audit_limit': 'Direct launches from this runner only; not an exhaustive descendant-process count.',
        'repository_test_discovery': False, 'hash_only_files_executed': False}
    save(target, report)
    expected_failures = manifest['expected_base_failure_ids'] if phase == 'base' else []
    if sorted(f['id'] for f in report['failures']) != expected_failures or report['errors'] or report['skipped']:
        raise RuntimeError('unexpected regression result; retained in ' + str(target))
    if report['tests_run'] != len(manifest['regression_test_ids']):
        raise RuntimeError('incomplete named regression run')


if __name__ == '__main__':
    try:
        if len(sys.argv) != 3 or sys.argv[1] not in ('base', 'patched'):
            raise RuntimeError('unexpected owned regression-runner arguments')
        run(sys.argv[1], Path(sys.argv[2]))
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)

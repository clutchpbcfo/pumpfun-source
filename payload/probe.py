#!/usr/bin/env python3
"""Owned controller for an approved hosted probe; never run its payload on Mac."""
import errno
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

CHECKER_SHA256 = 'dbfd77bc91b4f3963c5f4e70905ed3868a1aabdab60a6ff7011116aec46a8515'
PAYLOAD = Path(__file__).resolve().parent
CASES = ('boolean-valid', 'boolean-missing', 'string-control')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hashes(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise RuntimeError('linked probe input')
        if path.is_file():
            result[path.relative_to(root).as_posix()] = digest(path)
    return result


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def command(argv, cwd, output, label, env=None):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=45)
    (output / (label + '.stdout')).write_text(result.stdout)
    (output / (label + '.stderr')).write_text(result.stderr)
    return {'argv': list(map(str, argv)), 'exit_code': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr}


def prepare(root):
    root.mkdir()
    for name in CASES:
        target = root / name
        target.mkdir()
        for source in (PAYLOAD / 'cases' / name).rglob('*'):
            relative = source.relative_to(PAYLOAD / 'cases' / name)
            if source.is_symlink():
                raise RuntimeError('linked fixture')
            if source.is_dir():
                (target / relative).mkdir(exist_ok=True)
            else:
                (target / relative).parent.mkdir(parents=True, exist_ok=True)
                (target / relative).write_bytes(source.read_bytes())
        # Fixture metadata only: no remotes, commits, credentials or project hooks.
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
               'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null'}
        subprocess.run(['/usr/bin/git', '-c', 'init.defaultBranch=main', 'init', '-q', str(target)],
                       env=env, check=True, timeout=15)
    save(root / 'frozen-hashes.json', hashes(root))


def read_only_canary(root):
    path = root / '.owned-readonly-canary'
    try:
        path.write_text('must fail')
    except OSError as error:
        if error.errno != errno.EROFS:
            raise RuntimeError('readonly control did not fail with EROFS') from error
    else:
        path.unlink()
        raise RuntimeError('readonly control unexpectedly wrote')


def analyze(fixtures, output, parent_network_namespace, renderings):
    output.mkdir(exist_ok=True)
    # Persist raw qualification observations before deciding whether payload
    # execution is admitted. A failed qualification still produces evidence.
    preflight = {'phase': 'before_repository_checker', 'github_renderings': renderings,
                 'parent_network_namespace': parent_network_namespace,
                 'repository_checker_invocations_started': 0}
    save(output / 'isolation-preflight.json', preflight)
    try:
        status = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
        caps = {key: status[key].strip() for key in ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']}
        proc_net_dev = Path('/proc/self/net/dev').read_text()
        interfaces = sorted(line.partition(':')[0].strip() for line in proc_net_dev.splitlines()[2:] if ':' in line)
        current_network_namespace = os.readlink('/proc/self/ns/net')
        try:
            sysfs_interfaces = sorted(p.name for p in Path('/sys/class/net').iterdir())
        except OSError as error:
            sysfs_interfaces = {'read_error': type(error).__name__ + ': ' + str(error)}
        preflight.update(uid=os.getuid(), gid=os.getgid(), groups=os.getgroups(),
                         capabilities=caps, no_new_privileges=status['NoNewPrivs'].strip(),
                         current_network_namespace=current_network_namespace,
                         proc_net_interfaces=interfaces, proc_net_dev=proc_net_dev,
                         sysfs_interfaces_diagnostic_only=sysfs_interfaces)
        save(output / 'isolation-preflight.json', preflight)
        if renderings != ['true', 'false', 'True', 'False']:
            raise RuntimeError('unexpected GitHub interpolation; see isolation-preflight.json')
        if os.getuid() == 0 or os.getgid() == 0 or os.getgroups() or any(int(value, 16) for value in caps.values()):
            raise RuntimeError('UID/group/capability qualification failed; see isolation-preflight.json')
        if status['NoNewPrivs'].strip() != '1':
            raise RuntimeError('no_new_privs qualification failed; see isolation-preflight.json')
        # sysfs can retain its mounting namespace's view. Use the process's
        # own proc network view and require a different namespace identifier.
        def network_namespace_identifier(value):
            return value.startswith('net:[') and value.endswith(']') and value[5:-1].isdigit()
        if (not network_namespace_identifier(parent_network_namespace)
                or not network_namespace_identifier(current_network_namespace)
                or current_network_namespace == parent_network_namespace):
            raise RuntimeError('network namespace separation failed; see isolation-preflight.json')
        if interfaces != ['lo']:
            raise RuntimeError('external network interface in process namespace; see isolation-preflight.json')
    except Exception as error:
        preflight['qualification_error'] = type(error).__name__ + ': ' + str(error)
        save(output / 'isolation-preflight.json', preflight)
        raise
    read_only_canary(PAYLOAD)
    read_only_canary(fixtures)
    checker = PAYLOAD / 'repo/check_workflow_inputs.py'
    if digest(checker) != CHECKER_SHA256:
        raise RuntimeError('repository helper hash mismatch')
    manifest = json.loads((PAYLOAD / 'SOURCE_MANIFEST.json').read_text())
    if set(hashes(PAYLOAD)) != set(manifest['payload_files']) | {'SOURCE_MANIFEST.json'}:
        raise RuntimeError('unexpected or missing payload file')
    for name, expected in manifest['payload_files'].items():
        if digest(PAYLOAD / name) != expected:
            raise RuntimeError('payload input hash mismatch: ' + name)
    fixture_before = hashes(fixtures)
    for value in ('true', 'false'):
        if not (fixtures / 'boolean-valid/scripts' / ('flag-' + value + '.py')).is_file():
            raise RuntimeError('missing owned lowercase fixture')
        if (fixtures / 'boolean-valid/scripts' / ('flag-' + value.title() + '.py')).exists():
            raise RuntimeError('case-sensitive fixture qualification failed')
    frozen = json.loads((fixtures / 'frozen-hashes.json').read_text())
    if {k: v for k, v in fixture_before.items() if k != 'frozen-hashes.json'} != frozen:
        raise RuntimeError('prepared fixtures changed')
    import yaml
    if yaml.__version__ != '6.0.3':
        raise RuntimeError('unexpected PyYAML version')
    qualification = {'uid': os.getuid(), 'gid': os.getgid(), 'groups': os.getgroups(),
        'capabilities': caps, 'no_new_privileges': True, 'interfaces': interfaces,
        'parent_network_namespace': parent_network_namespace, 'current_network_namespace': current_network_namespace,
        'payload_and_fixture_writes_rejected_EROFS': True,
        'python': sys.version, 'pyyaml': yaml.__version__, 'github_renderings': renderings,
        'checker_sha256': digest(checker), 'source_execution_modules': ['check_workflow_inputs.py'],
        'subprocess_scope': 'trusted Git inventory reads and six owned Python path controls'}
    save(output / 'qualification.json', qualification)
    env = dict(os.environ)
    env['GIT_CONFIG_COUNT'] = str(len(CASES))
    for index, name in enumerate(CASES):
        env['GIT_CONFIG_KEY_' + str(index)] = 'safe.directory'
        env['GIT_CONFIG_VALUE_' + str(index)] = str(fixtures / name)
    expected_checker = {'boolean-valid': 1, 'boolean-missing': 0, 'string-control': 0}
    expected_paths = ['scripts/flag-True.py', 'scripts/flag-False.py']
    observations = []
    for name in CASES:
        root = fixtures / name
        checked = command([sys.executable, '-I', '-B', str(checker), '--repo', str(root), '--all'],
                          root, output, name + '-checker', env)
        if checked['exit_code'] != expected_checker[name]:
            raise RuntimeError('planned base checker behavior not reproduced: ' + name)
        report = json.loads(checked['stdout'])
        if report['checked_references'] != 2 or report['uninspected']:
            raise RuntimeError('fixture was not fully inspected by the real checker')
        expected_missing = set(expected_paths) if name == 'boolean-valid' else set()
        if {r[2] for r in report['new_missing']} != expected_missing:
            raise RuntimeError('unexpected checker paths: ' + name)
        rendered = renderings[:2] if name != 'string-control' else renderings[2:]
        native = []
        for index, value in enumerate(rendered):
            script = 'scripts/flag-' + value + '.py'
            run = command([sys.executable, '-I', '-B', script], root, output,
                          name + '-native-' + str(index), env)
            expected_exit = 2 if name == 'boolean-missing' else 0
            if run['exit_code'] != expected_exit:
                raise RuntimeError('unexpected actual Python path result: ' + name)
            if expected_exit == 0 and json.loads(run['stdout']) != {'case': name, 'file': Path(script).name}:
                raise RuntimeError('native marker does not bind the executed fixture file')
            if expected_exit == 2 and ('No such file or directory' not in run['stderr'] or Path(script).name not in run['stderr']):
                raise RuntimeError('negative path control failed for a different reason')
            native.append(run)
        observations.append({'case': name, 'checker': checked, 'report': report, 'native_path_controls': native})
    if hashes(fixtures) != fixture_before or digest(checker) != CHECKER_SHA256:
        raise RuntimeError('input hashes changed during probe')
    save(output / 'probe-result.json', {'status': 'BASE_BEHAVIOR_REPRODUCED',
        'source_commit': manifest['source_commit'], 'checker_sha256': CHECKER_SHA256,
        'checker_cli_invocations': 3, 'owned_python_path_invocations': 6,
        'observations': observations, 'input_hashes_unchanged': True,
        'patched_source_run': False, 'repository_test_discovery': False,
        'captured_execution': False, 'native_compilation': False,
        'limit': 'One workflow-input checker behavior, not repository CI or program equivalence.'})


if __name__ == '__main__':
    try:
        if sys.argv[1] == 'prepare' and len(sys.argv) == 3:
            prepare(Path(sys.argv[2]))
        elif sys.argv[1] == 'analyze' and len(sys.argv) == 9:
            analyze(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4], sys.argv[5:])
        else:
            raise RuntimeError('unexpected owned controller invocation')
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)

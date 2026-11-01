#!/usr/bin/env python3
"""Inspect retained workflow inputs through real local Git hooks; run no jobs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

WORKFLOW = Path('.github/workflows/search-dependency.yml')
SCRIPT = Path('scripts/search_dependency_commit.py')
CHECKER = Path('scripts/check_workflow_inputs.py')
FORMS = {
    'working_base': ['--base', 'HEAD^'],
    'working_all': ['--all'],
    'committed_base': ['--base', 'HEAD^', '--head', 'HEAD'],
    'committed_all': ['--all', '--head', 'HEAD'],
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def reproduce(repo, revision=None):
    repo = Path(repo).resolve()
    raw = (subprocess.check_output(['git', '-C', str(repo), 'show', revision + ':' + CHECKER.as_posix()])
           if revision else (repo / CHECKER).read_bytes())
    retained = {p: (repo / p).read_bytes() for p in (WORKFLOW, SCRIPT)}
    environment = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    identity = ['-c', 'user.name=Local Reproduction', '-c', 'user.email=reproduction@example.invalid',
                '-c', 'commit.gpgsign=false']
    proof = {'source_revision': revision or 'working tree', 'checker_sha256': sha(raw),
             'retained_input_sha256': {str(p): sha(b) for p, b in retained.items()}, 'rows': []}
    with tempfile.TemporaryDirectory(prefix='workflow-git-context-') as temporary:
        root = Path(temporary)
        checker = root / CHECKER.name
        checker.write_bytes(raw)
        target, outer = root / 'target', root / 'hook-caller'

        def git(directory, *args):
            return subprocess.run(['git', '-C', str(directory), *identity, *args],
                                  env=environment, capture_output=True, text=True, check=True)

        for directory in (target, outer):
            directory.mkdir()
            git(directory, 'init', '--template=', '-q')
        for path, content in retained.items():
            dest = target / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(content)
        git(target, 'add', '.')
        git(target, 'commit', '-qm', 'Retained workflow and literal input')
        git(target, 'commit', '--allow-empty', '-qm', 'Unchanged retained control')
        (outer / 'caller.txt').write_text('Independent local hook caller\n')
        git(outer, 'add', 'caller.txt')
        git(outer, 'commit', '-qm', 'Independent caller')
        git(outer, 'commit', '--allow-empty', '-qm', 'Independent parent')
        config, hook_result = root / 'command.json', root / 'hook-result.json'
        driver = root / 'hook_driver.py'
        driver.write_text(
            'import json,os,subprocess\nfrom pathlib import Path\n'
            + 'cmd=json.loads(Path(' + repr(str(config)) + ').read_text())\n'
            + 'p=subprocess.run(cmd,text=True,capture_output=True)\n'
            + 'row={"exit":p.returncode,"report":json.loads(p.stdout) if p.stdout else None,'
              '"stderr":p.stderr,"routing":{k:os.environ[k] for k in '
              '["GIT_DIR","GIT_WORK_TREE","GIT_INDEX_FILE","GIT_COMMON_DIR"] if k in os.environ}}\n'
            + 'Path(' + repr(str(hook_result)) + ').write_text(json.dumps(row))\n')
        hook = outer / '.git/hooks/pre-commit'
        hook.parent.mkdir()
        hook.write_text('#!/bin/sh\nexec ' + shlex.join([sys.executable, '-B', str(driver)]) + '\n')
        hook.chmod(0o755)
        for state in ('present', 'missing'):
            if state == 'missing':
                (target / SCRIPT).unlink()
                git(target, 'add', '-u')
                git(target, 'commit', '-qm', 'Remove only the private workflow input')
            for form, options in FORMS.items():
                command = [sys.executable, '-B', str(checker), '--repo', str(target), *options]
                config.write_text(json.dumps(command))
                for context in ('direct', 'default_hook', 'routed_hook'):
                    if context == 'direct':
                        run = subprocess.run(command, env=environment, capture_output=True, text=True)
                        row = {'exit': run.returncode, 'report': json.loads(run.stdout) if run.stdout else None,
                               'stderr': run.stderr, 'routing': {}}
                    else:
                        hook_result.unlink(missing_ok=True)
                        if context == 'default_hook':
                            git(outer, 'commit', '--allow-empty', '-qm', 'Invoke foreign workflow check')
                        else:
                            subprocess.run(['git', '--git-dir=' + str(outer / '.git'),
                                            '--work-tree=' + str(outer), *identity, 'commit', '--allow-empty',
                                            '-qm', 'Invoke foreign workflow check'], env=environment,
                                           capture_output=True, text=True, check=True)
                        row = json.loads(hook_result.read_text())
                    row.update(state=state, form=form, context=context)
                    row['routing'] = {k: v.replace(str(root), 'OWNED') for k, v in row['routing'].items()}
                    row['stderr'] = row['stderr'].replace(str(root), 'OWNED')
                    proof['rows'].append(row)
        proof['private_workflow_unchanged'] = (target / WORKFLOW).read_bytes() == retained[WORKFLOW]
        proof['retained_repository_inputs_unchanged'] = all((repo / p).read_bytes() == b for p, b in retained.items())
    return proof


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--revision', help='Read complete checker source at this Git revision')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        raise FileExistsError('Use a fresh proof output')
    proof = reproduce(args.repo, args.revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('x', encoding='utf-8') as output:
        output.write(json.dumps(proof, indent=2) + '\n')
    print(json.dumps({'actual_checker_invocations': len(proof['rows']),
                      'zero_reference_rows': sum(row['report']['checked_references'] == 0 for row in proof['rows']),
                      'retained_repository_inputs_unchanged': proof['retained_repository_inputs_unchanged']}))


if __name__ == '__main__':
    main()

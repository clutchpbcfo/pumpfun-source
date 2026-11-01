"""Stage only the admitted public text inputs on a disposable Linux runner."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

if sys.platform != 'linux':
    raise SystemExit('Linux runner only; no local payload execution')
payload = Path(__file__).resolve().parent
root = Path(sys.argv[1])
root.mkdir(exist_ok=False)
case, control, work, public = [root / x for x in ('case', 'control', 'work', 'public')]
for directory in (case, control, work, public, root / 'home'):
    directory.mkdir()
manifest = json.loads((payload / 'SOURCE_MANIFEST.json').read_text())
receipt = json.loads((payload / 'DRAFT_RECEIPT.json').read_text())
names = (receipt['validation_proposal']['repository_python_modules_that_may_execute']
         + receipt['validation_proposal']['repository_files_read_as_hash_inputs_only'])
assert len(names) == len(set(names)) == 10
assert receipt['base'] == '9bd38c7d5a4684b647ab59fc8942ed56e990e3b3'
for name in names:
    p = Path(name)
    assert not p.is_absolute() and '..' not in p.parts
    raw = (payload / 'sources' / (name + '.txt')).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == manifest[name]['sha256']
    assert hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == manifest[name]['git_blob_sha1']
    for phase in ('base', 'patched'):
        out = case / phase / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(raw)
after = (payload / 'test_sell_identity.after.py.txt').read_bytes()
assert hashlib.sha256(after).hexdigest() == receipt['patched_source_sha256']
(case / 'patched' / receipt['changed_path']).write_bytes(after)
for name in ('SOURCE_MANIFEST.json', 'DRAFT_RECEIPT.json', 'run_named.py', 'qualify_linux.py'):
    shutil.copyfile(payload / name, control / name)
assert hashlib.sha256((control / 'run_named.py').read_bytes()).hexdigest() == receipt['proposed_controller']['sha256']
(case / 'readonly-canary.txt').write_text('owned nonsecret readonly canary\n')
(public / 'preflight.json').write_text(json.dumps({'source_base': receipt['base'],
    'workflow_commit': os.environ['GITHUB_SHA'], 'repository_files_per_revision': 10,
    'captured_images_included': 0, 'controller_sha256': receipt['proposed_controller']['sha256'],
    'source_manifest_sha256': hashlib.sha256((control / 'SOURCE_MANIFEST.json').read_bytes()).hexdigest(),
    'patch_sha256': hashlib.sha256((payload / 'identity-version.patch').read_bytes()).hexdigest()}, indent=2) + '\n')

"""Owned control checks only; imports no repository code."""
import errno
import json
import os
from pathlib import Path
import socket
import sys

assert sys.platform == 'linux' and sys.flags.isolated and sys.flags.no_site
assert os.getuid() != 0 and not os.getgroups()
assert 'CapEff:\t0000000000000000' in Path('/proc/self/status').read_text()
assert os.readlink('/proc/self/ns/net') != os.environ['OUTER_NETNS']
assert sorted(name for _, name in socket.if_nameindex()) == ['lo']
assert not any(k in os.environ for k in ('GITHUB_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'SSH_AUTH_SOCK'))
canary = Path('/case/readonly-canary.txt')
assert canary.read_text() == 'owned nonsecret readonly canary\n'
try:
    canary.write_text('must not write')
except OSError as error:
    assert error.errno == errno.EROFS
else:
    raise RuntimeError('Read-only mount qualification failed')
Path(sys.argv[1]).write_text(json.dumps({'qualified': True, 'repository_code_imported': False,
    'nonroot': True, 'supplementary_groups_cleared': True, 'effective_capabilities_zero': True,
    'separate_network_namespace': True, 'external_network_interfaces': [],
    'owned_readonly_write_rejected': True, 'isolated_python_without_site': True}, indent=2) + '\n')
print('Owned Linux isolation controls qualified before repository imports')

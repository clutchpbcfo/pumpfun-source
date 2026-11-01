#!/usr/bin/env bash
set -euo pipefail
if [ "$#" -ne 4 ]; then exit 2; fi
probe_root=$(mktemp -d /tmp/workflow-bool-probe-XXXXXXXX)
chmod 755 "$probe_root"
mkdir -p "$GITHUB_WORKSPACE/probe-receipts"
cp -R payload "$probe_root/frozen"
python3 -m venv "$probe_root/venv"
"$probe_root/venv/bin/python" -m pip install --disable-pip-version-check --only-binary=:all: --no-deps --require-hashes -r "$probe_root/frozen/requirements.txt"
"$probe_root/venv/bin/python" -I -B "$probe_root/frozen/probe.py" prepare "$probe_root/fixtures"
mkdir "$probe_root/output"
chmod 777 "$probe_root/output" "$probe_root/frozen" "$probe_root/fixtures"
set +e
sudo unshare --mount --net --pid --fork --mount-proc --propagation private \
  /bin/bash "$probe_root/frozen/isolate.sh" "$probe_root" "$@"
probe_status=$?
set -e
cp -R "$probe_root/output/." "$GITHUB_WORKSPACE/probe-receipts/"
exit "$probe_status"

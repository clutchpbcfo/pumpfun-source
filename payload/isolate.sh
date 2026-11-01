#!/usr/bin/env bash
set -euo pipefail
probe_root=$1
shift
for input in frozen fixtures venv; do
  mount --bind "$probe_root/$input" "$probe_root/$input"
  mount -o remount,bind,ro,nosuid,nodev "$probe_root/$input"
done
mount -o remount,bind,ro,nosuid,nodev,noexec "$probe_root/frozen"
mount -o remount,bind,ro,nosuid,nodev,noexec "$probe_root/fixtures"
cd "$probe_root/output"
exec setpriv --reuid=65534 --regid=65534 --clear-groups \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  env -i PATH=/usr/bin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    "$probe_root/venv/bin/python" -I -B "$probe_root/frozen/probe.py" \
    analyze "$probe_root/fixtures" "$probe_root/output" "$@"

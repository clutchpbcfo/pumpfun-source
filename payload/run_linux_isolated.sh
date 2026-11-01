#!/usr/bin/env bash
set -euo pipefail
test "$(uname -s)" = Linux
job_root="$RUNNER_TEMP/amm-identity-v6"
outer_netns="$(readlink /proc/self/ns/net)"
payload_uid="$(id -u)"
payload_gid="$(id -g)"
test "$payload_uid" != 0
retain_results() {
  for phase in base patched; do
    if test -f "$job_root/work/$phase/result.json"; then
      cp "$job_root/work/$phase/result.json" "$job_root/public/$phase.json"
    fi
  done
}
trap retain_results EXIT
sudo unshare --net --mount --propagation private /bin/bash -euo pipefail -c '
  root="$1"; uid="$2"; gid="$3"; outer_netns="$4"
  mkdir -p /case /control
  mount --bind "$root/case" /case
  mount -o remount,bind,ro,noexec,nosuid,nodev /case
  mount --bind "$root/control" /control
  mount -o remount,bind,ro,noexec,nosuid,nodev /control
  exec setpriv --reuid "$uid" --regid "$gid" --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
    env -i HOME="$root/home" PATH="/usr/bin:/bin" TMPDIR="$root/work" LANG=C.UTF-8 LC_ALL=C.UTF-8 OUTER_NETNS="$outer_netns" \
    /bin/bash -euo pipefail -c '\''
      root="$1"
      /usr/bin/python3 -I -S -B /control/qualify_linux.py "$root/public/qualification.json"
      for phase in base patched; do
        /usr/bin/timeout --kill-after=5s 120s /usr/bin/python3 -I -S -B /control/run_named.py \
          --approved-isolated-run "$phase" "/case/$phase" "$root/work/$phase" \
          /control/SOURCE_MANIFEST.json /control/DRAFT_RECEIPT.json
      done
    '\'' _ "$root"
' _ "$job_root" "$payload_uid" "$payload_gid" "$outer_netns"

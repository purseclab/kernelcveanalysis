#!/bin/bash
# Runs one full Cuttlefish snapshot -> mutate -> restore cycle against a runtime root.
#
# Usage: [SNAPSHOT_DELAY=<sec>] snapshot_cycle_test.sh <runtime_root> <kernel_dir|-> [instance_num]
#
# Mimics what cuttle_server's host backend does (separate HOME per instance, legacy
# launch_cvd/stop_cvd). Uses an instance number outside the server's managed range.
# Everything is created under /home/ingots/snaptest/cycle-<pid> and removed on success.
set -u
RT=${1:?runtime root}
KDIR=${2:--}
NUM=${3:-2}
PORT=$((6520 + NUM - 1))
SERIAL=0.0.0.0:$PORT
W=/home/ingots/snaptest/cycle-$$
SNAP=$W/snap
mkdir -p "$W/home"
cd "$W" || exit 1
export HOME=$W/home ANDROID_HOST_OUT=$RT ANDROID_PRODUCT_OUT=$RT
ADB=$RT/bin/adb

FLAGS="--base_instance_num=$NUM --cpus=6 --gpu_mode=guest_swiftshader --vhost_user_vsock=false \
--start_webrtc=true --snapshot_compatible --daemon --report_anonymous_usage_stats=n"
if [ "$KDIR" != "-" ]; then
  FLAGS="$FLAGS --kernel_path=$KDIR/Image --initramfs_path=$KDIR/initramfs.img"
fi

gsh() { timeout 30 "$ADB" -s "$SERIAL" shell "$1" </dev/null 2>&1 | tr -d '\r'; }
reconnect() { "$ADB" disconnect "$SERIAL" >/dev/null 2>&1; "$ADB" connect "$SERIAL" >/dev/null 2>&1; }
fail() { echo "FAIL: $*"; timeout 120 "$RT/bin/stop_cvd" >/dev/null 2>&1; echo "left in $W"; exit 1; }

echo "runtime=$RT kernel=$KDIR instance=$NUM crosvm=$(sha256sum "$RT/bin/aarch64-linux-musl/crosvm" | cut -c1-12)"
t0=$(date +%s)
timeout 600 "$RT/bin/launch_cvd" $FLAGS >launch.log 2>&1 || fail "boot (see $W/launch.log)"
echo "boot: $(( $(date +%s) - t0 ))s"
reconnect
"$ADB" -s "$SERIAL" root >/dev/null 2>&1; sleep 3; reconnect
echo "guest: $(gsh 'uname -r; getenforce; whoami')" | tr '\n' ' '; echo
[ -n "${SNAPSHOT_DELAY:-}" ] && { echo "waiting ${SNAPSHOT_DELAY}s before snapshot"; sleep "$SNAPSHOT_DELAY"; }
# Random data on /data, so the disk (not just the guest page cache) is checked after restore.
gsh 'dd if=/dev/urandom of=/data/local/tmp/rnd bs=1048576 count=256 2>/dev/null; sync' >/dev/null
RND=$(gsh 'sha256sum /data/local/tmp/rnd' | cut -d' ' -f1)
gsh 'echo disk-marker > /data/local/tmp/marker; nohup sleep 100000 >/dev/null 2>&1 </dev/null &' >/dev/null
sleep 1
PID=$(gsh 'pidof sleep')
[ -n "$PID" ] || fail "could not start marker process"
echo "marker process pid=$PID"

t0=$(date +%s.%N)
timeout 400 "$RT/bin/snapshot_util_cvd" --subcmd=snapshot_take --snapshot_path="$SNAP" --auto_suspend \
  >snap.log 2>&1 || fail "snapshot_take (see $W/snap.log)"
printf 'snapshot: %.1fs size=%s\n' "$(echo "$(date +%s.%N)-$t0" | bc)" "$(du -sh "$SNAP" | cut -f1)"

gsh "echo MUTATED > /data/local/tmp/marker; rm /data/local/tmp/rnd; kill $PID" >/dev/null
timeout 120 "$RT/bin/stop_cvd" >stop.log 2>&1 || echo "note: stop_cvd rc!=0"

# Same as cuttle_server's protect_snapshot_overlays: keep assemble_cvd from replacing the
# overlays when --kernel_path makes it rebuild the composite disk.
touch -d "+1 day" "$SNAP"/instances/cvd-*/*overlay.img
t0=$(date +%s.%N)
timeout 600 "$RT/bin/launch_cvd" $FLAGS --snapshot_path="$SNAP" >restore.log 2>&1 || fail "restore (see $W/restore.log)"
printf 'restore: %.1fs\n' "$(echo "$(date +%s.%N)-$t0" | bc)"
sleep 5
reconnect
GOT_PID=$(gsh 'pidof sleep')
GOT_MARKER=$(gsh 'cat /data/local/tmp/marker')
gsh 'echo 3 > /proc/sys/vm/drop_caches' >/dev/null
GOT_RND=$(gsh 'sha256sum /data/local/tmp/rnd' | cut -d' ' -f1)
echo "after restore: sleep pid=$GOT_PID (want $PID) marker=$GOT_MARKER (want disk-marker) uptime=$(gsh 'cat /proc/uptime')"
echo "random file after drop_caches: ${GOT_RND:0:16} (want ${RND:0:16})"
grep -h "Overlay is out of date" "$HOME"/cuttlefish/assembly/assemble_cvd.log && echo "WARNING: overlay was replaced"
timeout 120 "$RT/bin/stop_cvd" >/dev/null 2>&1
if [ "$GOT_PID" = "$PID" ] && [ "$GOT_MARKER" = "disk-marker" ] && [ -n "$RND" ] && [ "$GOT_RND" = "$RND" ]; then
  echo "PASS"
  cd / && rm -rf "$W"
else
  echo "FAIL: state mismatch (left in $W)"
  exit 1
fi

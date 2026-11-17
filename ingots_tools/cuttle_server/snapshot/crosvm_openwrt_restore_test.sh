#!/bin/bash
# Standalone crosvm snapshot/restore test of the OpenWrt guest (no Cuttlefish).
CROSVM=${CROSVM:?}
D=/home/ingots/snaptest/owrt/run-$(basename $(dirname $(dirname $CROSVM)))-$$
mkdir -p $D; cd $D
cp /home/ingots/snaptest/rt-r2/etc/openwrt/images/openwrt_rootfs_aarch64 rootfs.img
K=/home/ingots/snaptest/rt-r2/etc/openwrt/images/openwrt_kernel_aarch64
mkfifo in1 in2
ARGS="--disable-sandbox --no-usb --mem 256 --cpus 1 --block path=$D/rootfs.img --params root=/dev/vda --core-scheduling=false"
send() { printf "%s\n" "$2" >&$1; }
# first boot: OpenWrt reboots itself once (first-boot setup); let it finish
timeout 60 $CROSVM run $ARGS --serial hardware=legacy-virtio-console,num=1,type=file,path=$D/out0.log,console=true $K > crosvm0.log 2>&1; echo first_boot_exit=$?
# boot
$CROSVM run $ARGS --socket $D/ctl.sock --serial hardware=legacy-virtio-console,num=1,type=file,path=$D/out1.log,input=$D/in1,console=true $K > crosvm1.log 2>&1 &
P=$!; exec 3<>in1; sleep 25
send 3 ""; send 3 "echo PRE-\$(cut -d. -f1 /proc/uptime); echo state-before > /tmp/m; (while true; do echo TICK-\$(cut -d. -f1 /proc/uptime) > /dev/console; sleep 1; done) &"; sleep 3
echo "pre:  $(grep -a PRE- out1.log | grep -v echo | tail -1)"
$CROSVM suspend $D/ctl.sock --full >/dev/null 2>&1; echo suspend=$?
$CROSVM snapshot take $D/snap $D/ctl.sock >snaptake.log 2>&1; echo snapshot=$?
$CROSVM stop $D/ctl.sock >/dev/null 2>&1; wait $P 2>/dev/null; exec 3>&-
# restore into a fresh process
$CROSVM run $ARGS --socket $D/ctl2.sock --serial hardware=legacy-virtio-console,num=1,type=file,path=$D/out2.log,input=$D/in2,console=true --restore $D/snap $K > crosvm2.log 2>&1 &
P=$!; exec 4<>in2; sleep 5
$CROSVM resume $D/ctl2.sock --full >/dev/null 2>&1; echo resume=$?
sleep 8; echo "ticks after restore: $(grep -a -c TICK- out2.log) last=$(grep -a -o "TICK-[0-9]*" out2.log | tail -1) first=$(grep -a -o "TICK-[0-9]*" out2.log | head -1)"; echo "ticks before snapshot: last=$(grep -a -o "TICK-[0-9]*" out1.log | tail -1)"; send 4 ""; send 4 "echo POST-\$(cut -d. -f1 /proc/uptime)-\$(cat /tmp/m)"; sleep 3
echo "post: $(grep -a POST- out2.log | grep -v echo | tail -1)"
echo "alive: $(kill -0 $P 2>/dev/null && echo yes || echo no)"
grep -a -iE "panic|Oops|Internal error|stack overflow" out2.log | head -3
grep -iE "ERROR" crosvm2.log | grep -v msix | head -5
$CROSVM stop $D/ctl2.sock >/dev/null 2>&1; sleep 1; kill $P 2>/dev/null; exec 4>&-

# Using gdb with cuttlefish on aarch64

Cuttlefish seems to be designed to work with crosvm by default. However, crosvm's gdb server only supports a single cpu, making crosvm's gdb server unusable with exploits that require multiple cpus.

Cuttlefish also supports using qemu for emulation. Qemu supports a gdb server with multiple cpus, however, it is considered "legacy" by google and is not too well supported anymore. But we can still make it work.

## Getting started

First, make sure to build cuttlefish [here](https://source.android.com/docs/devices/cuttlefish/get-started)

Tell cuttlefish to run using qemu:
```sh
HOME=$PWD ./bin/launch_cvd -kernel_path /location/of/kernel/Image -initramfs_path /location/of/kernel/initramfs.img -vm_manager qemu_cli
```

> If this command boots android kernel properly, then hooray, skip to [here]
> Otherwise,

Cuttlefish spawns the qemu process by default using the following arguments:
```sh
/usr/bin/qemu-system-aarch64 \
-name guest=cvd-1,debug-threads=on \
-machine virt,gic-version=2,mte=on,usb=off,dump-guest-core=off \
-m size=2048M,maxmem=2050M \
-overcommit mem-lock=off \
-smp 2,cores=2,threads=1 \
-uuid 699acfc4-c8c4-11e7-882b-5065f31dc101 \
-no-user-config \
-nodefaults \
-no-shutdown \
-rtc base=utc \
-boot strict=on \
-display none \
-device virtio-gpu-gl-pci,id=gpu0 \
-chardev socket,id=charmonitor,path=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/internal/qemu_monitor.sock,server=on,wait=off \
-mon chardev=charmonitor,id=monitor,mode=control \
-chardev file,id=serial0,path=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/internal/kernel-log-pipe,append=on \
-serial chardev:serial0 \
-chardev file,id=hvc0,path=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/internal/kernel-log-pipe,append=on \
-device virtio-serial-pci-non-transitional,max_ports=1,id=virtio-serial0 \
-device virtconsole,bus=virtio-serial0.0,chardev=hvc0 \
-chardev null,id=hvc1 \
-device virtio-serial-pci-non-transitional,max_ports=1,id=virtio-serial1 \
-device virtconsole,bus=virtio-serial1.0,chardev=hvc1 \
-chardev file,id=hvc2,path=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/internal/logcat-pipe,append=on \
-device virtio-serial-pci-non-transitional,max_ports=1,id=virtio-serial2 \
-device virtconsole,bus=virtio-serial2.0,chardev=hvc2 \
-chardev pipe,id=hvc3,path=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/internal/keymaster_fifo_vm \
-device virtio-serial-pci-non-transitional,max_ports=1,id=virtio-serial3 \
-device virtconsole,bus=virtio-serial3.0,chardev=hvc3 \
-chardev pipe,id=hvc4,path=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/internal/gatekeeper_fifo_vm \
-device virtio-serial-pci-non-transitional,max_ports=1,id=virtio-serial4 \
-device virtconsole,bus=virtio-serial4.0,chardev=hvc4 \
-chardev pipe,id=hvc5,path=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/internal/bt_fifo_vm \
-device virtio-serial-pci-non-transitional,max_ports=1,id=virtio-serial5 \
-device virtconsole,bus=virtio-serial5.0,chardev=hvc5 \
-drive file=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/overlay.img,if=none,id=drive-virtio-disk0,aio=threads \
-device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk0,id=virtio-disk0,bootindex=1 \
-drive file=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/persistent_composite.img,if=none,id=drive-virtio-disk1,aio=threads,format=raw \
-device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk1,id=virtio-disk1 \
-drive file=/home/nhommes/cuttlefish_images/main-throttled/cuttlefish_runtime.1/sdcard.img,if=none,id=drive-virtio-disk2,aio=threads,format=raw \
-device virtio-blk-pci-non-transitional,scsi=off,drive=drive-virtio-disk2,id=virtio-disk2 \
-object rng-random,id=objrng0,filename=/dev/urandom \
-device virtio-rng-pci-non-transitional,rng=objrng0,id=rng0,max-bytes=1024,period=2000 \
-device virtio-mouse-pci,disable-legacy=on \
-device virtio-keyboard-pci,disable-legacy=on \
-device virtio-keyboard-pci,disable-legacy=on \
-device virtio-balloon-pci-non-transitional,id=balloon0 \
-netdev tap,id=hostnet0,ifname=cvd-wtap-01,script=no,downscript=no \
-device virtio-net-pci-non-transitional,netdev=hostnet0,id=net0 \
-netdev tap,id=hostnet1,ifname=cvd-mtap-01,script=no,downscript=no \
-device virtio-net-pci-non-transitional,netdev=hostnet1,id=net1 \
-device vhost-vsock-pci-non-transitional,guest-cid=3 \
-device qemu-xhci,id=xhci \
-device AC97,audiodev=audio_none \
-audiodev driver=none,id=audio_none \
-cpu host \
-msg timestamp=on \
-bios /home/nhommes/cuttlefish_images/main-throttled/bootloader.qemu
```

To get started with using cuttlefish and qemu I recommend to not skip any of the following steps and test whether cuttlefish has properly started after each step as the requirements of qemu seems to vary between systems.

We need to be able to inject arguments into qemu at runtime. The cleanest way to do this would be to patch the way cuttlefish spawns qemu. The temporary solution to test is:

First locate where `qemu-system-aarch64` binary is.
For me it is in `/usr/bin/qemu-system-aarch64`.

Now move it to any new path and make a new executable wrapper script that calls qemu:
```sh
mv /usr/bin/qemu-system-aarch64 /usr/bin/qemu-system-aarch64.real
touch /usr/bin/qemu-system-aarch64
chmod +x /usr/bin/qemu-system-aarch64
cat <<'EOF' > /usr/bin/qemu-system-aarch64
#!/bin/bash

real_qemu="/usr/bin/qemu-system-aarch64.real"

args=()
for arg in "$@"; do
  args+=("$new_arg")
done

args+=( -d guest_errors,unimp,cpu_reset -D /tmp/qemu.log )

exec "$real_qemu" "${args[@]}"
EOF
```

The wrapper script will inject / remove arguments it is called with, and pass those arguments onto the real qemu binary. For now we just inject a logging option to log in `/tmp/qemu.log`.

### 1. Audio Drivers issue
If you run into some issues with audio drivers, simply removing them and replacing them with a dummy audio backend worked for me. You may be able to skip this step as I wasn't able to reproduce it on different systems and I'm not exactly sure what the cause is.

`/usr/bin/qemu-system-aarch64`:

```sh
#!/bin/bash

real_qemu="/usr/bin/qemu-system-aarch64.real"

args=()
for arg in "$@"; do

  # Replace AC97 device with dummy audio backend
  if [[ "$new_arg" == AC97* ]]; then
    args+=("AC97,audiodev=audio_none")
    continue
  fi

  args+=("$new_arg")
done

args+=( -audiodev driver=none,id=audio_none )
args+=( -d guest_errors,unimp,cpu_reset -D /tmp/qemu.log )

exec "$real_qemu" "${args[@]}"
```

If cuttlefish boots skip to **Running with gdb** section
### 2. Adding a virtio-vsock PCI device

If cuttlefish hangs at a `transport message failed: ` error, likely qemu is unable to communicate with cuttlefish.

Add these lines to the qemu wrapper to inject one.

```sh
#!/bin/bash

real_qemu="/usr/bin/qemu-system-aarch64.real"

args=()
for arg in "$@"; do

  if [[ "$new_arg" == AC97* ]]; then
    args+=("AC97,audiodev=audio_none")
    continue
  fi

  args+=("$new_arg")
done

# added virtio-vsock PCI device
args+=( -device vhost-vsock-pci,guest-cid=69 )
args+=( -audiodev driver=none,id=audio_none )
args+=( -d guest_errors,unimp,cpu_reset -D /tmp/qemu.log )

exec "$real_qemu" "${args[@]}"
```

If cuttlefish boots skip to **Running with gdb** section

### 3. Disable memory tagging extension
For me, when adding the vsock device, some errors regarding memory tagging came up and since we don't really need that I just disabled it.

```sh
#!/bin/bash

real_qemu="/usr/bin/qemu-system-aarch64.real"

args=()
for arg in "$@"; do
  #disable memory tagging
  new_arg="${arg//mte=on/mte=off}"

  if [[ "$new_arg" == AC97* ]]; then
    args+=("AC97,audiodev=audio_none")
    continue
  fi

  args+=("$new_arg")
done

args+=( -device vhost-vsock-pci,guest-cid=69 )
args+=( -audiodev driver=none,id=audio_none )
args+=( -d guest_errors,unimp,cpu_reset -D /tmp/qemu.log )

exec "$real_qemu" "${args[@]}"
```

## Running with gdb
After applying these to the wrapper script, gdb should be ready to use.

You can run cuttlefish like:
```sh
HOME=$PWD ./bin/launch_cvd -kernel_path /home/jack/ingots/kernel/Image -initramfs_path /home/jack/ingots/kernel/initramfs.img -vm_manager qemu_cli --gdb_port 1234 -extra_kernel_cmdline "nokaslr"
```

We specify a gdb server at port 1234, and disable kaslr.

In gdb:

```gdb
(gdb) target remote :1234
```

Should break at address 0x0, and you can continue from there.

Also you can see if symbols can be added to the kernel image for better debugging using [https://github.com/marin-m/vmlinux-to-elf](https://github.com/marin-m/vmlinux-to-elf "https://github.com/marin-m/vmlinux-to-elf")

### Fixing GDB si or continue

It may be the case the hitting a breakpoint and hitting running the step instruction command results in execution immediately transferring to `__bp_harden_el1_vectors` or similar, instead of the next instruction.
Hitting continue will also cause the same breakpoint to be hit over and over, even if execution should continue later on.

I think this is caused due to some interrupt firing, which transfers execution to `__bp_harden_el1_vectors`. When the interrupt finishes, the syscall is then restarted?

The fix for this issue is to disable interrupts whenever a breakpoint is hit. This can be done easily with a gdb stop hook, shown below:

```
define hook-stop
    # Mask IRQ + FIQ again automatically
    set $cpsr = $cpsr | 0xc0
end
```

## Unknown Error

When trying this on my raspberry pi, I encountered some issues with qemu:
```
PSTATE=400003c5 -Z-- EL1h
pflash_write: Unimplemented flash cmd sequence (offset 0000000000001028, wcycle 0x0 cmd 0x0 value 0x2)
CPU Reset (CPU 0)
 PC=00000000bfe6b1e8 X00=fffffffffffffffa X01=0000000000000000
X02=0000000000000000 X03=0000000000000000 X04=0000000000000000
X05=0000000000000000 X06=0000000000000000 X07=0000000000000000
X08=00000000bed69970 X09=00000000bfed33c8 X10=00000000bed699a0
X11=00000000bed699f0 X12=00000000bfed1000 X13=00000000000000d1
X14=0000000000016201 X15=0000000000000051 X16=0000000000000009
X17=0000000000000001 X18=00000000bee69dd0 X19=0000000000000001
X20=00000000ffffffda X21=00000000bee719a0 X22=0000000000000001
X23=0000000000000000 X24=00000000bfed2de8 X25=0000000000000000
X26=0000000000000001 X27=0000000000000000 X28=0000000000000004
X29=00000000bed69990 X30=00000000bfe6b270  SP=00000000bed69960
PSTATE=600003c5 -ZC- EL1h
CPU Reset (CPU 1)
 PC=0000000000000000 X00=0000000000000000 X01=0000000000000000
X02=0000000000000000 X03=0000000000000000 X04=0000000000000000
X05=0000000000000000 X06=0000000000000000 X07=0000000000000000
X08=0000000000000000 X09=0000000000000000 X10=0000000000000000
X11=0000000000000000 X12=0000000000000000 X13=0000000000000000
X14=0000000000000000 X15=0000000000000000 X16=0000000000000000
X17=0000000000000000 X18=0000000000000000 X19=0000000000000000
X20=0000000000000000 X21=0000000000000000 X22=0000000000000000
X23=0000000000000000 X24=0000000000000000 X25=0000000000000000
X26=0000000000000000 X27=0000000000000000 X28=0000000000000000
X29=0000000000000000 X30=0000000000000000  SP=0000000000000000
PSTATE=400003c5 -Z-- EL1h
```

The easiest fix (untested) would probably be to patch the command sequence into qemu and rebuild. Some online research seems to indicate this is a raspbian problem though.

## Tested hardware
Regardless of the issue mentioned above, we can run Cuttlefish with QEMU succesfully using an `a1.metal` machine on `Amazon EC2`.

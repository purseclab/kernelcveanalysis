There are several potential options for debugging arm64 android kernel:

# Qemu
We could attempt to run android in qemu. There are perhaps performance concerns about running emulated arm64 kernel on x86 qemu, but running qemu on the arm server with KVM should be fast, and qemu GDB server still works even with KVM mode enabled (tested on x86_64).

# Cuttlefish
Cuttlefish by default uses a vm called crosvm (https://github.com/google/crosvm), and crosvm manages VMs and will use hypervisor behind the scenes like KVM. However looking at cuttlefish source code, it seems there are support for other VMs, including qemu (also supports gem5). You can pass the `-vm_manager=qemu_cli` argument to cuttlefish to use qemu instead.

### CrosVM and Cuttlefish Debugging
CrosVM actually seems to have a gdb server option, which it will use if you specify the `-gdb_port=<port_numger>`. However a limitation of CrosVM's gdb mode is that it only works when the VM has only 1 cpu, so in the case of exploits like badspin, or many race condition exploits which require multiple CPUs, they are not possible to run with only 1 cpu.

### Qemu and Cuttlefish Debugging
If you specify the `-gdb_port=<port_number>` argument, cuttlefish should start qemu with gdb server listening on the given port (based on source code). However I was not able to get qemu to run with cuttlefish due to some issues with audio drivers on cuttlefish.

NOTE: debug on aarch64 may have issue where gdb jumps to `__bp_harden_el1_vectors` after hitting breakpoint and running si command. The solution is to disable interrupts (when you return form syscall kernel will reenable interrrupts).
An easy way to do this is to use a stop-hook to disable them every time a breakpoint is hit:
```
define hook-stop
    # Mask IRQ + FIQ again automatically
    set $cpsr = $cpsr | 0xc0
end
```

# kgdb
Cuttlefish actually supports making a kgdb console, by setting the `-kgdb=true` cli argument. Cuttlefish will then make the necessary serial console. The `-gdb_port=<port_number>` field controls the port number which cuttlefish will host gdb server on and communicate with kgdb. One issue I found is specifying `-gdb_port=<port_number>` for kgdb also turns on CrosVM's gdb mode, which will cause an assertion error if you need more than 1 cpu for the exploit. We will probably have to patch cuttlefish if we want to use this feature then, which looks fairly simple to do.

Kernel has to be configured with kgdb support, using the `CONFIG_KGDB=y` option. `CONFIG_KGDB_SERIAL_CONSOLE=y` also needed to communicate with kgdb from outside kernel. https://www.kernel.org/doc/html/latest/process/debugging/kgdb.html has some other options for debugging.

Config files used:
```
Using /mnt/data/jroscoe/common-android13-5.10-2025-03/out/bazel/output_user_root/ef1877d2bcd4bec391143ebc488890e1/sandbox/linux-sandbox/8/execroot/__main__/common/arch/arm64/configs/gki_defconfig as base  
Merging /mnt/data/jroscoe/common-android13-5.10-2025-03/out/bazel/output_user_root/ef1877d2bcd4bec391143ebc488890e1/sandbox/linux-sandbox/8/execroot/__main__/common-modules/virtual-device/virtual_device.fragment  
Merging /mnt/data/jroscoe/common-android13-5.10-2025-03/out/bazel/output_user_root/ef1877d2bcd4bec391143ebc488890e1/sandbox/linux-sandbox/8/execroot/__main__/common-modules/virtual-device/aarch64.fragment

#  
# merged configuration written to /mnt/data/jroscoe/common-android13-5.10-2025-03/out/bazel/output_user_root/ef1877d2bcd4bec391143ebc488890e1/sandbox/linux-sandbox/6/execroot/__main__/common/arch/arm64/configs/vd_aarch_64_gki_defconfig  
(needs make)  
#
```

# Config Android Kernel
https://android.googlesource.com/kernel/build/+/refs/heads/main/kleaf/docs/kernel_config.md

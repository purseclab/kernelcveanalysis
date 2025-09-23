Random list of tools that are useful

- `vmlinux-to-elf`: convert linux boot image to elf with symbols by extracting symbols from kallsyms
- `android-tools` nix package: `unpack_bootimg` works to extract linux ramdisk and kernel image from android `boot.img` file
- docker build containers for linux: https://github.com/a13xp0p0v/kernel-build-containers
- libslub: GDB plugin for debugging kmalloc clabs: https://github.com/nccgroup/libslub
- Working with qcow2 disks:
	- 7zip can extract them

### CLI Tools in Android ADB Shell
- am: activity manager
	- `am start -n com.example.testapp/.MainActivity`: start an app from command line
- pm: package manager
	- `pm list packages`: list installed apps
- dumpsys: given a service name, dump information about it
	- example: list permissions of app: `dumpsys package com.example.app`
		- or get all app's permissions: `dumpsys package --permission`
- `service list`: list binder services

##### Important folders / files in Android ADB Shell

- selinux stuff: `/system/etc/selinux`
	- `/system/etc/selinux/plat_seapp_contexts`: contexts that can be loaded by zygote as selinux policy
	- source code for selinux policies: https://cs.android.com/android/platform/superproject/main/+/main:system/sepolicy/private/
- seccomp policies: `/system/etc/seccomp_policy/`
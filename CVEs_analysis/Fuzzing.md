# Syzkaller
Syzkaller fuzzes linux kernel (and other kernels)
Syzbot uses syzkaller to continuously fuzz and submit reports (https://android.googlesource.com/platform/external/syzkaller/+/HEAD/docs/syzbot.md)
Syzbot is part of syzkaller project

## Syzkaller reproduction
https://github.com/google/syzkaller/blob/master/docs/reproducing_crashes.md
Syzkaller has a dsl which describes the crash

### Issues With Running C Repro on Android

- Highest virtual address that worked to mmap on cuttlefish emulator is `0x7ffffff000`, anything `0x8000000000` (40th bit set) and above does not work

## Exploit Adaptation from Syzkaller Bugs
Automatically download promising bug types from syzbot dashboard
- Filter for promising bugs
	- C reproduction available
	- Filter out deadlocks, assertion failures, warnings, and null dereference, which are probably not exploitable
	- Look for KASAN UAF bugs
		- Try to identify UAF object, exploitation steps are similar for similar objects, so pre-written exploit could be appended
For now, manual download, do this later

Android syzkaller bugs to look into:
- UAF in crypto stuff for sockets: https://syzkaller.appspot.com/bug?extid=4851c19615d35f0e4d68
	- Problem: only introduced for a very short time
- `/dev/usbmon` can be mmap as writable, which causes many issues: https://syzkaller.appspot.com/bug?extid=23f57c5ae902429285d7
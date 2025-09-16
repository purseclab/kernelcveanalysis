# APEX
Some system servers load libraries from apex file (ie. netd loading dns resolver library).
APEX is like APK for system binaries. Has signature, manifest, and ext4 image which is mounted as loopback.

# System Servers

### netd
Handles low level networking and such, loads dns resolver library as well.
Runs with decently high privileges, including root on cuttlefish, though this is not typical.

### system_server
Runs almost all java servers in 1 process
Some services in `system_server`:
- activity manager (`am`): coordinates sending intents and luanching activities and such
- package manager (`pm`): installs apks and such, also does permission checks
	- permission manager has its own binder interface I think

### servicemanager
A native process started early in boot. This is the binder context manager.
Holds mappings between strings to binder handles.
So when app does `ServiceManager.getService(String service_name)` it goes through service manager.

### zygote
Spawns new apps and higher level system services. Has a unix socket in `/dev/socket/zygote` which activity manager talks too.

# IPC
Most app components are started with an intent. You can bind to an app service and get an IBinder which makes ipc method calls with binder.
Binder instances can also be obtained through `servicemanager`.

### Intents
https://developer.android.com/guide/components/intents-filters

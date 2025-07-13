<!--add more detail-->

# Compiling and flashing custom kernels

## prerequisites
  1) [repo](https://gerrit.googlesource.com/git-repo/+/refs/heads/main/README.md)

In Ubuntu 24.04 repo can be installed with `sudo apt-get install repo` but not in 20.04. 

## Download source 
Initialize repo and sync with the version that you want using instructions from [building pixel kernels](https://source.android.com/docs/setup/build/building-pixel-kernels)

For example:
```bash
repo init -u https://android.googlesource.com/kernel/manifest -b android-gs-raviole-5.10-android12-d1
repo sync -c --no-tags
```

### extract vendor ramdisk
Download a [facotry image](https://developers.google.com/android/images) with compatible vendor ramdisk. [SD1A.210817.015.A4](https://dl.google.com/dl/android/aosp/oriole-sd1a.210817.015.a4-factory-074b7f51.zip) for pixel 6 on Android 12.

after unzipping dowloaded factory image, run 
```bash
PATH_TO_CUSTOM_KERNEL_ROOT/tools/mkbootimg/unpack_bootimg.py --boot_img vendor_boot.img --out vendor_boot_out
```
Then copy created `vendor_boot_out/vendor-ramdisk-by-name/ramdisk_` file to the correct ramdisk path in your custom kernel (prebuilts/boot-artifacts/ramdisks/vendor_ramdisk-oriole.img for pixel 6).

## Compiling source
Set the build options:

```sh
export BUILD_AOSP_KERNEL=1
export BUILD_KERNEL=1
```

### Edit configs to include KGDB (not currently working)

In `build.config`, add the following:

```sh
POST_DEFCONFIG_CMDS="update_debug_config"

function update_debug_config() {
    ${KERNEL_DIR}/scripts/config --file ${OUT_DIR}/.config \
        -e CONFIG_KGDB \
        -e CONFIG_KGDB_SERIAL_CONSOLE \
        -e CONFIG_DEBUG_INFO \
        -e CONFIG_FRAME_POINTER \
        -e CONFIG_MAGIC_SYSRQ \
        -e CONFIG_CONSOLE_POLL

    (cd ${OUT_DIR} && \
        make O=${OUT_DIR} $archsubarch CC=${CC} CROSS_COMPILE=${CROSS_COMPILE} olddefconfig)
}
``` 

In `aosp/kernel/configs/android-base.config` and `aosp/kernel/configs/android-recommended.config` add
```sh
CONFIG_KGDB=y
```

### Building kernel
Build kernel using the legacy build system: 
```bash 
./build/build.sh
```

(You should also be able to build using `./build_<devicename>.sh` but that randomly fails sometimes)

The output of building should be:
```vendor boot image created at /home/wboulton/research/kernel_build/out/mixed/dist/vendor_boot.img```

There is more information about building kernels for virtual devices [here](https://source.android.com/docs/setup/build/building-kernels)


## flashing
After building, use [fastboot](https://source.android.com/docs/setup/test/running) to flash the `boot.img`, `dtbo.img`, `vendor_boot.img`, and `vendor_dlkm.img` images:
```bash
fastboot flash boot        out/slider/dist/boot.img
fastboot flash dtbo        out/slider/dist/dtbo.img
fastboot flash vendor_boot out/slider/dist/vendor_boot.img
fastboot reboot fastboot
fastboot flash vendor_dlkm out/slider/dist/vendor_dlkm.img
```

These can be found in `out/mixed/dist/`
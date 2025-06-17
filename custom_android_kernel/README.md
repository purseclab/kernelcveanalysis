<!--add more detail-->

# Compiling and flashing custom kernels (KGDB)

## Download source 
Initialize repo and sync with the version that you want using instructions from [building pixel kernels](https://source.android.com/docs/setup/build/building-pixel-kernels)

I used the following:
```bash
repo init -u https://android.googlesource.com/kernel/manifest -b android-gs-raviole-5.10-android12-d1
repo sync -c --no-tags
```

### extract vendor ramdisk
Download a [facotry image](https://developers.google.com/android/images) with compatible vendor ramdisk. [SD1A.210817.015.A4](https://dl.google.com/dl/android/aosp/oriole-sd1a.210817.015.a4-factory-074b7f51.zip) for pixel 6 on Android 12.

In downloaded repo root, run 
```bash
PATH_TO_CUSTOM_KERNEL_ROOT/tools/mkbootimg/unpack_bootimg.py --boot_img vendor_boot.img --out vendor_boot_out
```
Then copy created `ramdisk_` file to the correct ramdisk path in your custom kernel (prebuilts/boot-artifacts/ramdisks/vendor_ramdisk-oriole.img for pixel 6).

## Compiling source
Set the build options:

```sh
export BUILD_AOSP_KERNEL=1
export BUILD_KERNEL=1
```

### Edit configs to include KGDB

In `build.config`, add the following code:

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
build_<device name>.sh DEVICE_KERNEL_BUILD_CONFIG=build.config`
```

The output of building should be:
```vendor boot image created at /home/wboulton/research/kernel_build/out/mixed/dist/vendor_boot.img```
<!--finish flash instructions-->

You can then flash it with instructions from the above [link](https://source.android.com/docs/setup/build/building-pixel-kernels). 

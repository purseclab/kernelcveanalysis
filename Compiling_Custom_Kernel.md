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

### Edit configs to include KGDB
To build source with KGDB, you must set `export KMI_SYMBOL_LIST_STRICT_MODE=0` to prevent the build system from failing when trying to use different configs

In your build/build.config file look for the name of the build config used to generate your android kernel in the first line. It should look like this:
```sh
. ${ROOT_DIR}/${KERNEL_DIR}/build.config.gs101
```
In your project root, use `find` to locate this build config file (likely in `private/gs-google/{FILENAME}`)

In this file, edit the `PRE_DEFCONFIG_CMDS` by adding a new fragment with your kgdb config options. Your `PRE_DEFCONFIG_CMDS` may look like the following:
```sh
PRE_DEFCONFIG_CMDS="KCONFIG_CONFIG=${ROOT_DIR}/${KERNEL_DIR}/arch/arm64/configs/${DEFCONFIG} ${ROOT_DIR}/${KERNEL_DIR}/scripts/kconfig/merge_config.sh -m -r ${ROOT_DIR}/${KERNEL_DIR}/arch/arm64/configs/gki_defconfig ${ROOT_DIR}/${KERNEL_DIR}/arch/arm64/configs/slider_gki.fragment ${ROOT_DIR}/${KERNEL_DIR}/arch/arm64/configs/kgdb.fragment"
```

To include kgdb with access to a serial console (as done in [this article](https://xairy.io/articles/pixel-kgdb)) the following configs are necessary:
```sh
CONFIG_KGDB=y
CONFIG_VT=y
CONFIG_HW_CONSOLE=y
CONFIG_KGDB_SERIAL_CONSOLE=y
```

### Building kernel
Build kernel using the legacy build system: 
```bash 
./build/build.sh
```

(You should also be able to build using `./build_<devicename>.sh` but that randomly fails sometimes)

The output of building should be:
```vendor boot image created at /home/<user>/research/kernel_build/out/mixed/dist/vendor_boot.img```

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

<!-- 
turn off KMI_SYMBOL_LIST_STRICT_MODE
patch build.config.gs101 to add another defconfig fragment with kgdb configs
-->
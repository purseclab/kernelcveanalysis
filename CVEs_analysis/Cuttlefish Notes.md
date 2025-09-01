How to do various things on cuttlefish:

###### Launch chromium to go to website
```sh
adb shell am start -a android.intent.action.VIEW -d 'http://stackoverflow.com/?uid=isme\&debug=true'
```

# Launching Kernel Versions

### First Ingots Eval, android 5.10.101

In folder `~/cuttlefish_images/aosp_android13_cgi/cf`, run:
```sh
HOME=$PWD ./bin/launch_cvd -kernel_path=/home/jack/ingots/kernel/Image -initramfs_path=/home/jack/ingots/kernel/initramfs.img
```
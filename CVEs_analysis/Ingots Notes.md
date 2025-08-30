Answers due 5pm ET Thursday
Write POC exploit chain (could be one exploit?)
- Get kernel access
- Try to generate multiple chains

# Running Cuttlefish
5.10.234 kernel:
```sh
HOME=$PWD ./bin/launch_cvd -kernel_path=/home/jack/ingots/arm64/Image -initramfs_path=/home/jack/ingots/arm64/initramfs.img -cpus 8
```

5.10.101:
```sh
HOME=$PWD ./bin/launch_cvd -kernel_path=/home/jack/ingots/kernel/Image -initramfs_path=/home/jack/ingots/kernel/initramfs.img -cpus 8
```

Use kernel commit `fc74821cbc612c5becff43e0c2e64aa905ac826b` with manifest `common-android12-5.10-2025-03` for binary diffing
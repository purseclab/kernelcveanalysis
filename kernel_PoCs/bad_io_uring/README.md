# Bad IO_uring

These POCs are based on: https://github.com/Markakd/bad_io_uring

Bad IO uring details: https://www.blackhat.com/us-23/briefings/schedule/index.html#bad-io_uring-a-new-era-of-rooting-for-android-32243

## Build the exploit

For x86:
```bash
./compile_x86.sh
```

The x86 exploit is written for a specific 5.10.66 kernel compiled with kernelctf config (build_5.10.66_lts_x86_64).


For android on cuttlefish:
Make sure the [Android NDK](https://developer.android.com/ndk) is installed
Then:
```bash
./compile.sh
```

The android exploit is written for the ingots 5.10.66 kernel running on cuttlefish (ingots_5.10.66).

## kexploit Adaptation

`exp_cuttlefish_annotated.c` is an annotated version of the android exploit for use with kexploit automatic exploit adaptation.

# Syzbot Repro Analyzer

### Docker

You can run kexploit in a docker container. The Dockerfile is provided in the repository. We also provide a script to run everything once the docker container is built.
To build the docker image, run:
```sh
docker build -t syzbot-repro-env .
```
To run the docker container, you can use the provided script:
```sh
./set-env
```
This will mount the current `syzbot_repro_analysis` directory to `/workspace/syzbot-repro` in the container, match the network to the host network, and then also run it in user mode so all of the data collected can be accessed from the host machine.

### Setup for Running syzkaller POCs on Cuttlefish

Start the cuttlefish emulator on cuttlefish server, and run adb once to start adb daemon:
```sh
cd /home/jack/cuttlefish_images/aosp_android13_cgi/cf
HOME=$PWD ./bin/launch_cvd -kernel_path=/home/jack/ingots/kernel/Image -initramfs_path=/home/jack/ingots/kernel/initramfs.img
./bin/adb shell
```
The above command starts ingots kernel 5.10.101, but there are many different kernel versions on cuttlefish server.

Setup ssh port forwarding for adb on local machine running kexploit:
```sh
ssh -L localhost:5037:localhost:5037 cuttlefish-user@cuttlefish-host
```

`uv run kexploit test <bug_id>` can now be used to test syzkaller bugs.

## Running

Run `uv run kexploit` to run kexploit. There are various commands and subcommands that can be run (see `uv run kexploit --help` or `src/kexploit/main.py` for details).

### Syzkaller POC Reproduction
- `uv run kexploit syzkall pull`: pull exploits from syzkaller website and save locally
  - database with syzkall exploits metadata already created and pushed in github so this shouldn't be needed
```sh
 Usage: kexploit syzkall pull [OPTIONS]                                         
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --syzkall-kernel        TEXT  Kernel name to pull bugs for                   │
│                               [default: android-5-10]                        │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```
- `uv run kexploit syzkall query`: query available POCs pulled from syzkaller website
  - kind of incomplete, I just wrote random code here and changed code itself when looking for different bugs
```sh
 Usage: kexploit syzkall query [OPTIONS]                                        
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --syzkall-kernel        TEXT  Kernel name to pull bugs for                   │
│                               [default: android-5-10]                        │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```
- `uv run kexploit syzkall test <bug_id>`: run the given bug on cuttlefish and reprot if crash occurred
  - see [here](#setup-for-running-syzkaller-pocs-on-cuttlefish) for neccessary setup for `kexploit test`
```sh
 Usage: kexploit syzkall test [OPTIONS] BUG_ID                                  
                                                                                
╭─ Arguments ──────────────────────────────────────────────────────────────────╮
│ *    bug_id      TEXT  Bug ID to test [default: None] [required]             │
╰──────────────────────────────────────────────────────────────────────────────╯
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --local             --no-local          Use local cuttlefish instance        │
│                                         [default: local]                     │
│ --root              --no-root           Run repro as root user in VM         │
│                                         [default: root]                      │
│ --arch                            TEXT  Architecture of kernel to test bugs  │
│                                         on                                   │
│                                         [default: x86_64]                    │
│ --syzkall-kernel                  TEXT  Kernel name to pull bugs for         │
│                                         [default: android-5-10]              │
│ --qemu              --no-qemu           Use QEMU VM instead of cuttlefish    │
│                                         [default: no-qemu]                   │
│ --source-image                    PATH  Path to source image [default: None] │
│ --source-disk                     PATH  Path to source disk [default: None]  │
│ --help                                  Show this message and exit.          │
╰──────────────────────────────────────────────────────────────────────────────╯
```
- `uv run kexploit syzkall testall`: run all available syzkaller POCs on cuttlefish and report if crash occurred
  - this will take a long time, so be careful with this command and make sure the connection isn't disconnected otherwise you may need to restart the port forwarding and adb 
```sh
  Usage: kexploit syzkall testall [OPTIONS]                                      
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --local             --no-local           Use local cuttlefish instance       │
│                                          [default: no-local]                 │
│ --arch                             TEXT  Architecture of kernel to test bugs │
│                                          on                                  │
│                                          [default: x86_64]                   │
│ --syzkall-kernel                   TEXT  Kernel name to pull bugs for        │
│                                          [default: android-5-10]             │
│ --qemu              --no-qemu            Use QEMU VM instead of cuttlefish   │
│                                          [default: no-qemu]                  │
│ --source-image                     PATH  Path to source image                │
│                                          [default: None]                     │
│ --source-disk                      PATH  Path to source disk [default: None] │
│ --source            --no-source          Test bugs from syzbot source image  │
│                                          [default: no-source]                │
│ --root              --no-root            Run repro as root user in VM        │
│                                          [default: no-root]                  │
│ --outdir-name                      TEXT  Output directory name for crash     │
│                                          artifacts                           │
│                                          [default: syzkall_crashes]          │
│ --help                                   Show this message and exit.         │
╰──────────────────────────────────────────────────────────────────────────────╯
```
- `uv run kexploit syzkall collectstats`: This will collect statistics on all of the syzbot crashes to provide a starting point for understanding all of the crashes for a given kernel version.
```sh
 Usage: kexploit syzkall collectstats [OPTIONS]                                 
                                                                                
╭─ Options ────────────────────────────────────────────────────────────────────╮
│ --syzkall-kernel        TEXT  Kernel name to pull bugs for                   │
│                               [default: android-5-10]                        │
│ --outfile               TEXT  Output file to write stats to                  │
│                               [default: syzkall_stats]                       │
│ --help                        Show this message and exit.                    │
╰──────────────────────────────────────────────────────────────────────────────╯
```


There are also extensions for all of the commands above to allow for you to specify the kernel version you want to pull from and use for testing. The default version is `android-5.10`, but you can specify any kernel version that is available in the syzbot database.
For example, if you want to run against the current upstream kernel, you can use:
```sh
uv run kexploit syzkall pull --syzkall-kernel upstream
uv run kexploit syzkall testall --syzkall-kernel upstream
```

#### Syzkaller Example
On the host machine:
```sh
ssh -L localhost:5037:localhost:5037 cuttlefish-user@cuttlefish-host
cd ~/ingots2/U-2.1.TA1
./run.sh
```

In a seperate terminal on the host machine:
```sh
docker build -t kexploit-env .
./set-env
cd /workspace/kexploit
uv run kexploit syzkall pull
uv run kexploit syzkall testall
```
Note: The docker container can only be run on x86 machines as of right now


# dirtypipe

Exploit POC for dirtypipe vulnerability.

Written for android and injects code in init process.

Currently only works with selinux disabled.

Tested with ingots_5.10.66 kernel, and the libcpp and init process from the same android image.

## Compiling

To compile, run
```sh
./compile.sh '<exploit_data_dir>' '<dirtypipe_binary>'
```

Where `<exploit_data_dir>` is a path to a folder writable by the unprivileged user running the exploit,
and `<dirtypipe_binary>` is the path to the exploit binary itself.

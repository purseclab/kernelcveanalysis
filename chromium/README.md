# Chromium Exploits
  1) [CVE-2020-15972](./CVE-2020-15972/)
  2) [CVE-2020-16040](./CVE-2020-16040/)
  3) [CVE-2020-16045](./CVE-2020-16045/)
  4) [CVE-2020-16010](./CVE-2020-16010/)

Exploits 1 and 2 are exploits on the chrome renderer, both currently effective on a Google Pixel six using kernel version 5.10.43-android12-9-00007-g9771767708df-ab8009062 and chrome version 86.0.4240.30. The Chrome beta app was compiled from source using the following build flags from the [CVE-2020-16045 poc](https://github.com/github/securitylab/tree/main/SecurityExploits/Chrome/SandboxEscape/GHSL-2020-165)
```
target_os = "android"
target_cpu = "arm64"
is_java_debug = false
is_debug = false
symbol_level = 1
blink_symbol_level = 1
```

For exploit 1 and 2, no more modificaitons were made to chrome. 

To test exploit 3, there were slight modifications made to chrome source to allow for testing without being chained with either of the first two exploits. You can see that patch [here](./CVE-2020-16045/sbx.patch).

Exploit 4 is another sandbox escape for chrome. According to [project zero](https://googleprojectzero.blogspot.com/2021/03/in-wild-series-october-2020-0-day.html) it was used with CVE-2020-15999 to get userland RCE on android devices. An original poc was presented [here](https://project-zero.issues.chromium.org/issues/42451222). This exploit seems to cause a crash in chromium as is, but there is no available poc which allows controlled RCE. The poc would need to be developed to be used in an exploit chain. 

## Plan
When exploit 3 is chained with exploits 1 and 2, these exploits can escape the Chrome 86.0.4240.30 Beta sandbox on android and achieve RCE an android phone. If these were then chained with a third exploit to escalate privileges in the android kernel, then they can create a 1-click exploit on a Google Pixel 6. These exploits (specifically 1 and 3) were already used in [this writeup](https://github.blog/security/application-security/real-world-exploit-chains-explained/) along with CVE-2020-11239 to create a 1 click exploit on Samsung Galaxy A71. These are adjusted exploits along with alternative options for a Google Pixel 6.

## Building Chrome
Building old versions of Chrome is not trivial as a lot of files for older version of Chrome are no longer supported by Google. For more information on building Chrome 86.0.4240.30 Beta, see [Building_Chrome_Legacy.md](Building_Chrome_Legacy.md).

See [here](./Building_Chrome_Legacy.md) for information on how to build chrome version 86.0.4240.30 vulnerable to all four of the provided exploits. It has been patched in the manner described [here](./CVE-2020-16045/README.md) to be vulnerable to [exploit 3](./CVE-2020-16045/) without needing to be chained with another poc. 
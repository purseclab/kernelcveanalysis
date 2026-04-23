# kdebug

`kdebug` is a daemon-backed CLI for Android app debugging over ADB.

It keeps Frida sessions, loaded scripts, and LLDB attach sessions alive in a
local per-device daemon so you can:

- list visible apps
- attach to a running package
- spawn a package suspended
- resume and detach sessions
- load and unload persistent scripts
- run one-shot scripts
- call RPC exports
- read buffered Frida messages
- attach `lldb-server` to an existing process by package or PID
- print the exact host `lldb` command needed to connect
- inspect and stop active LLDB sessions

Basic usage:

```bash
uv run kdebug --device 127.0.0.1:6532 frida apps
uv run kdebug --device 127.0.0.1:6532 frida attach com.example.app
uv run kdebug --device 127.0.0.1:6532 frida load-script <session-id> --name demo --file hook.js
uv run kdebug --device 127.0.0.1:6532 frida rpc <script-id> ping a b
uv run kdebug --device 127.0.0.1:6532 lldb attach-package com.example.app
uv run kdebug --device 127.0.0.1:6532 lldb connect <session-id> --binary ./libtarget.so
```

`kdebug` auto-starts its daemon for Frida and LLDB commands. Use
`kdebug daemon status`, `start`, and `stop` only when you need to inspect or
manage that state directly.

Place a host `frida-server` binary at `kdebug/assets/frida-server` or pass an
override with `--frida-server-path`.

Place host `lldb-server` binaries under `kdebug/assets/lldb-server/<abi>/lldb-server`
or pass an alternate root with `--lldb-server-root`. Supported ABI directories
for v1 are `arm64-v8a`, `armeabi-v7a`, `x86`, and `x86_64`.

LLDB support in v1 is attach-only. `kdebug` sets up `lldb-server` on the device
and prints the host `lldb` command; it does not launch host LLDB itself.

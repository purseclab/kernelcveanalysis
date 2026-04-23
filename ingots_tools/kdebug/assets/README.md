Place a host `frida-server` binary at `kdebug/assets/frida-server`.

`kdebug` uploads that file to the selected device and launches it when the local
daemon starts.

For LLDB, place host `lldb-server` binaries under:

- `kdebug/assets/lldb-server/arm64-v8a/lldb-server`
- `kdebug/assets/lldb-server/armeabi-v7a/lldb-server`
- `kdebug/assets/lldb-server/x86/lldb-server`
- `kdebug/assets/lldb-server/x86_64/lldb-server`

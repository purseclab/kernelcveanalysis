Place bundled `lldb-server` binaries in ABI-specific subdirectories:

- `arm64-v8a/lldb-server`
- `armeabi-v7a/lldb-server`
- `x86/lldb-server`
- `x86_64/lldb-server`

`kdebug lldb` selects the binary by the device ABI reported over ADB.

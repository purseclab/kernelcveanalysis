# android_app_mcp

MCP server for debugging Android apps inside an emulator over ADB.

Run it over stdio with:

```bash
uv run android_app_mcp serve --adb-host 0.0.0.0 --adb-port 6532
```

Available tools:

- `run_shell`: run a shell command inside the emulator, optionally as root.
- `read_file`: read a UTF-8 text file from the emulator.
- `write_file`: write a UTF-8 text file into the emulator, optionally creating parent directories.
- `install_app`: install a host-local APK into the emulator via `libadb`.

# android_app_mcp

MCP server for debugging Android apps inside an emulator over ADB.

On startup, the server uploads `android_app_mcp/assets/frida-server`, launches it on
the emulator, and connects the host Frida client through an ADB port forward.

Run it over stdio with:

```bash
uv run android_app_mcp serve --adb-host 0.0.0.0 --adb-port 6532
```

Available tools:

- `run_shell`: run a shell command inside the emulator, optionally as root.
- `read_file`: read a UTF-8 text file from the emulator.
- `write_file`: write a UTF-8 text file into the emulator, optionally creating parent directories.
- `install_app`: install a host-local APK into the emulator via `libadb`.
- `frida_list_apps`: list Frida-visible Android apps.
- `frida_attach`: attach Frida to a running app by package name.
- `frida_spawn`: spawn an app suspended and attach Frida.
- `frida_resume`: resume a spawned Frida session.
- `frida_detach`: detach a Frida session and unload its scripts.
- `frida_load_script`: load a persistent Frida script.
- `frida_unload_script`: unload a persistent Frida script.
- `frida_eval`: run a one-shot Frida script in a session.
- `frida_rpc_call`: call an RPC export on a persistent script.
- `frida_get_messages`: fetch buffered Frida messages for a script.

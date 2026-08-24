# Ingots Tools

Collection of tools and libraries for ingots.

## Setup

### Skills

Run `./install_cli_tools.sh` to install cli tools referenced from skills in `skills/` folder.

Symlink or copy needed skills from `skills/` into codex or whatever harness skills folder.

### Docker setup

All Docker setup for Ingots agent sandboxes is centralized in
`kexploit_utils/`. Build the maintained images from the
`ingots_tools` workspace with:

```bash
uv run kexploit-utils build-all
```

## File Structure

- `cuttle_server/`: server and cli client for managing cuttlefish instances remotely.
- `cuttleagent/`: simple agent harness for researching vulnerabilities in apps.
- `kartifact/`: manages bug report, binary, exploit, and chain artifacts. Provides both a cli interface and dedicated agents.
  - NOTE: unfinished
- `kdebug/`: simple cli tool to help agent with debugging apps and exploits on android device.
- `ksandbox/`: simple python library to manage docker sandboxes, and provides api for running subprocess like commands and manipulating files in container.
- `kexploit_agent/`: uses `ksandbox/` and manages different agent harnesses in the sandbox, such as codex.
- `kexploit_utils/`: simple utils library, used by other packages.
- `object_db/`: builds queryable database of kernel objects, for agent to use when writing exploits.
- `scripts/`: collection of miscallaneous python scripts.
- `skills/`: collection of llm agent skills on using certain tools or other behaviors.

- `android_env/`: parse android selinux info to determine accessible services and files, and diff selinux contexts.
- `kexploit/`: adapts exploits between kernel versions.
- `primitives/`: library of primitive techniques for agent to use when writing kernel exploits.

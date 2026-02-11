# Synthesis Todo

Todos for exploit synthesis tools which will integrate with syzploit pipeline.

## Features

- Template folders with compilation commands
- Sandboxing in a docker container for llm command execution: ✅
- Debugging integration for llm
  - could be gdb, idk exactly what the syzploit gdb features are
  - something else, thinking if we could make some qemu tcg tracing thing and query the debug trace
  - Proibably just gdb first cause its easy and if llm has poor abilties with gdb something else
- heap object more details from runtime info
- ghidra integration, and mapping the definitions from source with ghidra definitions
- debugger subagent
- collect a repository of primitives, to expand upon the initial list of syzploit
- improve llm prompt

### Minor Feature

- token limits: ✅

## Cleanup

Probably just ditch lsp and btf types, just do it all codeql is cleaner, maybe more initial work

Jack TODO list for ingots stuff

# Exploit Development

- [ ] Review the connor exploits which only cause a crash, and the new bad epoll
	- [ ] also told to look at working ones but lower priority

# Tooling

### New Tools

- [ ] Overall an easier way to manage in progress exploits, finished exploits, and keep track of what targets they are for, some sort of central management system
	- [ ] Also manage kernel images, from ingots and built, source code, provenance etc.
- [ ] Building android easier
- [ ] possible better debugging, though agent seems pretty able to debug with kprobes

### ObjectDB

- [ ] LLM made report of issues encountered with the objectdb on first run, resolve them
- [ ] Future work on allocation reachability from android apps

### kexploit agent

- [x] Add some easy to use python interface for running codex in the sandbox, current python only harness kept for legacy purposes
	- [ ] TODO: test

### ksandbox

- [x] Resumable sandbox
	- [ ] TODO: test

### cuttle cli

- [ ] There were a lot of issues integrating with cuttlefish shutdowns, resolve them

### kdebug

- [ ] iirc this is very untested, test it more

### primitives

- [ ] Overall this needs a more complete extraction phase and knowledge database for reusable techniques
	- [ ] should support easy ingestion from human input as well
- [ ] Look at exiting todo list for new primitivies

### android_env

- [ ] potentially can improve, it is not super well tested, but multi stage exploits where we care about permissions of all parts have been relatively less common, it is mostly 1 app 1 kernel exploit
	- [ ] Think reformat as llm cli and skill, with structured report is more valueable
# Cuttle CLI Reliability and Security Issues

This document records a detailed review of `cuttle_cli`, with emphasis on bugs
that can hamper reliability, make daemon recovery unsafe, or expose sensitive
configuration. The findings are ordered roughly by severity.

## High-severity issues

### 1. Stale PID metadata can identify and terminate the wrong process

Daemon liveness is determined only by calling `os.kill(pid, 0)`. If the daemon
is killed abruptly and its PID is later reused, the CLI considers the unrelated
process to be the daemon. `daemon stop` then sends that process `SIGTERM`.

Relevant code:

- [`stop_managed_daemon()`](cuttle_cli/src/cuttle_cli/daemon.py#L111)
- [`get_daemon_status()`](cuttle_cli/src/cuttle_cli/daemon.py#L134)
- [`_pid_is_running()`](cuttle_cli/src/cuttle_cli/daemon.py#L281)

`DaemonMetadata.pid` also accepts zero or negative values. Corrupted state
containing `0` or `-1` could therefore cause a much broader signal operation.

Recommended fix:

- Use a lifetime-held advisory lock or a Linux pidfd as the authoritative
  daemon-liveness mechanism.
- If PID metadata remains, require `pid > 1` and record and verify the process
  start time, boot ID, and executable before signaling it.

### 2. Concurrent CLI invocations can launch multiple daemons

Daemon startup performs an unlocked check-then-spawn sequence. Two simultaneous
`start`, `list`, or `stop` commands can both observe no daemon and launch one.

Both children can then overwrite the same metadata and endpoint files. Stopping
the daemon signals only the last PID written; the other process remains alive
and can later delete the new daemon's files during cleanup.

Relevant code:

- [`ensure_managed_daemon_running()`](cuttle_cli/src/cuttle_cli/daemon.py#L60)
- [`start_managed_daemon()`](cuttle_cli/src/cuttle_cli/daemon.py#L73)
- [Daemon state writes](cuttle_cli/src/cuttle_cli/daemon.py#L298)

Recommended fix:

- Serialize startup with an advisory lock such as `flock`.
- Have the daemon retain the lock for its entire lifetime.
- Associate metadata and cleanup with a unique daemon generation so an older
  process cannot delete a newer daemon's state.

### 3. A single transient error permanently kills the daemon

Every reconciliation directly calls the API and `adb`. There is no per-cycle
recovery or backoff:

- A temporary connection refusal or server restart raises `CliError` and exits.
- A missing `adb` binary raises `FileNotFoundError` and exits.
- Malformed server or state JSON raises an uncaught validation error and exits.
- Other subprocess failures can also escape the loop.

Relevant code:

- [`run_daemon_forever()`](cuttle_cli/src/cuttle_cli/daemon.py#L144)
- [`sync_managed_daemon_once_with_client()`](cuttle_cli/src/cuttle_cli/daemon.py#L179)
- [`_run_adb_command()`](cuttle_cli/src/cuttle_cli/daemon.py#L271)

Automatic stale recovery compounds this problem: it deletes
`owned_endpoints.json` without first disconnecting or adopting those endpoints.
Existing ADB connections can therefore be left behind permanently with no
remaining ownership record.

Relevant code:

- [Stale-state handling](cuttle_cli/src/cuttle_cli/daemon.py#L67)
- [`_cleanup_stale_files()`](cuttle_cli/src/cuttle_cli/daemon.py#L329)

Recommended fix:

- Treat expected network and ADB failures as recoverable reconciliation-cycle
  failures.
- Log failures and retry with bounded exponential backoff.
- Preserve and reconcile old endpoint state during daemon recovery instead of
  deleting it first.

### 4. HTTP and ADB operations have no timeouts

`urlopen()` and `subprocess.run(["adb", ...])` can block indefinitely. This can
hang foreground commands, freeze daemon reconciliation, and prevent SIGTERM
shutdown because the signal handler only sets a boolean.

Relevant code:

- [`CuttleApiClient._request_json()`](cuttle_cli/src/cuttle_cli/client.py#L97)
- [`urlopen()` call](cuttle_cli/src/cuttle_cli/client.py#L115)
- [`_run_adb_command()`](cuttle_cli/src/cuttle_cli/daemon.py#L271)

Recommended fix:

- Define explicit HTTP connection and read deadlines.
- Give each `adb` subprocess a timeout.
- Convert timeout and transport failures into contextual `CliError` messages.

### 5. Clean shutdown can exceed its own deadline during normal operation

The daemon sleeps for five seconds, while `stop_managed_daemon()` waits exactly
five seconds. If SIGTERM arrives during sleep, the handler sets
`stop_requested`, but after sleeping the loop performs another reconciliation
before checking the flag. Cleanup then performs additional sequential ADB
operations.

A healthy daemon can consequently produce the error
`did not exit after SIGTERM`.

Relevant code:

- [`DAEMON_POLL_INTERVAL_SEC`](cuttle_cli/src/cuttle_cli/daemon.py#L18)
- [Five-second stop deadline](cuttle_cli/src/cuttle_cli/daemon.py#L120)
- [Daemon polling loop](cuttle_cli/src/cuttle_cli/daemon.py#L159)

Recommended fix:

- Use `threading.Event.wait()` as an interruptible polling delay.
- Check the stop event before starting another reconciliation.
- Give final cleanup a separate, bounded deadline that accounts for all ADB
  subprocesses.

### 6. `start` can wait forever or report a failed launch as successful

Startup polling has no client-side deadline. Although the server normally
bounds CVD startup, a server restart, stuck app installation, or persisted
orphaned `starting` record can leave the CLI looping forever.

Only `CRASHED` is treated as failure. If an instance becomes `STOPPING`,
`STOPPED`, or `EXPIRED`, the CLI exits the polling loop and prints
`started ...`.

Relevant code:

- [`start()` request and polling](cuttle_cli/src/cuttle_cli/main.py#L109)
- [`STARTING` loop](cuttle_cli/src/cuttle_cli/main.py#L124)
- [Terminal-state handling](cuttle_cli/src/cuttle_cli/main.py#L139)

Recommended fix:

- Impose a configurable client-side startup deadline.
- Treat only `ACTIVE` as successful startup.
- Treat all other terminal or unexpected states as failures and print the
  available diagnostic logs.

## Security and transport issues

### 7. The bearer token is exposed in the daemon command line

Even when loaded from the config file, the token is passed to the child process
as `--auth-token <token>`. It may be visible through process listings or
`/proc/<pid>/cmdline`.

Relevant code:

- [Daemon `Popen` arguments](cuttle_cli/src/cuttle_cli/daemon.py#L86)

The metadata already hashes the token, so placing the raw token in the process
argument list is unnecessary.

Recommended fix:

- Have the daemon reread a permission-checked configuration file, or pass the
  credential through a restricted pipe or inherited file descriptor.
- Do not put credentials in process arguments.

### 8. All API traffic is hardcoded to plaintext HTTP

The shared bearer token and user identity are transmitted without TLS whenever
the server is remote. The client cannot connect to an HTTPS endpoint.

Relevant code:

- [URL construction](cuttle_cli/src/cuttle_cli/client.py#L103)

The raw host construction also mishandles IPv6 literals. For example, `::1`
produces the malformed URL `http://::1:8000/...` and the ambiguous ADB target
`::1:<adb-port>`.

Recommended fix:

- Replace the host/port pair at the HTTP boundary with a validated server URL.
- Support HTTPS and correctly bracket IPv6 literals.

## Medium-severity reliability issues

### 9. State files are non-atomic and corruption is unrecoverable

Metadata and endpoint JSON are written directly to their final paths. A crash
or concurrent read can observe an empty or partial file. Parsing errors then
propagate out of `status`, `stop`, and automatic daemon startup.

A truncated `daemon.json` was confirmed to raise an uncaught Pydantic
`ValidationError` from `get_daemon_status()`.

Relevant code:

- [`_load_metadata()`](cuttle_cli/src/cuttle_cli/daemon.py#L291)
- [`_write_metadata()`](cuttle_cli/src/cuttle_cli/daemon.py#L298)
- [Endpoint-state reads and writes](cuttle_cli/src/cuttle_cli/daemon.py#L310)

Recommended fix:

- Write to a temporary file, flush and `fsync` it, then atomically rename it.
- Handle invalid state as a recoverable stale-state condition while preserving
  enough information for safe endpoint cleanup.

### 10. ADB "ownership" can disconnect connections established by another tool

A successful `adb connect` is recorded as owned even when the endpoint was
already connected. When the instance disappears, the daemon globally
disconnects it from the shared ADB server. This can disrupt a shell, debugger,
or another automation tool using the same endpoint.

Relevant code:

- [ADB endpoint reconciliation](cuttle_cli/src/cuttle_cli/daemon.py#L179)
- [`_disconnect_owned_endpoints()`](cuttle_cli/src/cuttle_cli/daemon.py#L256)

Recommended fix:

- Use an isolated ADB server for the daemon, or snapshot pre-existing
  connections and disconnect only endpoints demonstrably introduced by the
  daemon.

### 11. Recovery commands unnecessarily require valid API credentials

The root callback loads and validates API configuration before every command.
Consequently, `daemon status` and `daemon stop` cannot be used when the config
is missing or malformed, even though neither operation needs API credentials.

Relevant code:

- [Root callback](cuttle_cli/src/cuttle_cli/main.py#L47)
- [`daemon stop`](cuttle_cli/src/cuttle_cli/main.py#L336)

Recommended fix:

- Load API configuration lazily only for commands that contact the server or
  start/synchronize the daemon.

### 12. Polling and listing scale poorly over time

The daemon downloads the complete instance history every five seconds and
filters terminal instances locally. Because stopped and crashed history remains
in SQLite and the endpoint is unpaginated, reconciliation traffic grows with
the server's lifetime.

Startup polling is more expensive: every second it downloads the full log model,
including kernel, launcher, and logcat data, and then uses only the newly
appended portion of `start_log`. With growing logs, this causes approximately
quadratic cumulative transfer and repeated full-file reads.

Relevant code:

- [Daemon instance listing](cuttle_cli/src/cuttle_cli/daemon.py#L179)
- [Startup log polling](cuttle_cli/src/cuttle_cli/client.py#L155)
- [`get_instance_logs()`](cuttle_cli/src/cuttle_cli/transport.py#L58)

Recommended fix:

- Add server-side state filters and pagination for instance lists.
- Add an incremental log endpoint that accepts a stream name and byte offset.

### 13. Protocol and input validation failures escape CLI error handling

The client translates `HTTPError` and `URLError`, but not invalid JSON,
response-model validation failures, truncated responses, or unexpected JSON
shapes. Similarly, values such as `--cpus 0` raise a Pydantic validation error
that is not converted into a concise CLI error.

Relevant code:

- [HTTP exception handling](cuttle_cli/src/cuttle_cli/transport.py#L114)
- [JSON decoding](cuttle_cli/src/cuttle_cli/transport.py#L124)
- [Start request validation](cuttle_cli/src/cuttle_cli/client.py#L141)

Recommended fix:

- Translate decoding, schema-validation, and relevant transport failures into
  contextual `CliError` messages.
- Express CLI input constraints directly in Typer options where practical.

### 14. Log lookup by a reused name becomes permanently ambiguous

The server allows a name to be reused after the previous instance reaches a
terminal state. The CLI's name fallback matches every historical instance, so
`cuttle-cli logs demo` fails once more than one visible historical `demo`
exists, even when exactly one is currently active.

Relevant code:

- [`CuttleClient.logs()`](cuttle_cli/src/cuttle_cli/client.py#L181)

Recommended fix:

- Add a server-side lookup-by-name endpoint with the same selection semantics as
  stop-by-name, or consistently prefer the sole non-terminal/latest record and
  require an instance ID only when the result remains ambiguous.

## Verification and test gaps

- All 26 `cuttle_cli` unit tests pass under `unittest`.
- Production code and tests pass normal mypy checking, and both `cuttle_cli` and
  `cuttle_types` ship `py.typed` markers.
- Unit tests cover the high-level client workflows and CLI delegation, but do
  not simulate server-side concurrent admission or teardown.
- Tests still do not cover PID reuse, malformed or partial state, transient
  server failures, missing or hung `adb`, shutdown timing, or an instance stuck
  in `starting`.

## Suggested implementation order

1. Add lifetime daemon locking and verified process identity.
2. Add bounded HTTP and ADB operations.
3. Make shutdown signal-aware and independently bound cleanup.
4. Recover from transient reconciliation failures without exiting.
5. Make state persistence atomic and stale-state recovery lossless.
6. Bound startup polling and require `ACTIVE` for success.
7. Remove credentials from process arguments and support HTTPS.
8. Add regression tests for all daemon lifecycle and corruption scenarios.

## Live stress test: 2026-09-11

The live server was exercised through `cuttle-cli --user-id admin` using the
host-backed `challenge3` template (`cvd`, 6 CPUs, no template apps). The server
started with eight active instances belonging to other users. Test instances
used the `codex-stress-0911-*`, `codex-race-0911-*`, `codex-dup-0911`, and
`codex-postfail-0911` names. Cleanup was limited to owner `admin`.

### 15. Bulk stop can leave forced-stop records as crashed

Stopping seven active test instances with:

```text
cuttle-cli --user-id admin stop --stop-all-user admin
```

produced two failures. Both `cvd stop` calls exited with status 255 after the
launcher monitor returned an error. The stop log then reported that it sent
`SIGKILL` to the instance process group. The server changed both records to
`crashed`, retained their runtime directories and ADB port metadata, and made
the CLI exit nonzero even though the processes and ADB endpoints were gone.

Observed records:

```text
codex-race-0911-05  crashed  adb=cuttlefish:6536
codex-race-0911-06  crashed  adb=cuttlefish:6537
```

The slots were reusable immediately, so this did not reproduce permanent
capacity loss. It does make bulk cleanup noisy and accumulates failed records
and runtime directories after force termination apparently succeeded. The
seven-instance bulk stop also took roughly 30 seconds because stops run
sequentially.

Recommended fix:

- After a graceful stop failure and forced termination, verify that the process
  group and endpoint are gone. If verified, complete the record as `stopped`
  while preserving the graceful-stop warning separately.
- Reserve `crashed` and retained runtime state for instances whose forced
  teardown cannot be verified.
- Consider bounded parallel teardown for bulk stop, or expose progress so a
  large sequential cleanup does not appear hung.

### 16. Terminal history displays stale, reusable ADB targets

`list --all` displays stored ADB targets for many stopped and crashed records.
Those ports are no longer connected and are routinely reassigned to newer
instances. During this test, the crashed records above continued to display
ports 6536 and 6537 after the daemon had disconnected them; later launches
could reuse the same slot and port.

This is misleading for users and unsafe for automation parsing `list --all`,
because connecting to a historical row can reach an unrelated current device.

Recommended fix:

- Clear connection metadata when an instance becomes terminal, or make the CLI
  render `-` for terminal-state ADB targets while retaining historical port data
  separately if it is useful for diagnostics.

### Reconfirmed existing issues

- Issue 12: `list --all` returned the complete, already-large historical table;
  there is still no state filter or pagination.
- Issue 14: `cuttle-cli --user-id admin logs shareit_pwn` failed with
  `multiple visible instances match 'shareit_pwn'` because the name has been
  reused across terminal records.

### Behaviors that held under stress

- The managed range was 5-20 (16 slots). At 16 active instances, an additional
  start failed cleanly with HTTP 409 and `no instance slots available`.
- From eight active instances, ten simultaneous starts admitted exactly eight
  and rejected exactly two with HTTP 409. Allocated instance numbers and ADB
  ports were unique, and rejected requests left no ghost records.
- Stopping one instance made its slot immediately reusable. Even the two failed
  forced stops released capacity.
- Two simultaneous starts with the same owner/name admitted one request and
  rejected the other with HTTP 400; name uniqueness remained atomic.
- After cleanup, the active inventory and `adb devices` both returned to the
  original eight instances/endpoints, with no stress endpoints left connected.

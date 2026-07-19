use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const SOCKET_NAME: &str = "daemon.sock";

#[derive(Debug, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
enum Request {
    #[serde(rename = "health")]
    Health,
    #[serde(rename = "spawn")]
    Spawn {
        command: String,
        timeout_secs: Option<u64>,
        cwd: Option<String>,
        env: Option<std::collections::HashMap<String, String>>,
    },
    #[serde(rename = "stdin")]
    Stdin { data_b64: String },
    #[serde(rename = "close_stdin")]
    CloseStdin,
    #[serde(rename = "kill")]
    Kill {
        #[serde(default = "default_signal")]
        signal: i32,
    },
    #[serde(rename = "read_file")]
    ReadFile { path: String },
    #[serde(rename = "write_file")]
    WriteFile {
        path: String,
        content_b64: String,
        #[serde(default)]
        overwrite: bool,
    },
    #[serde(rename = "edit_file")]
    EditFile {
        path: String,
        old_b64: String,
        new_b64: String,
        #[serde(default)]
        replace_all: bool,
    },
    #[serde(rename = "list_directory")]
    ListDirectory { path: String },
    #[serde(rename = "grep")]
    Grep {
        pattern: String,
        path: Option<String>,
        glob: Option<String>,
        timeout_secs: Option<u64>,
    },
    #[serde(rename = "glob")]
    Glob {
        pattern: String,
        #[serde(default = "root_path")]
        path: String,
        timeout_secs: Option<u64>,
    },
}

fn default_signal() -> i32 {
    libc::SIGTERM
}
fn root_path() -> String {
    "/".to_owned()
}

#[derive(Serialize)]
struct DirectoryEntry {
    path: String,
    is_dir: bool,
}

#[derive(Serialize)]
struct GrepMatch {
    path: String,
    line: usize,
    text: String,
}

fn send(stream: &mut UnixStream, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *stream, value)?;
    stream.write_all(b"\n")?;
    stream.flush()
}

fn send_locked(stream: &Arc<Mutex<UnixStream>>, value: Value) -> io::Result<()> {
    send(&mut stream.lock().expect("socket mutex poisoned"), &value)
}

fn classify_file_error(error: &io::Error) -> &'static str {
    match error.raw_os_error() {
        Some(libc::ENOENT | libc::ENOTDIR) => "file_not_found",
        Some(libc::EACCES | libc::EPERM) => "permission_denied",
        Some(libc::EISDIR) => "is_directory",
        Some(libc::EEXIST) => "already_exists",
        Some(libc::EINVAL | libc::ENAMETOOLONG) => "invalid_path",
        _ => "unknown_error",
    }
}

fn sibling_binary(name: &str) -> io::Result<PathBuf> {
    Ok(env::current_exe()?
        .parent()
        .ok_or_else(|| io::Error::other("daemon has no parent directory"))?
        .join(name))
}

fn kill_process_group(pid: u32, signal: i32) {
    unsafe {
        libc::kill(-(pid as i32), signal);
    }
}

fn stream_output<R: Read + Send + 'static>(
    mut reader: R,
    event_type: &'static str,
    command_id: String,
    stream: Arc<Mutex<UnixStream>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let _ = send_locked(
                        &stream,
                        json!({
                            "type": event_type,
                            "id": command_id,
                            "data_b64": BASE64.encode(&buffer[..count]),
                        }),
                    );
                }
                Err(_) => break,
            }
        }
    })
}

fn control_messages(stream: UnixStream, stdin: ChildStdin, pid: u32) {
    thread::spawn(move || {
        let mut stdin = Some(stdin);
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => match serde_json::from_str::<Request>(&line) {
                    Ok(Request::Stdin { data_b64 }) => {
                        if let (Ok(data), Some(handle)) = (BASE64.decode(data_b64), stdin.as_mut())
                        {
                            let _ = handle.write_all(&data);
                            let _ = handle.flush();
                        }
                    }
                    Ok(Request::CloseStdin) => {
                        stdin.take();
                    }
                    Ok(Request::Kill { signal }) => kill_process_group(pid, signal),
                    _ => {}
                },
            }
        }
    });
}

fn handle_spawn(
    stream: UnixStream,
    command: String,
    timeout_secs: Option<u64>,
    cwd: Option<String>,
    request_env: Option<std::collections::HashMap<String, String>>,
) -> io::Result<()> {
    let command_id = Uuid::new_v4().simple().to_string();
    let mut process = Command::new("/bin/sh");
    process
        .arg("-c")
        .arg(command)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    process.process_group(0);
    if let Some(cwd) = cwd {
        process.current_dir(cwd);
    }
    if let Some(vars) = request_env {
        process.envs(vars);
    }

    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => {
            let mut stream = stream;
            return send(
                &mut stream,
                &json!({"type":"error", "message":error.to_string()}),
            );
        }
    };
    let pid = child.id();
    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    send_locked(&writer, json!({"type":"spawned", "id":command_id}))?;

    let stdout_thread = stream_output(
        child.stdout.take().expect("piped stdout"),
        "stdout",
        command_id.clone(),
        writer.clone(),
    );
    let stderr_thread = stream_output(
        child.stderr.take().expect("piped stderr"),
        "stderr",
        command_id.clone(),
        writer.clone(),
    );
    control_messages(stream, child.stdin.take().expect("piped stdin"), pid);

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if timeout_secs.is_some_and(|timeout| start.elapsed() >= Duration::from_secs(timeout)) {
            timed_out = true;
            kill_process_group(pid, libc::SIGTERM);
            let grace = Instant::now();
            let timeout_status = loop {
                if let Some(status) = child.try_wait()? {
                    break status;
                }
                if grace.elapsed() >= Duration::from_secs(2) {
                    kill_process_group(pid, libc::SIGKILL);
                    break child.wait()?;
                }
                thread::sleep(Duration::from_millis(20));
            };
            break timeout_status;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
    let exit_code = if timed_out {
        124
    } else {
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
    };
    send_locked(
        &writer,
        json!({
            "type":"exit", "id":command_id, "exit_code":exit_code,
            "timed_out":timed_out, "timeout_secs":timeout_secs,
        }),
    )
}

fn read_all<R: Read + Send + 'static>(mut input: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut output = Vec::new();
        let _ = input.read_to_end(&mut output);
        output
    })
}

fn run_tool(
    binary: &str,
    args: &[String],
    timeout_secs: Option<u64>,
) -> io::Result<(Vec<u8>, Vec<u8>, i32, bool)> {
    let mut child = Command::new(sibling_binary(binary)?)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout_thread = read_all(child.stdout.take().expect("piped stdout"));
    let stderr_thread = read_all(child.stderr.take().expect("piped stderr"));
    let start = Instant::now();
    let mut timed_out = false;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if timeout_secs.is_some_and(|timeout| start.elapsed() >= Duration::from_secs(timeout)) {
            timed_out = true;
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let status = child.wait()?;
    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();
    Ok((stdout, stderr, status.code().unwrap_or(1), timed_out))
}

fn handle_request(mut stream: UnixStream) -> io::Result<()> {
    let request = {
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        match serde_json::from_str::<Request>(&line) {
            Ok(request) => request,
            Err(error) => {
                return send(
                    &mut stream,
                    &json!({"type":"error", "message":error.to_string()}),
                )
            }
        }
    };
    match request {
        Request::Health => send(&mut stream, &json!({"type":"health", "status":"ok"})),
        Request::Spawn {
            command,
            timeout_secs,
            cwd,
            env,
        } => handle_spawn(stream, command, timeout_secs, cwd, env),
        Request::ReadFile { path } => match fs::read(&path) {
            Ok(content) => send(
                &mut stream,
                &json!({"type":"read_file_result", "path":path, "content_b64":BASE64.encode(content)}),
            ),
            Err(error) => send(
                &mut stream,
                &json!({"type":"read_file_result", "path":path, "error":classify_file_error(&error)}),
            ),
        },
        Request::WriteFile {
            path,
            content_b64,
            overwrite,
        } => {
            let result = (|| -> io::Result<()> {
                if let Some(parent) = Path::new(&path).parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut options = OpenOptions::new();
                options
                    .write(true)
                    .create_new(!overwrite)
                    .create(overwrite)
                    .truncate(overwrite);
                options
                    .open(&path)?
                    .write_all(&BASE64.decode(content_b64).map_err(io::Error::other)?)
            })();
            match result {
                Ok(()) => send(
                    &mut stream,
                    &json!({"type":"write_file_result", "path":path}),
                ),
                Err(error) => send(
                    &mut stream,
                    &json!({"type":"write_file_result", "path":path, "error":classify_file_error(&error)}),
                ),
            }
        }
        Request::EditFile {
            path,
            old_b64,
            new_b64,
            replace_all,
        } => {
            let result = (|| -> io::Result<Result<usize, (&'static str, usize)>> {
                let content = fs::read(&path)?;
                let old = BASE64.decode(old_b64).map_err(io::Error::other)?;
                let new = BASE64.decode(new_b64).map_err(io::Error::other)?;
                if old.is_empty() {
                    return Ok(Err(("invalid_path", 0)));
                }
                let mut offsets = Vec::new();
                let mut search_from = 0;
                while search_from + old.len() <= content.len() {
                    let Some(relative) = content[search_from..]
                        .windows(old.len())
                        .position(|value| value == old.as_slice())
                    else {
                        break;
                    };
                    let offset = search_from + relative;
                    offsets.push(offset);
                    search_from = offset + old.len();
                }
                if offsets.is_empty() {
                    return Ok(Err(("string_not_found", 0)));
                }
                if offsets.len() > 1 && !replace_all {
                    return Ok(Err(("multiple_occurrences", offsets.len())));
                }
                let mut updated = Vec::with_capacity(content.len());
                let mut cursor = 0;
                for offset in offsets.iter().copied() {
                    if offset < cursor {
                        continue;
                    }
                    updated.extend_from_slice(&content[cursor..offset]);
                    updated.extend_from_slice(&new);
                    cursor = offset + old.len();
                    if !replace_all {
                        break;
                    }
                }
                updated.extend_from_slice(&content[cursor..]);
                fs::write(&path, updated)?;
                Ok(Ok(offsets.len()))
            })();
            match result {
                Ok(Ok(count)) => send(
                    &mut stream,
                    &json!({"type":"edit_file_result", "path":path, "occurrences":count}),
                ),
                Ok(Err((error, count))) => send(
                    &mut stream,
                    &json!({"type":"edit_file_result", "path":path, "occurrences":count, "error":error}),
                ),
                Err(error) => send(
                    &mut stream,
                    &json!({"type":"edit_file_result", "path":path, "error":classify_file_error(&error)}),
                ),
            }
        }
        Request::ListDirectory { path } => match fs::read_dir(&path) {
            Ok(items) => {
                let entries: Vec<DirectoryEntry> = items
                    .filter_map(Result::ok)
                    .map(|item| {
                        let item_path = item.path();
                        DirectoryEntry {
                            path: item_path.to_string_lossy().into_owned(),
                            is_dir: item.file_type().is_ok_and(|kind| kind.is_dir()),
                        }
                    })
                    .collect();
                send(
                    &mut stream,
                    &json!({"type":"list_directory_result", "entries":entries}),
                )
            }
            Err(error) => send(
                &mut stream,
                &json!({"type":"list_directory_result", "entries":[], "error":classify_file_error(&error)}),
            ),
        },
        Request::Grep {
            pattern,
            path,
            glob,
            timeout_secs,
        } => {
            let mut args = vec![
                "--line-number",
                "--with-filename",
                "--color",
                "never",
                "--no-heading",
                "--fixed-strings",
                "--hidden",
                "--no-ignore",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
            if let Some(glob) = glob {
                args.extend(["--glob".to_owned(), glob]);
            }
            args.extend([pattern, path.unwrap_or_else(|| ".".to_owned())]);
            match run_tool("rg", &args, timeout_secs) {
                Ok((_, _, _, true)) => send(
                    &mut stream,
                    &json!({"type":"grep_result", "matches":[], "timed_out":true}),
                ),
                Ok((stdout, _stderr, code, false)) if code == 0 || code == 1 => {
                    let matches: Vec<GrepMatch> = String::from_utf8_lossy(&stdout)
                        .lines()
                        .filter_map(|line| {
                            let mut parts = line.splitn(3, ':');
                            Some(GrepMatch {
                                path: parts.next()?.to_owned(),
                                line: parts.next()?.parse().ok()?,
                                text: parts.next()?.to_owned(),
                            })
                        })
                        .collect();
                    send(
                        &mut stream,
                        &json!({"type":"grep_result", "matches":matches}),
                    )
                }
                Ok((_, stderr, _, false)) => send(
                    &mut stream,
                    &json!({"type":"grep_result", "matches":[], "error":String::from_utf8_lossy(&stderr).trim()}),
                ),
                Err(error) => send(
                    &mut stream,
                    &json!({"type":"grep_result", "matches":[], "error":error.to_string()}),
                ),
            }
        }
        Request::Glob {
            pattern,
            path,
            timeout_secs,
        } => {
            let args = vec![
                "--hidden".to_owned(),
                "--no-ignore".to_owned(),
                "--glob".to_owned(),
                "--full-path".to_owned(),
                pattern,
                path.clone(),
            ];
            match run_tool("fd", &args, timeout_secs) {
                Ok((_, _, _, true)) => send(
                    &mut stream,
                    &json!({"type":"glob_result", "entries":[], "timed_out":true}),
                ),
                Ok((stdout, _stderr, code, false)) if code == 0 || code == 1 => {
                    let entries: Vec<DirectoryEntry> = String::from_utf8_lossy(&stdout)
                        .lines()
                        .filter(|line| !line.is_empty())
                        .map(|line| {
                            let output_path = if Path::new(line).is_absolute() {
                                PathBuf::from(line)
                            } else {
                                Path::new(&path).join(line)
                            };
                            DirectoryEntry {
                                is_dir: output_path.is_dir(),
                                path: output_path.to_string_lossy().into_owned(),
                            }
                        })
                        .collect();
                    send(
                        &mut stream,
                        &json!({"type":"glob_result", "entries":entries}),
                    )
                }
                Ok((_, stderr, _, false)) => send(
                    &mut stream,
                    &json!({"type":"glob_result", "entries":[], "error":String::from_utf8_lossy(&stderr).trim()}),
                ),
                Err(error) => send(
                    &mut stream,
                    &json!({"type":"glob_result", "entries":[], "error":error.to_string()}),
                ),
            }
        }
        Request::Stdin { .. } | Request::CloseStdin | Request::Kill { .. } => send(
            &mut stream,
            &json!({"type":"error", "message":"unsupported request type"}),
        ),
    }
}

fn main() -> io::Result<()> {
    let mut runtime_dir = PathBuf::from("/sandbox_runtime");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--runtime-dir" {
            runtime_dir = PathBuf::from(
                args.next()
                    .ok_or_else(|| io::Error::other("--runtime-dir requires a value"))?,
            );
        }
    }
    fs::create_dir_all(&runtime_dir)?;
    let socket_path = runtime_dir.join(SOCKET_NAME);
    if fs::symlink_metadata(&socket_path).is_ok() {
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_request(stream);
                });
            }
            Err(error) => eprintln!("ksandbox daemon accept failed: {error}"),
        }
    }
    Ok(())
}

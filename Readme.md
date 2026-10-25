# Ramsi (Rust AMSI Provider)

**Ramsi** is a custom AMSI (Antimalware Scan Interface) provider implemented in Rust. It enables advanced monitoring and logging of script execution and content scanning on Windows systems.

## Features

- AMSI provider DLL written in Rust (`ramsi-com`)
- PowerShell deobfuscation and heuristic scan (keyword lists, embedded C# from `Add-Type`, `powershell -Command`/`-EncodedCommand`, `-Version 2` downgrade)
- Monitor or block mode, extra rules from a `rules.toml` file
- CLI tool for registration, configuration and tracing events (`ramsi-cli`)
- Scan events sent as JSON over a named pipe; the provider only talks to a pipe owned by Administrators or SYSTEM
- Logs and optional dumps in `C:\ProgramData\ramsi`
- Debug logging via `OutputDebugString` (viewable with [DbgView](https://docs.microsoft.com/en-us/sysinternals/downloads/dbgview))
- Easy build and distribution via `xtask`

## Requirements

- Windows OS
- Rust nightly, pinned in `rust-toolchain.toml` (rustup installs it automatically)

## Build Instructions

To build the project and prepare distributable binaries:

```sh
cargo xtask dist
```

This will produce `ramsi_com.dll`, `ramsi_com32.dll` (the provider for 32-bit processes) and `ramsi-cli.exe` in the `dist` directory. The CRT is linked statically, so no VC++ redistributable is needed.

## Installation

From an elevated prompt, register the provider with `ramsi-cli.exe`:
```sh
ramsi-cli.exe register --dll ramsi_com.dll --dll32 ramsi_com32.dll
```

Without `--dll32`, 32-bit processes such as `C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` are not scanned. Both providers read the same configuration.

Registration (also through `regsvr32`) creates the log directory owned by Administrators, with an ACL that lets users create their own log files but not read other users' ones. Providers write logs and dumps only to a directory owned by Administrators or SYSTEM.

Or use the built-in Windows tool:
```sh
regsvr32 ramsi_com.dll
```

## Usage
```sh
> ramsi-cli.exe --help
Manage the Ramsi AMSI provider and trace its events

Usage: ramsi-cli.exe <COMMAND>

Commands:
  register    Register the provider DLL as an AMSI provider
  unregister  Unregister the provider DLL
  trace       Print events reported by the provider until Ctrl+C
  status      Show registration and configuration
  config      Show or change the configuration in HKLM\SOFTWARE\Ramsi
  help        Print this message or the help of the given subcommand(s)
```

Trace events (elevated; `--register` registers the DLL for the time of tracing):
```sh
> ramsi-cli.exe trace --register --dll ramsi_com.dll
2026-10-22T11:10:04.123Z Detected (blocked) pid: 7668, app: PowerShell, content: <command>, reason: Blacklisted keyword in script detected TECHNIC 1. Keyword: amsiutils
```

`--json` prints every event as one JSON line (with the script content), `--filter TEXT` prints only events containing `TEXT`.

## Configuration

Settings live in `HKLM\SOFTWARE\Ramsi` and are read once when a process loads the provider, so they apply to processes started afterwards.

```sh
ramsi-cli.exe config show
ramsi-cli.exe config set mode block
ramsi-cli.exe config unset mode
```

| Name | Default | Meaning |
|---|---|---|
| `mode` | `monitor` | `monitor` reports only, `block` also returns `AMSI_RESULT_DETECTED` |
| `block_on` | `detected` | lowest status blocked in block mode: `detected` or `suspicious` |
| `report` | `1` | send events to the pipe |
| `report_on` | `suspicious` | lowest status reported: `detected`, `suspicious` or `all` (every scan, including clean ones) |
| `commands` | none | `;`-separated commands, e.g. `Register-ScheduledTask`; a script calling one is reported whatever its status, with the command's arguments as the parser evaluated them; see [Command matching](#command-matching) |
| `apps` | all | `;`-separated app name prefixes to scan, e.g. `PowerShell_` |
| `log_level` | `info` | `off`, `error`, `warn`, `info`, `debug`, `trace` |
| `log_dir` | `C:\ProgramData\ramsi` | logs and dumps; `config set log_dir` secures the new directory |
| `dump` | `0` | write the content of every reported script to `log_dir` |
| `max_content` | `65536` | bytes of script content sent in an event, at most 2 MiB |
| `pipe` | `ramsi` | pipe name suffix, `\\.\pipe\<pipe>` |
| `rules` | none | path to a `rules.toml`; `config set rules` makes the file owned and writable by admins only, providers ignore it otherwise |

`rules.toml` extends the built-in lists; every key is optional:

```toml
blacklist_keywords = ["Invoke-Evil"]          # strings -> detected
blacklist_keywords_endswith = []
blacklist_functions = []                       # commands and methods -> detected
telemetry_strings = []                         # -> suspicious
telemetry_functions = []
telemetry_types = []
allowlist_sha256 = ["<sha256 of a script that is always clean>"]
```

## Output

- Scan events as JSON over `\\.\pipe\ramsi` (8-byte big-endian length, then the JSON), see [Event format](#event-format)
- Logs in `C:\ProgramData\ramsi\amsi-{pid}-{tid}-{date}.log`, created only by a process that logs something; a missing trace server is logged once per process until it connects
- With `dump` on: `{pid}_{tid}_{requestNumber}_{contentName}.dmp` (and an identical `.txt`) with the scanned content and a `.info` file with its metadata
- Debug messages via `OutputDebugString`

## Event format

Each provider (one per process that loaded it) connects to the pipe and sends one message per reported scan: an 8-byte big-endian length, then a JSON object. `ramsi-cli trace --json` prints the same object as one line, after the trace server filled in its fields.

| Field | Type | Meaning |
|---|---|---|
| `version` | number | event schema version, currently `1`, bumped on a breaking change; `0` (or missing) from providers older than the field; adding a field does not bump it, the trace server passes every version through |
| `time` | string | scan time, RFC 3339 UTC with milliseconds |
| `pid`, `tid` | number | process and thread that ran the scan |
| `process` | string | executable file name, e.g. `powershell.exe` |
| `cmd_line` | string | command line of the process |
| `app_name` | string | AMSI app name, e.g. `PowerShell_C:\...\powershell.exe_10.0.19041.1` |
| `content_name` | string | script path, empty for an interactive command |
| `session` | number | AMSI session, groups the scans of one script; not the Windows session |
| `request_number` | number | per-process scan counter, starting at 1 |
| `status` | string | `clean` (allowlisted), `detected`, `suspicious` or `not_detected` |
| `reason` | string or null | what the heuristic matched |
| `blocked` | bool | the provider returned `AMSI_RESULT_DETECTED` |
| `content` | string | scanned script, cut to `max_content` bytes |
| `content_truncated` | bool | `content` was cut |
| `commands` | array | calls of the configured `commands`, each `{"name": ..., "args": [...]}` with the arguments as the parser evaluated them (variables, splatting, concatenation); an argument it cannot evaluate, e.g. an unknown variable, is kept as written (`$action`); parameter names are lowercased, the name loses quotes and backticks, a repeated call is listed once, e.g. `{"name": "Register-ScheduledTask", "args": ["-taskname", "Updater"]}` |
| `commands_truncated` | bool | `commands` was cut, they share `max_content` with `content` and go first |
| `parse_failed` | bool | the PowerShell parser could not handle the script (e.g. a syntax error), so `commands` is empty whatever it calls; content that is not PowerShell and allowlisted scripts are not parsed and have it `false` |
| `process_created` | string or null | creation time of the client process, with `pid` it tells it apart from a later process reusing the pid |
| `user_sid` | string or null | user of the client process |
| `parent_pid` | number or null | parent of the client process, null when the parent has exited (a process created after the client only reuses its pid); a process can be started with a spoofed parent |
| `session_id` | number or null | Windows session of the client process |

The last four fields are set by the trace server from the pipe client process as the kernel reports it; whatever a provider sends there is overwritten. Any local process can write to the pipe, so the trace server drops an event whose `pid` is not the pid of the client that sent it. Fields added later are optional, so a consumer reading older events gets their defaults (`false`, empty, null).

## Command matching

A configured command is matched, case-insensitively and with or without its module (`ScheduledTasks\Register-ScheduledTask`), when the script calls it:
- directly, with any arguments, including unknown variables, splatting and pipeline input
- by a name built at run time: `& ('Register-' + 'ScheduledTask')`, `.(...)`, `& $name`, `-f`, or escaped with backticks
- inside `try`/`catch`/`finally`, loops, functions and script blocks
- through `powershell -EncodedCommand` (in the calling process, and again in the child process)
- through `Invoke-Expression` or `[ScriptBlock]::Create`: the parser does not see the call, but PowerShell scans the string when it runs it, so the event comes from that scan

Not matched: calls through an alias or `& (Get-Command ...)`, allowlisted scripts and scripts that fail to parse (`parse_failed`).

## Trust model

The provider runs inside every process that calls AMSI, including unelevated ones, so any local user can write to the pipe. That process controls its own memory: it can send any `content` and `commands`, or bypass AMSI altogether, as with any AMSI provider. Only the fields the trace server takes from the kernel (`pid`, `process_created`, `user_sid`, `parent_pid`, `session_id`) can be trusted. Treat `content` and `commands` as telemetry the process reported, not as proof of what it ran.

## Performance

Measured on a 2-vCPU Windows 10 VM with Defender and another AMSI provider installed, ramsi added on top (medians):

| | without ramsi | ramsi, default config | ramsi, `report_on all` |
|---|---|---|---|
| `powershell -Command "exit 0"` | 170 ms | 205 ms | 200 ms |
| 500 `Invoke-Expression` scans | 0.8 s | 1.45 s | 2.0 s (server running) |
| `Import-Module ScheduledTasks; Get-ScheduledTask` | 0.9 s | 1.0 s | 1.0 s |

That is about 30 ms per process start and 1.3 ms per scan, plus about 1 ms per reported event. No trace server adds nothing measurable; a server that stops reading costs a reporting process 500 ms once, then it stops sending for 30 s. In every case scripts ran with the same output and exit code.

## Integration

A consumer such as shem reads events as JSON lines from `ramsi-cli trace --json`, run as an elevated child process:

```sh
ramsi-cli.exe register --dll ramsi_com.dll --dll32 ramsi_com32.dll
ramsi-cli.exe config set commands "Register-ScheduledTask"
ramsi-cli.exe trace --json
```

The trace server checks each event against the pipe client process and fills in `process_created`, `user_sid`, `parent_pid` and `session_id` (see [Event format](#event-format)), so a consumer should not read the pipe directly. Configuration is read when a process loads the provider, so changes apply to processes started afterwards. Events reported while no trace server runs are lost; a provider reconnects on its next reported scan.

## Uninstallation

Unregister the AMSI provider with `ramsi-cli.exe`:
```sh
ramsi-cli.exe unregister --dll ramsi_com.dll --dll32 ramsi_com32.dll
```

With `regsvr32`
```sh
regsvr32 /u dist\ramsi_com.dll
```

**Note:** If PowerShell or another process is using the DLL, you may need to close those processes before replacing or deleting the DLL.

## Tests

```sh
cargo test --workspace
cargo test -p ramsi-com --target i686-pc-windows-msvc --lib --test samples
```

Pipe tests need an elevated prompt; set `RAMSI_TEST_USER` and `RAMSI_TEST_PASSWORD` to a standard local account to also test a client running as another user. `ramsi-com/tests/samples/{benign,suspicious,detected}` hold sample scripts checked by `tests/samples.rs`. The end-to-end test registers the DLL machine-wide, so run it elevated on a disposable VM only:

```sh
cargo test -p ramsi-com --test e2e -- --ignored
```

With `--target i686-pc-windows-msvc` and `RAMSI_DLL` set to `ramsi_com32.dll`, the same test checks the 32-bit provider in 32-bit PowerShell.

## Project Structure

- `ramsi-com/` — AMSI provider DLL
- `ramsi-cli/` — CLI tool for provider management and tracing
- `shared/` — Shared types and constants
- `macros/` — Compile-time keyword and hash list macros
- `xtask/` — Custom build and distribution tasks

## Future plans
- add certificate
- log to event viewer

## License

Licensed under the MIT Non-Commercial License: commercial use requires written permission from the copyright holder.
See [LICENSE_MIT](LICENSE_MIT) for details.

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

This will produce `ramsi_com.dll` and `ramsi-cli.exe` in the `dist` directory.

## Installation

From an elevated prompt, register the provider with `ramsi-cli.exe`:
```sh
ramsi-cli.exe register --dll ramsi_com.dll
```

This also creates the log directory with an ACL that lets users create their own log files but not read other users' ones.

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
| `report` | `1` | send detected and suspicious events to the pipe |
| `apps` | all | `;`-separated app name prefixes to scan, e.g. `PowerShell_` |
| `log_level` | `info` | `off`, `error`, `warn`, `info`, `debug`, `trace` |
| `log_dir` | `C:\ProgramData\ramsi` | logs and dumps |
| `dump` | `0` | write the content of every reported script to `log_dir` |
| `max_content` | `65536` | bytes of script content sent in an event |
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

- Scan events as JSON over `\\.\pipe\ramsi` (8-byte big-endian length, then the JSON)
- Logs in `C:\ProgramData\ramsi\amsi-{pid}-{tid}-{date}.log`
- With `dump` on: `{pid}_{tid}_{requestNumber}_{contentName}.dmp` (and an identical `.txt`) with the scanned content and a `.info` file with its metadata
- Debug messages via `OutputDebugString`

## Uninstallation

Unregister the AMSI provider with `ramsi-cli.exe`:
```sh
ramsi-cli.exe unregister --dll ramsi_com.dll
```

With `regsvr32`
```sh
regsvr32 /u dist\ramsi_com.dll
```

**Note:** If PowerShell or another process is using the DLL, you may need to close those processes before replacing or deleting the DLL.

## Tests

```sh
cargo test --workspace
```

Pipe tests need an elevated prompt; set `RAMSI_TEST_USER` and `RAMSI_TEST_PASSWORD` to a standard local account to also test a client running as another user. `ramsi-com/tests/samples/{benign,suspicious,detected}` hold sample scripts checked by `tests/samples.rs`. The end-to-end test registers the DLL machine-wide, so run it elevated on a disposable VM only:

```sh
cargo test -p ramsi-com --test e2e -- --ignored
```

## Project Structure

- `ramsi-com/` — AMSI provider DLL
- `ramsi-cli/` — CLI tool for provider management and tracing
- `shared/` — Shared types and constants
- `macros/` — Compile-time keyword and hash list macros
- `xtask/` — Custom build and distribution tasks

## Future plans
- add certificate
- support for win32
- log to event viewer

## License

Licensed under MIT.
See [LICENSE_MIT](LICENSE_MIT) for details.

# Ramsi (Rust AMSI Provider)

**Ramsi** is a custom AMSI (Antimalware Scan Interface) provider implemented in Rust. It enables advanced monitoring and logging of script execution and content scanning on Windows systems.

## Commercial Use & Contact
This project is a demo version. For commercial licensing, partnership opportunities, or access to the full version (including pattern matching, PowerShell deobfuscation, and script blocking features), please contact: radoslaw.kumorekit@gmail.com

## Features

- AMSI provider DLL written in Rust (`ramsi-com`)
- CLI tool for registration, unregistration, and tracing events (`ramsi-cli`)
- Inter-process communication via named pipes
- Dumps scanned content and metadata to `C:\ramsi`
- Debug logging via `OutputDebugString` (viewable with [DbgView](https://docs.microsoft.com/en-us/sysinternals/downloads/dbgview))
- Easy build and distribution via `xtask`

## Requirements

- Rust 1.88 or newer (nightly recommended)
- Windows OS

## Build Instructions

To build the project and prepare distributable binaries:

```sh
cargo xtask dist
```

This will produce `ramsi_com.dll` and `ramsi-cli.exe` in the `dist` directory.

## Installation
Run `ramsi-cli.exe` to register `ramsi_com.dll` and intercept events:
```sh
ramsi-cli.exe -r ramsi_com.dll
```

Use built-in windows tool:
```sh
regsvr32 ramsi_com.dll
```

## Usage
```sh
> ramsi-cli.exe -h
Usage: ramsi-cli [OPTION]
Options:
  -r, --register       Register the COM component
  -u, --unregister     Unregister the COM component
  -a, --all            Register the COM component and trace AMSI events
  -t, --trace          Trace AMSI events
```

Example:
```sh
>ramsi-cli.exe -a ramsi_com.dll
[2025-10-21T14:23:29Z TRACE ramsi_cli] Main start
Pid: 13924, AppName: PowerShell_C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe_10.0.19041.1, ContentName: C:\Program Files\WindowsPowerShell\Modules\PSReadline\2.0.0\PSReadline.psd1
...
```

## Output

Ramsi logs events and dumps content to `C:\ramsi`:
- `{pid}_{session}_{requestNumber}_{contentName}.dmp` — raw scanned content
- AmsiMessage by `\\.\pipe\ramsi`
- Debug messages via `OutputDebugString`

## Uninstallation

Unregister the AMSI provider with `ramsi-cli.exe`:
```sh
ramsi-cli.exe -u ramsi_com.dll
```

With `regsvr32`
```sh
regsvr32 /u dist\ramsi_com.dll
```

**Note:** If PowerShell or another process is using the DLL, you may need to close those processes before replacing or deleting the DLL.

## Project Structure

- `ramsi-com/` — AMSI provider DLL
- `ramsi-cli/` — CLI tool for provider management and tracing
- `shared/` — Shared types and constants
- `macros/` — Logging and error macros
- `xtask/` — Custom build and distribution tasks

## Future plans
- add events evaluation
- secure and auntheticate pipes
- add certificate
- improve cli
- support for win32
- log to event viewer

## License

Licensed under MIT.
See [LICENSE-MIT](LICENSE-MIT) for details.
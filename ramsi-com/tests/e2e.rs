// Registers the built DLL machine-wide: run elevated on a disposable VM only.
//   cargo test -p ramsi-com --test e2e -- --ignored

use std::{process::Command, time::Duration};

use shared::{ScanEvent, ScanStatus, constants::CONFIG_KEY};
use tokio::{io::AsyncReadExt, net::windows::named_pipe::ServerOptions, time::timeout};
use windows::Win32::{
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    },
    System::LibraryLoader::{GetProcAddress, LoadLibraryW},
};
use windows_core::{HSTRING, PCWSTR, s, w};
use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE};

struct Registered(windows::Win32::Foundation::HMODULE);

impl Registered {
    fn new(pipe_suffix: &str) -> Self {
        let dll = std::env::var("RAMSI_DLL").unwrap_or_else(|_| {
            let dir = std::env::current_exe().unwrap();
            dir.parent()
                .unwrap()
                .join("..\\ramsi_com.dll")
                .display()
                .to_string()
        });
        unsafe {
            let module = LoadLibraryW(&HSTRING::from(dll)).unwrap();
            let register: unsafe extern "system" fn(PCWSTR) -> i32 = std::mem::transmute(
                GetProcAddress(module, s!("DllRegisterServerWithPipe")).unwrap(),
            );
            let suffix = HSTRING::from(pipe_suffix);
            assert_eq!(register(PCWSTR(suffix.as_ptr())), 0);
            Self(module)
        }
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        unsafe {
            let unregister: unsafe extern "system" fn() -> i32 =
                std::mem::transmute(GetProcAddress(self.0, s!("DllUnregisterServer")).unwrap());
            unregister();
        }
        let _ = config().delete_value("mode");
        let _ = config().delete_value("rules");
        let _ = config().delete_value("pipe");
        let _ = std::fs::remove_file(rules_path());
    }
}

const MARKER: &str = "ramsi-e2e-marker";

fn rules_path() -> std::path::PathBuf {
    std::env::temp_dir().join("ramsi-e2e-rules.toml")
}

fn config() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
        .create_subkey(CONFIG_KEY)
        .unwrap()
        .0
}

#[tokio::test]
#[ignore]
async fn powershell_is_blocked_and_reported() {
    let suffix = format!("ramsi-e2e-{}", std::process::id());
    // owned by Administrators like the ramsi-cli pipe, or the provider will not
    // connect
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    let mut server = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("O:BAD:(A;OICI;GA;;;BA)(A;OICI;GRGWGX;;;AU)"),
            SDDL_REVISION_1,
            &mut attributes.lpSecurityDescriptor as *mut _ as _,
            None,
        )
        .unwrap();
        ServerOptions::new()
            .create_with_security_attributes_raw(
                format!(r"\\.\pipe\{suffix}"),
                &mut attributes as *mut _ as _,
            )
            .unwrap()
    };
    let _registered = Registered::new(&suffix);
    config().set_value("mode", &"block").unwrap();
    // a keyword only this provider knows, other providers on the machine may block
    // first
    std::fs::write(rules_path(), format!("blacklist_keywords = [\"{MARKER}\"]")).unwrap();
    config()
        .set_value("rules", &rules_path().display().to_string())
        .unwrap();

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!("Write-Output '{MARKER}'"),
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "not blocked: {stderr}");
    assert!(stderr.contains("malicious"), "{stderr}");

    let event: ScanEvent = timeout(Duration::from_secs(10), async {
        server.connect().await.unwrap();
        // module loading may report suspicious events first
        loop {
            let len = server.read_u64().await.unwrap();
            let mut buf = vec![0; len as usize];
            server.read_exact(&mut buf).await.unwrap();
            let event: ScanEvent = serde_json::from_slice(&buf).unwrap();
            if event.status == ScanStatus::Detected {
                break event;
            }
        }
    })
    .await
    .expect("no event on the pipe");

    assert_eq!(event.status, ScanStatus::Detected);
    assert!(event.blocked);
    assert!(event.content.contains(MARKER), "{event:?}");
    assert_eq!(event.process, "powershell.exe");
}

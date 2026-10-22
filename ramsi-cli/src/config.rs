use std::path::{Path, PathBuf};

use shared::{
    DynResult, PipeName,
    constants::{CONFIG_KEY, DEFAULT_LOG_DIR, RAMSI_CLSID, RAMSI_PIPE_SUFFIX, config_value::*},
};
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::{
        ACL,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
            SetNamedSecurityInfoW,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    },
};
use windows_core::{BOOL, HSTRING};
use winreg::{RegKey, RegValue, enums::*};

// SYSTEM and admins: full; users: create files they own, not read others' logs
// and dumps
const LOG_DIR_SDDL: &str =
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1000a2;;;AU)(A;OICIIO;FA;;;CO)";

enum Kind {
    Text,
    Dword,
    Choice(&'static [&'static str]),
}

const VALUES: &[(&str, Kind)] = &[
    (MODE, Kind::Choice(&["monitor", "block"])),
    (BLOCK_ON, Kind::Choice(&["detected", "suspicious"])),
    (REPORT, Kind::Dword),
    (APPS, Kind::Text),
    (
        LOG_LEVEL,
        Kind::Choice(&["off", "error", "warn", "info", "debug", "trace"]),
    ),
    (LOG_DIR, Kind::Text),
    (DUMP, Kind::Dword),
    (MAX_CONTENT, Kind::Dword),
    (PIPE, Kind::Text),
    (RULES, Kind::Text),
];

fn hklm() -> RegKey {
    RegKey::predef(HKEY_LOCAL_MACHINE)
}

fn kind(name: &str) -> DynResult<&'static Kind> {
    VALUES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, kind)| kind)
        .ok_or_else(|| {
            let names: Vec<_> = VALUES.iter().map(|(n, _)| *n).collect();
            format!(
                "Unknown value \"{name}\", expected one of: {}",
                names.join(", ")
            )
            .into()
        })
}

pub fn pipe_suffix() -> String {
    hklm()
        .open_subkey(CONFIG_KEY)
        .and_then(|key| key.get_value(PIPE))
        .unwrap_or_else(|_| RAMSI_PIPE_SUFFIX.to_string())
}

pub fn secure_log_dir() -> DynResult<PathBuf> {
    let dir: PathBuf = hklm()
        .open_subkey(CONFIG_KEY)
        .and_then(|key| key.get_value::<String, _>(LOG_DIR))
        .unwrap_or_else(|_| DEFAULT_LOG_DIR.to_string())
        .into();
    secure_dir(&dir)?;
    Ok(dir)
}

fn secure_dir(dir: &Path) -> DynResult<()> {
    std::fs::create_dir_all(dir)?;
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(LOG_DIR_SDDL),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let res =
            GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted).and_then(|_| {
                SetNamedSecurityInfoW(
                    &HSTRING::from(dir.as_os_str()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(dacl),
                    None,
                )
                .ok()
            });
        LocalFree(Some(HLOCAL(sd.0)));
        res?;
    }
    Ok(())
}

pub fn set(name: &str, value: &str) -> DynResult<()> {
    let (key, _) = hklm().create_subkey(CONFIG_KEY)?;
    match kind(name)? {
        Kind::Dword => {
            let value: u32 = match value {
                "true" => 1,
                "false" => 0,
                _ => value.parse()?,
            };
            key.set_value(name, &value)?;
        },
        Kind::Choice(choices) if !choices.contains(&value) => {
            return Err(format!("Expected one of: {}", choices.join(", ")).into());
        },
        _ if name == PIPE => {
            PipeName::from_suffix(value).verify()?;
            key.set_value(name, &value)?;
        },
        _ => key.set_value(name, &value)?,
    }
    println!("{name} = {value} (applies to processes started from now on)");
    Ok(())
}

pub fn unset(name: &str) -> DynResult<()> {
    kind(name)?;
    let key = hklm().open_subkey_with_flags(CONFIG_KEY, KEY_SET_VALUE)?;
    match key.delete_value(name) {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => Err(err.into()),
        _ => Ok(()),
    }
}

pub fn show() -> DynResult<()> {
    let key = hklm().open_subkey(CONFIG_KEY).ok();
    println!("HKLM\\{CONFIG_KEY}");
    for (name, _) in VALUES {
        let value = key
            .as_ref()
            .and_then(|key| key.get_raw_value(name).ok())
            .map(display)
            .unwrap_or_else(|| "<default>".to_string());
        println!("  {name:<12} {value}");
    }
    Ok(())
}

fn display(value: RegValue) -> String {
    match value.vtype {
        REG_DWORD if value.bytes.len() == 4 => {
            u32::from_le_bytes(value.bytes.try_into().unwrap()).to_string()
        },
        _ => value.to_string(),
    }
}

pub fn status() -> DynResult<()> {
    let server = hklm()
        .open_subkey(format!(
            "Software\\Classes\\CLSID\\{RAMSI_CLSID}\\InProcServer32"
        ))
        .and_then(|key| key.get_value::<String, _>(""));
    let provider = hklm()
        .open_subkey(format!(
            "Software\\Microsoft\\AMSI\\Providers\\{RAMSI_CLSID}"
        ))
        .is_ok();
    match (server, provider) {
        (Ok(dll), true) => println!("Registered: {dll}"),
        (Ok(dll), false) => println!("COM server registered ({dll}), AMSI provider key missing"),
        (Err(_), _) => println!("Not registered"),
    }
    show()
}

#[cfg(test)]
mod tests {
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
    };
    use windows_core::PWSTR;

    use super::*;

    #[test]
    fn secured_dir_has_protected_dacl() {
        // reused across runs, never removed
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/acl-test");
        secure_dir(&dir).unwrap();

        let sddl = unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            GetNamedSecurityInfoW(
                &HSTRING::from(dir.as_os_str()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut sd,
            )
            .ok()
            .unwrap();
            let mut text = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
            .unwrap();
            let sddl = text.to_string().unwrap();
            LocalFree(Some(HLOCAL(text.0 as _)));
            LocalFree(Some(HLOCAL(sd.0)));
            sddl
        };

        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(sddl.contains("(A;OICIIO;FA;;;CO)"), "{sddl}");
        assert!(!sddl.contains(";;;BU)"), "{sddl}");
    }
}

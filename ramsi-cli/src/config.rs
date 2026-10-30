use std::path::Path;

use shared::{
    DynResult, PipeName,
    constants::{
        CONFIG_KEY, LOG_DIR_SDDL, MAX_CONTENT_LIMIT, RAMSI_CLSID, RAMSI_PIPE_SUFFIX, RULES_SDDL,
        config_value::*,
    },
};
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::{
        ACL,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
            SetNamedSecurityInfoW,
        },
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID,
    },
};
use windows_core::{BOOL, HSTRING};
use winreg::{RegKey, RegValue, enums::*};

enum Kind {
    Text,
    Dword,
    Choice(&'static [&'static str]),
}

const VALUES: &[(&str, Kind)] = &[
    (MODE, Kind::Choice(&["monitor", "block"])),
    (BLOCK_ON, Kind::Choice(&["detected", "suspicious"])),
    (REPORT, Kind::Dword),
    (REPORT_ON, Kind::Choice(&["detected", "suspicious", "all"])),
    (APPS, Kind::Text),
    (COMMANDS, Kind::Text),
    (
        LOG_LEVEL,
        Kind::Choice(&["off", "error", "warn", "info", "debug", "trace"]),
    ),
    (LOG_DIR, Kind::Text),
    (DUMP, Kind::Dword),
    (MAX_CONTENT, Kind::Dword),
    (PIPE, Kind::Text),
    (RULES, Kind::Text),
    (BLOCK_PIDS_FILE, Kind::Text),
    (HEARTBEAT_SECS, Kind::Dword),
    (HEARTBEAT_PIDS_FILE, Kind::Text),
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

fn secure_dir(dir: &Path) -> DynResult<()> {
    std::fs::create_dir_all(dir)?;
    secure_path(dir, LOG_DIR_SDDL)
}

// applies the DACL of `sddl` and its owner, if it has one
fn secure_path(path: &Path, sddl: &str) -> DynResult<()> {
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(sddl),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut owner = PSID::default();
        let res = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted)
            .and_then(|_| GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted))
            .and_then(|_| {
                let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
                if !owner.is_invalid() {
                    info |= OWNER_SECURITY_INFORMATION;
                }
                SetNamedSecurityInfoW(
                    &HSTRING::from(path.as_os_str()),
                    SE_FILE_OBJECT,
                    info,
                    (!owner.is_invalid()).then_some(owner),
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
            if name == MAX_CONTENT && value > MAX_CONTENT_LIMIT {
                return Err(format!("{name} must be at most {MAX_CONTENT_LIMIT}").into());
            }
            key.set_value(name, &value)?;
        },
        Kind::Choice(choices) if !choices.contains(&value) => {
            return Err(format!("Expected one of: {}", choices.join(", ")).into());
        },
        _ if name == PIPE => {
            PipeName::from_suffix(value).verify()?;
            key.set_value(name, &value)?;
        },
        // providers log only to a dir owned by admins
        _ if name == LOG_DIR => {
            let path = std::path::absolute(value)?;
            secure_dir(&path)?;
            key.set_value(name, &path.display().to_string())?;
        },
        _ if name == RULES => {
            // providers load only a file that just admins can change
            let path = std::path::absolute(value)?;
            secure_path(&path, RULES_SDDL)?;
            key.set_value(name, &path.display().to_string())?;
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
    for (view, bits) in [
        (KEY_WOW64_64KEY, ""),
        (KEY_WOW64_32KEY, " for 32-bit processes"),
    ] {
        let open = |path: String| hklm().open_subkey_with_flags(path, KEY_READ | view);
        let server = open(format!(
            "Software\\Classes\\CLSID\\{RAMSI_CLSID}\\InProcServer32"
        ))
        .and_then(|key| key.get_value::<String, _>(""));
        let provider = open(format!(
            "Software\\Microsoft\\AMSI\\Providers\\{RAMSI_CLSID}"
        ))
        .is_ok();
        match (server, provider) {
            (Ok(dll), true) => println!("Registered{bits}: {dll}"),
            (Ok(dll), false) => {
                println!("COM server registered{bits} ({dll}), AMSI provider key missing")
            },
            (Err(_), _) => println!("Not registered{bits}"),
        }
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

    fn sddl_of(path: &Path) -> String {
        let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            GetNamedSecurityInfoW(
                &HSTRING::from(path.as_os_str()),
                SE_FILE_OBJECT,
                info,
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
                info,
                &mut text,
                None,
            )
            .unwrap();
            let sddl = text.to_string().unwrap();
            LocalFree(Some(HLOCAL(text.0 as _)));
            LocalFree(Some(HLOCAL(sd.0)));
            sddl
        }
    }

    #[test]
    fn secured_rules_file_is_owned_by_admins() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/acl-test-cli");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.toml");
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, "").unwrap();

        secure_path(&path, RULES_SDDL).unwrap();

        // AI: Windows marks the DACL as auto-inherited
        assert_eq!(sddl_of(&path).replace("D:PAI", "D:P"), RULES_SDDL);
    }

    #[test]
    fn secured_dir_has_protected_dacl() {
        // reused across runs, never removed
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/acl-test");
        secure_dir(&dir).unwrap();

        let sddl = sddl_of(&dir);
        assert!(sddl.contains("D:P"), "{sddl}");
        assert!(sddl.contains("(A;OICIIO;FA;;;CO)"), "{sddl}");
        assert!(!sddl.contains(";;;BU)"), "{sddl}");
    }
}

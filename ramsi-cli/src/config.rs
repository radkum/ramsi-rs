use shared::{
    DynResult, PipeName,
    constants::{CONFIG_KEY, RAMSI_CLSID, RAMSI_PIPE_SUFFIX, config_value::*},
};
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

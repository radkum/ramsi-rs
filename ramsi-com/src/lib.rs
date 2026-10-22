#![allow(non_snake_case)]

mod amsi_utils;
mod ramsi;
mod winapi;

use amsi_utils as utils;
use ramsi::{Ramsi, Ramsi_Impl};
pub use ramsi::{ScanResult, ScanStatus, Scanner, ScriptType};
use shared::{PipeName, constants::RAMSI_PIPE_SUFFIX};
use windows::Win32::{Foundation::HMODULE, System::LibraryLoader::DisableThreadLibraryCalls};
type Dword = u32;
type Lpvoid = *mut core::ffi::c_void;
type HResult = i32;

pub use shared::{dprintln, win_log};

pub const DLL_PROCESS_ATTACH: u32 = 1u32;
pub const DLL_PROCESS_DETACH: u32 = 0u32;
pub const DLL_THREAD_ATTACH: u32 = 2u32;
pub const DLL_THREAD_DETACH: u32 = 3u32;

use std::{path::Path, sync::OnceLock};

use windows_core::{GUID, PCWSTR};
use winreg::{RegKey, enums::*};

static MODULE_NAME: OnceLock<String> = OnceLock::new();

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HMODULE, reason: Dword, reserved: Lpvoid) -> bool {
    match reason {
        DLL_PROCESS_ATTACH => {
            win_log!("DLL_PROCESS_ATTACH");

            let _ = MODULE_NAME.set(winapi::get_curr_module_file_name(module));
            if let Err(err) = unsafe { DisableThreadLibraryCalls(module) } {
                win_log!("Failed to disable thread library calls: {:?}", err);
            }
        },
        // no teardown under the loader lock: the class factory is never released
        DLL_PROCESS_DETACH => {
            win_log!("DLL_PROCESS_DETACH (process exit: {})", !reserved.is_null())
        },
        DLL_THREAD_ATTACH => win_log!("DLL_THREAD_ATTACH"),
        _ => win_log!("unknown reason"),
    }

    true
}

#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HResult {
    win_log!("DllGetClassObject");
    let res = Ramsi_Impl::get_class_object(rclsid, riid, ppv);
    if res.is_err() {
        win_log!(
            "DllGetClassObject: res: {}, {}",
            res.message(),
            display_pointers(rclsid, riid, ppv)
        );
    }

    res.0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HResult {
    // keep loaded: the static class factory lives until DLL_PROCESS_DETACH
    win_log!("DllCanUnloadNow");
    windows::Win32::Foundation::S_FALSE.0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServerWithPipe(pipe_suffix: PCWSTR) -> HResult {
    //set pipe name to registry
    dprintln!("DllRegisterServerWithPipe");
    let pipe_suffix = (!pipe_suffix.is_null())
        .then(|| unsafe { pipe_suffix.to_string() }.ok())
        .flatten()
        .filter(|s| !s.is_empty());
    if let Err(err) = imp_register_server(pipe_suffix) {
        win_log!("{err:?}");
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> HResult {
    dprintln!("DllRegisterServer");
    if let Err(err) = imp_register_server(None) {
        win_log!("DllRegisterServer error: {err:?}");
        return -1;
    }
    0
}

fn imp_register_server(pipe_suffix: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let pipe_suffix = pipe_suffix.as_deref().unwrap_or(RAMSI_PIPE_SUFFIX);
    let pipe_name = PipeName::from_suffix(pipe_suffix);
    pipe_name.verify()?;

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    //set CLSID
    let uuid_path_string = format!("Software\\Classes\\CLSID\\{}", Ramsi::IID());
    win_log!("uuid_path {}", uuid_path_string);

    let uuid_path = Path::new(uuid_path_string.as_str());
    let (key, disp) = hklm.create_subkey(uuid_path)?;
    match disp {
        REG_CREATED_NEW_KEY => win_log!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => win_log!("An existing key has been opened"),
    }
    key.set_value("", &Ramsi::NAME)?;
    key.set_value("pipe", &pipe_name.suffix())?;

    // set InProcServer32
    let inproc_path = uuid_path.join("InProcServer32");
    win_log!("inproc_path {}", inproc_path.display());

    let (key, disp) = hklm.create_subkey(&inproc_path)?;
    match disp {
        REG_CREATED_NEW_KEY => win_log!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => win_log!("An existing key has been opened"),
    }

    key.set_value("", &MODULE_NAME.get().cloned().unwrap_or_default())?;
    key.set_value("ThreadingModel", &"Both")?;

    //set amsi provider
    let amsi_provider_path_string =
        format!("Software\\Microsoft\\AMSI\\Providers\\{}", Ramsi::IID());
    win_log!("uuid_path {}", uuid_path_string);

    let amsi_provider_path = Path::new(amsi_provider_path_string.as_str());
    let (key, disp) = hklm.create_subkey(amsi_provider_path)?;
    match disp {
        REG_CREATED_NEW_KEY => win_log!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => win_log!("An existing key has been opened"),
    }
    key.set_value("", &Ramsi::NAME)?;

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> HResult {
    dprintln!("DllUnregisterServer");
    if let Err(err) = imp_unregister_server() {
        win_log!("{err:?}");
        return -1;
    }
    0
}

fn imp_unregister_server() -> Result<(), Box<dyn std::error::Error>> {
    win_log!("DllUnregisterServer start");
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Unregister this CLSID as an anti-malware provider.
    let amsi_provider_path_string =
        format!("Software\\Microsoft\\AMSI\\Providers\\{}", Ramsi::IID());
    hklm.delete_subkey_all(amsi_provider_path_string)?;

    // Unregister this CLSID as a COM server.
    let CLSID_path = format!("Software\\Classes\\CLSID\\{}", Ramsi::IID());
    hklm.delete_subkey_all(CLSID_path)?;

    win_log!("DllUnregisterServer end");
    Ok(())
}

fn display_pointers(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> String {
    let rclsid = if rclsid.is_null() {
        "null".to_string()
    } else {
        format!("rclsid: {:?}", unsafe { *rclsid })
    };

    let riid = if riid.is_null() {
        "null".to_string()
    } else {
        format!("riid: {:?}", unsafe { *riid })
    };

    let ppv = if ppv.is_null() {
        "null".to_string()
    } else {
        format!("ppv: {:p}", unsafe { *ppv })
    };

    format!("rclsid: {rclsid}, riid: {riid}, ppv: {ppv}")
}

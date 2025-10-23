#![allow(non_snake_case)]
#![allow(static_mut_refs)]

mod ramsi;
mod winapi;

use ramsi::{Ramsi, Ramsi_Impl};
use shared::{PipeName, constants::RAMSI_PIPE_SUFFIX, ffi_string::FfiString};
use windows::Win32::{Foundation::HMODULE, System::LibraryLoader::DisableThreadLibraryCalls};
type Dword = u32;
type Lpvoid = *mut core::ffi::c_void;
type HResult = i32;

pub const DLL_PROCESS_ATTACH: u32 = 1u32;
pub const DLL_PROCESS_DETACH: u32 = 0u32;
pub const DLL_THREAD_ATTACH: u32 = 2u32;
pub const DLL_THREAD_DETACH: u32 = 3u32;

use std::path::Path;

use macros::{debug, dprintln};
use windows_core::GUID;
use winreg::{RegKey, enums::*};

static mut MODULE_NAME: Option<String> = None;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HMODULE, reason: Dword, _: Lpvoid) -> bool {
    match reason {
        DLL_PROCESS_ATTACH => {
            debug!("DLL_PROCESS_ATTACH");

            unsafe {
                MODULE_NAME = Some(winapi::get_curr_module_file_name(module));
                if let Err(err) = DisableThreadLibraryCalls(module) {
                    debug!("Failed to disable thread library calls: {:?}", err);
                }
                Ramsi_Impl::create();
            }
        },
        DLL_PROCESS_DETACH => {
            debug!("DLL_PROCESS_DETACH");
            let result = Ramsi_Impl::terminate();
            debug!("Ramsi_Impl::terminate result: {}", result);
        },
        DLL_THREAD_ATTACH => debug!("DLL_THREAD_ATTACH"),
        DLL_THREAD_DETACH => debug!("DLL_THREAD_DETACH"),
        _ => debug!("unknows reason"),
    }

    true
}

#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut core::ffi::c_void,
) -> HResult {
    debug!("DllGetClassObject");
    let res = Ramsi_Impl::get_class_object(rclsid, riid, ppv);
    if res.is_err() {
        debug!(
            "DllGetClassObject: res: {}, {}",
            res.message(),
            display_pointers(rclsid, riid, ppv)
        );
    }

    res.0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HResult {
    //terminate
    debug!("DllCanUnloadNow");
    let result = Ramsi_Impl::terminate();
    debug!("Ramsi_Impl::terminate result: {}", result);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServerWithPipe(pipe_suffix: FfiString) -> HResult {
    //set pipe name to registry
    dprintln!("DllRegisterServerWithPipe");
    if let Err(err) = imp_register_server(pipe_suffix.into_string()) {
        debug!("{err:?}");
        return -1;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> HResult {
    dprintln!("DllRegisterServer");
    if let Err(err) = imp_register_server(None) {
        debug!("DllRegisterServer error: {err:?}");
        return -1;
    }
    0
}

fn imp_register_server(pipe_suffix: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let pipe_suffix = pipe_suffix.as_deref().unwrap_or(RAMSI_PIPE_SUFFIX);
    let pipe_name = PipeName::from_suffix(pipe_suffix);
    pipe_name.verify()?;

    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);

    //set CLSID
    let uuid_path_string = format!("Software\\Classes\\CLSID\\{}", Ramsi::IID());
    debug!("uuid_path {}", uuid_path_string);

    let uuid_path = Path::new(uuid_path_string.as_str());
    let (key, disp) = hkcu.create_subkey(uuid_path)?;
    match disp {
        REG_CREATED_NEW_KEY => debug!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => debug!("An existing key has been opened"),
    }
    key.set_value("", &Ramsi::NAME)?;
    key.set_value("pipe", &pipe_name.suffix())?;

    // set InProcServer32
    let inproc_path = uuid_path.join("InProcServer32");
    debug!("inproc_path {}", inproc_path.display());

    let (key, disp) = hkcu.create_subkey(&inproc_path)?;
    match disp {
        REG_CREATED_NEW_KEY => debug!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => debug!("An existing key has been opened"),
    }

    let module_name = unsafe { MODULE_NAME.clone() };
    key.set_value("", &module_name.unwrap_or_default())?;
    key.set_value("ThreadingModel", &"Both")?;

    //set amsi provider
    let amsi_provider_path_string =
        format!("Software\\Microsoft\\AMSI\\Providers\\{}", Ramsi::IID());
    debug!("uuid_path {}", uuid_path_string);

    let amsi_provider_path = Path::new(amsi_provider_path_string.as_str());
    let (key, disp) = hkcu.create_subkey(amsi_provider_path)?;
    match disp {
        REG_CREATED_NEW_KEY => debug!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => debug!("An existing key has been opened"),
    }
    key.set_value("", &Ramsi::NAME)?;

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> HResult {
    dprintln!("DllUnregisterServer");
    if let Err(err) = imp_unregister_server() {
        debug!("{err:?}");
        return -1;
    }
    0
}

fn imp_unregister_server() -> Result<(), Box<dyn std::error::Error>> {
    debug!("DllUnregisterServer start");
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);

    // Unregister this CLSID as an anti-malware provider.
    let amsi_provider_path_string =
        format!("Software\\Microsoft\\AMSI\\Providers\\{}", Ramsi::IID());
    hkcu.delete_subkey_all(amsi_provider_path_string)?;

    // Unregister this CLSID as a COM server.
    let CLSID_path = format!("Software\\Classes\\CLSID\\{}", Ramsi::IID());
    hkcu.delete_subkey_all(CLSID_path)?;

    debug!("DllUnregisterServer end");
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

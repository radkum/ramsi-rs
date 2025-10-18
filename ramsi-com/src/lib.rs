#![allow(non_snake_case)]
#![allow(static_mut_refs)]

mod ramsi;
mod winapi;

use ramsi::{Ramsi, Ramsi_Impl};

use windows_sys::Win32::{Foundation::HMODULE, System::LibraryLoader::DisableThreadLibraryCalls};

type DWORD = u32;
type LPVOID = *mut core::ffi::c_void;
type HRESULT = i32;

pub const DLL_PROCESS_ATTACH: u32 = 1u32;
pub const DLL_PROCESS_DETACH: u32 = 0u32;
pub const DLL_THREAD_ATTACH: u32 = 2u32;
pub const DLL_THREAD_DETACH: u32 = 3u32;

use std::path::Path;

use windows_core::GUID;
use winreg::{RegKey, enums::*};

use macros::{debug, dprintln};

static mut MODULE_NAME: Option<String> = None;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(module: HMODULE, reason: DWORD, _: LPVOID) -> bool {
    match reason {
        DLL_PROCESS_ATTACH => {
            debug!("DLL_PROCESS_ATTACH");

            unsafe {
                MODULE_NAME = Some(winapi::get_curr_module_file_name(module));
                DisableThreadLibraryCalls(module);
                Ramsi_Impl::create();
            }
        },
        DLL_PROCESS_DETACH => {
            debug!("DLL_PROCESS_DETACH");
            Ramsi_Impl::terminate();
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
) -> HRESULT {
    debug!("DllGetClassObject");
    let res = Ramsi_Impl::get_class_object(rclsid, riid, ppv).0;
    unsafe {
        debug!(
            "res: 0x{:08x}, rclsid: {:?}, riid: {:?}, ppv:{:p}",
            res, *rclsid, *riid, *ppv
        );
    }
    res
}

#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    //terminate
    debug!("DllCanUnloadNow");
    Ramsi_Impl::terminate();
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    dprintln!("DllRegisterServer");
    if let Err(err) = imp_register_server() {
        debug!("{err:?}");
        return -1;
    }
    0
}

fn imp_register_server() -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);

    //set CLSID
    let uuid_path_string = format!("Software\\Classes\\CLSID\\{}", Ramsi::IID());
    debug!("uuid_path {}", uuid_path_string);

    let uuid_path = Path::new(uuid_path_string.as_str());
    let (key, disp) = hkcu.create_subkey(&uuid_path)?;
    match disp {
        REG_CREATED_NEW_KEY => debug!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => debug!("An existing key has been opened"),
    }
    key.set_value("", &Ramsi::NAME)?;

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
    let (key, disp) = hkcu.create_subkey(&amsi_provider_path)?;
    match disp {
        REG_CREATED_NEW_KEY => debug!("A new key has been created"),
        REG_OPENED_EXISTING_KEY => debug!("An existing key has been opened"),
    }
    key.set_value("", &Ramsi::NAME)?;

    Ok(())
}

#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
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

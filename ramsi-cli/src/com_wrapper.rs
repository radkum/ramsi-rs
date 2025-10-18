use anyhow::anyhow;
use macros::debug;
use windows::Win32::{
    Foundation::{FARPROC, FreeLibrary, GetLastError, HMODULE},
    System::{
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Ole::{OleInitialize, OleUninitialize},
    },
};
use windows_core::PCSTR;

type DynError = Box<dyn std::error::Error>;

pub struct RamsiComWrapper(ComWrapper);
impl RamsiComWrapper {
    pub fn new(com_name: &str) -> Result<Self, DynError> {
        let com_wrapper = ComWrapper::new(com_name)?;
        com_wrapper.register()?;
        Ok(Self(com_wrapper))
    }
}

impl Drop for RamsiComWrapper {
    fn drop(&mut self) {
        if let Err(err) = self.0.unregister() {
            debug!("{err:?}")
        }
    }
}

pub struct ComWrapper(DllWrapper);

impl ComWrapper {
    const DLL_REGISTER_SERVER: &str = "DllRegisterServer";
    const DLL_UNREGISTER_SERVER: &str = "DllUnregisterServer";

    pub fn new(com_name: &str) -> Result<Self, DynError> {
        unsafe { OleInitialize(None)? };

        Ok(Self(DllWrapper::new(com_name)?))
    }

    pub fn register(&self) -> Result<(), DynError> {
        let fn_reg_opt = self.0.load_fn(Self::DLL_REGISTER_SERVER);
        let fn_reg = fn_reg_opt.ok_or(last_error("Failed to load DLL_REGISTER_SERVER fn"))?;
        unsafe { fn_reg() };
        Ok(())
    }

    pub fn unregister(&self) -> Result<(), DynError> {
        let fn_unreg_opt = self.0.load_fn(Self::DLL_UNREGISTER_SERVER);
        let fn_unreg = fn_unreg_opt.ok_or(last_error("Failed to load DLL_UNREGISTER_SERVER fn"))?;
        unsafe { fn_unreg() };
        Ok(())
    }
}

impl Drop for ComWrapper {
    fn drop(&mut self) {
        unsafe { OleUninitialize() };
    }
}

struct DllWrapper(HMODULE);
impl DllWrapper {
    pub fn new(dll_name: &str) -> Result<Self, DynError> {
        let c_dll_name = to_c_str(dll_name);
        let hmod = unsafe { LoadLibraryA(PCSTR::from_raw(c_dll_name.as_ptr())) }?;
        if hmod.is_invalid() {
            return Err(last_error("Failed to load library"));
        }
        Ok(Self(hmod))
    }

    // pub fn hmod(&self) -> HMODULE {
    //     self.0
    // }

    pub fn load_fn(&self, proc_name: &str) -> FARPROC {
        let module = self.0;
        if module.is_invalid() {
            None
        } else {
            let vec_proc_name = to_c_str(proc_name);
            unsafe { GetProcAddress(module, PCSTR::from_raw(vec_proc_name.as_ptr())) }
        }
    }
}

impl Drop for DllWrapper {
    fn drop(&mut self) {
        if let Err(err) = unsafe { FreeLibrary(self.0) } {
            debug!("Failed to free library: {:?}", err);
        }
    }
}

fn to_c_str(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn last_error(msg: &str) -> DynError {
    anyhow!("{msg}. LastError: {}", unsafe {
        GetLastError().to_hresult()
    })
    .into()
}

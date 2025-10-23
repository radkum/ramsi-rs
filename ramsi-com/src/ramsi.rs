#![allow(non_camel_case_types)]

mod amsi_event;
mod pipe_client;
mod ramsi_impl;
use core::result::Result;
use std::{cell::RefCell, path::Path, sync::atomic::AtomicU32};

pub use amsi_event::AmsiEvent;
use amsi_event::ProcessInfo;
use macros::{debug, error};
use pipe_client::PipeClient;
use shared::{PipeName, constants::RAMSI_PIPE_SUFFIX};
use windows::Win32::System::{
    Antimalware::*,
    Com::{IClassFactory, IClassFactory_Impl},
};
use windows_core::*;
use winreg::{RegKey, enums::*};
// pub(super) static mut CLASS_FACTORY:
// std::sync::LazyLock<StaticComObject<Ramsi>> =     std::sync::LazyLock::new(||
// Ramsi::new().into_static());
pub(super) static mut CLASS_FACTORY: Option<StaticComObject<Ramsi>> = None;

#[interface("b8614e83-84ac-45fb-82a8-21711aaf07f2")]
unsafe trait IRamsi: IAntimalwareProvider2 {}

#[implement(IRamsi, IClassFactory)]

pub struct Ramsi {
    process_info: ProcessInfo,
    request_number: AtomicU32,
    pipe_client: RefCell<PipeClient>,
}

impl Ramsi {
    fn get_pipe_name() -> Result<String, Box<dyn std::error::Error>> {
        let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
        let uuid_path_string = format!("Software\\Classes\\CLSID\\{}", Ramsi::IID());
        let uuid_path = Path::new(uuid_path_string.as_str());
        let key = hkcu.open_subkey(uuid_path)?;
        let pipe_suffix: String = key.get_value("pipe")?;
        let pipe_name = PipeName::from_suffix(&pipe_suffix);
        pipe_name.verify()?;
        Ok(pipe_name.to_string())
    }

    pub fn new() -> Self {
        //read pipe name from registry
        let pipe_name = match Self::get_pipe_name() {
            Ok(name) => name,
            Err(err) => {
                error!("Failed to get pipe name: {err}");
                format!(r"\\.\pipe\{}", RAMSI_PIPE_SUFFIX)
            },
        };
        Self {
            process_info: ProcessInfo::current(),
            request_number: AtomicU32::new(0),
            pipe_client: RefCell::new(PipeClient::new(&pipe_name)),
        }
    }
}

impl IRamsi_Impl for Ramsi_Impl {}

impl IClassFactory_Impl for Ramsi_Impl {
    fn CreateInstance(
        &self,
        _: windows_core::Ref<'_, IUnknown>,
        iid: *const windows_core::GUID,
        interface: *mut *mut std::ffi::c_void,
    ) -> windows_core::Result<()> {
        Self::query_interface(iid, interface)
    }

    fn LockServer(&self, _: BOOL) -> windows_core::Result<()> {
        Ok(())
    }
}

impl Ramsi {
    pub const NAME: &str = "Ramsi";
    pub const DISPLAY_NAME: &[u16] = &[0x44u16, 0x61, 0x6D, 0x73, 0x69, 0x0]; //Ramsi
}

impl Ramsi {
    pub fn IID() -> String {
        format!("{{{:?}}}", IRamsi::IID)
    }
}

impl Ramsi_Impl {
    pub fn get_class_object(
        rclsid: *const ::windows_core::GUID,
        iid: *const ::windows_core::GUID,
        interface: *mut *mut ::core::ffi::c_void,
    ) -> windows_core::HRESULT {
        if rclsid.is_null() || IRamsi::IID != unsafe { *rclsid } {
            debug!(
                "Ramsi_Impl::get_class_object: Unsupported IID: {:?}",
                unsafe { *iid }
            );
            return windows_core::HRESULT(-2147221231); // E_NOINTERFACE
        }

        if let Err(r) = Self::query_interface(iid, interface) {
            debug!("Ramsi_Impl::get_class_object: {:?}", r);
            return r.into();
        }
        windows_core::HRESULT(0)
    }

    fn query_interface(
        iid: *const windows_core::GUID,
        interface: *mut *mut std::ffi::c_void,
    ) -> windows_core::Result<()> {
        let class_factory = unsafe { CLASS_FACTORY.as_ref() };
        let Some(class_factory) = class_factory else {
            debug!("Ramsi_Impl::get_class_object: CLASS_FACTORY is None");
            return Err(windows_core::HRESULT(-1).into());
        };
        let hr = unsafe { class_factory.QueryInterface(iid, interface) };
        if hr.is_err() {
            debug!("Ramsi_Impl::query_interface: {:?}", hr);
            return Err(hr.into());
        }

        Ok(())
    }

    pub fn create() {
        debug!("Ramsi_Impl::create");
        unsafe { CLASS_FACTORY = Some(Ramsi::new().into_static()) };
    }

    pub fn terminate() -> bool {
        let class_factory = unsafe { CLASS_FACTORY.take() };
        let Some(class_factory) = class_factory else {
            debug!("Ramsi_Impl::get_class_object: CLASS_FACTORY is None");
            return false;
        };
        let released = class_factory.count.release();
        debug!("Remaining: {released}");
        released == 0
    }
}

#![allow(non_camel_case_types)]

mod amsi_event;
mod pipe_client;
mod ramsi_impl;

pub use amsi_event::AmsiEvent;
use amsi_event::ProcessInfo;
use pipe_client::PipeClient;

use windows::Win32::System::{
    Antimalware::*,
    Com::{IClassFactory, IClassFactory_Impl},
};
use windows_core::*;

use std::{
    cell::RefCell,
    sync::{LazyLock, atomic::AtomicU32},
};

//pub(super) static mut CLASS_FACTORY: StaticComObject<Ramsi> = Ramsi {}.into_static();
pub(super) static mut CLASS_FACTORY: LazyLock<StaticComObject<Ramsi>> =
    LazyLock::new(|| Ramsi::new().into_static());

#[interface("25eace5d-da54-423b-819e-025895b7ba70")]
unsafe trait IRamsi: IAntimalwareProvider {}

#[implement(IRamsi, IClassFactory)]

pub struct Ramsi {
    pub process_info: ProcessInfo,
    pub request_number: AtomicU32,
    pub pipe: RefCell<PipeClient>,
}

impl Ramsi {
    pub fn new() -> Self {
        Self {
            process_info: ProcessInfo::current(),
            request_number: AtomicU32::new(0),
            pipe: RefCell::new(PipeClient::new(shared::constants::RAMSI_PIPE_NAME)),
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
        unsafe {
            let r = CLASS_FACTORY.query_interface(iid, interface);
            if r.is_err() {
                return Err(r.into());
            }
        }
        Ok(())
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
    pub fn query_interface(
        &self,
        iid: *const ::windows_core::GUID,
        interface: *mut *mut ::core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe { self.QueryInterface(iid, interface) }
    }

    pub fn get_class_object(
        _rclsid: *const ::windows_core::GUID,
        iid: *const ::windows_core::GUID,
        interface: *mut *mut ::core::ffi::c_void,
    ) -> windows_core::HRESULT {
        unsafe { CLASS_FACTORY.QueryInterface(iid, interface) }
    }

    pub fn create() {
        // should I implement this?
    }

    pub fn terminate() {
        unsafe {
            let _released = CLASS_FACTORY.count.release();
            //dprintln!("relase: {_released}");
        }
    }
}

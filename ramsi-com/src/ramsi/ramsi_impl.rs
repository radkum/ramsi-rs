use std::{
    ffi::c_void,
    mem::zeroed,
    sync::{LazyLock, atomic::Ordering},
};

use shared::RamsiMessage;
use tokio::runtime::Runtime;
use windows::Win32::System::Antimalware::*;
use windows_core::{PCSTR, PWSTR, Result as WindowsResult};

use super::{AmsiEvent, Ramsi, Ramsi_Impl};
use crate::{debug, dprintln, winapi::E_NOT_SUFFICIENT_BUFFER};

pub(super) static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| Runtime::new().unwrap());

use macros::error;

impl Ramsi_Impl {
    fn u64_attribute<T>(s: &IAmsiStream, attribute: AMSI_ATTRIBUTE) -> T {
        unsafe {
            #[allow(unused_assignments)]
            let mut result: T = zeroed();

            let mut size: u32 = 0;
            let mut vec = vec![0; size_of::<T>()];

            if let Err(_err) = s.GetAttribute(attribute, vec.as_mut_slice(), &mut size) {
                debug!(
                    "get_fixed_size_attribute error: 0x{:08x}, msg: {}, size: {size}",
                    _err.code().0,
                    _err.message()
                )
            }
            result = std::ptr::read(vec.as_ptr() as *const _);

            if size as usize != size_of::<T>() {
                debug!("get_fixed_size_attribute incorrect size");
            }

            result
        }
    }

    pub fn string_from_vec(mut buff: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
        let pwstr = PWSTR::from_raw(buff.as_mut_ptr() as *mut u16);
        unsafe {
            match pwstr.to_string() {
                Ok(s) => Ok(s),
                Err(e) => {
                    error!("Failed convert vector to wstring: {}", e);
                    Ok(PCSTR::from_raw(buff.as_mut_ptr()).to_string()?)
                },
            }
        }

        // let u16_buffer = unsafe { buf.align_to_mut::<u16>().1 };

        // let mut ends_with_null = false;
        // if let Some(c) = u16_buffer.last() && *c == 0 {
        //     ends_with_null = true;
        // }

        // let mut res_string = String::from_utf16_lossy(u16_buffer);
        // if ends_with_null {
        //     res_string.pop();
        // }

        // res_string
    }

    fn string_attribute(s: &IAmsiStream, attribute: AMSI_ATTRIBUTE) -> String {
        Self::impl_string_attribute(s, attribute).unwrap_or_else(|e| {
            error!("Failed to get string attribute {:?}: {}", attribute, e);
            "<empty>".to_string()
        })
    }

    fn impl_string_attribute(
        s: &IAmsiStream,
        attribute: AMSI_ATTRIBUTE,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut alloc_size: u32 = 0;
        let mut buf = Vec::new();

        unsafe {
            if let Err(err) = s.GetAttribute(attribute, buf.as_mut_slice(), &mut alloc_size)
                && err.code().0 == E_NOT_SUFFICIENT_BUFFER
            {
                buf.resize(alloc_size as usize, 0);
            }
            s.GetAttribute(attribute, buf.as_mut_slice(), &mut alloc_size)?;
            Self::string_from_vec(buf)
        }
    }

    fn get_content(s: &IAmsiStream) -> Vec<u8> {
        let content_size = Self::u64_attribute::<u64>(s, AMSI_ATTRIBUTE_CONTENT_SIZE) as usize;
        let content_ptr = Self::u64_attribute::<*mut c_void>(s, AMSI_ATTRIBUTE_CONTENT_ADDRESS);
        let mut out_buf = vec![0; content_size];

        unsafe {
            std::ptr::copy_nonoverlapping(
                content_ptr,
                out_buf.as_mut_ptr() as *mut _,
                content_size,
            );
        }

        out_buf
    }
}

impl IAntimalwareProvider2_Impl for Ramsi_Impl {
    fn Notify(
        &self,
        _buffer: *const core::ffi::c_void,
        length: u32,
        _contentname: &windows_core::PCWSTR,
        appname: &windows_core::PCWSTR,
    ) -> windows_core::Result<AMSI_RESULT> {
        debug!("Ramsi::Notify: length: {length}, app_name: {}", unsafe {
            appname.to_string().unwrap_or_default()
        });

        Ok(AMSI_RESULT_NOT_DETECTED)
    }
}

impl IAntimalwareProvider_Impl for Ramsi_Impl {
    fn Scan(&self, stream: windows_core::Ref<'_, IAmsiStream>) -> WindowsResult<AMSI_RESULT> {
        debug!("Ramsi::Scan");

        let amsi_event = if let Some(s) = stream.as_ref() {
            let app_name = Self::string_attribute(s, AMSI_ATTRIBUTE_APP_NAME);
            let content_name = Self::string_attribute(s, AMSI_ATTRIBUTE_CONTENT_NAME);
            let session = Self::u64_attribute::<u64>(s, AMSI_ATTRIBUTE_SESSION);
            let content = Self::get_content(s);
            let process_info = self.process_info.clone();

            let request_num = self.request_number.load(Ordering::Acquire) + 1;
            self.request_number.store(request_num, Ordering::Release);

            AmsiEvent::new(
                process_info,
                app_name,
                content_name,
                content,
                session,
                request_num,
            )
        } else {
            Default::default()
        };

        dprintln!("{}", amsi_event);
        if let Err(e) = amsi_event.dump() {
            dprintln!("{e}");
        }

        RUNTIME.block_on(async {
            if !self.pipe_client.borrow().active()
                && let Err(err) = self.pipe_client.borrow_mut().connect()
            {
                error!("{err}");
                return;
            }

            let res = self
                .pipe_client
                .borrow_mut()
                .send(RamsiMessage::new(&amsi_event.to_string()))
                .await;

            if let Err(e) = res {
                error!("{e}");
            }
        });

        Ok(AMSI_RESULT_NOT_DETECTED)
    }

    fn CloseSession(&self, id: u64) {
        debug!("Ramsi::CloseSession: {}", id);
    }

    fn DisplayName(&self) -> WindowsResult<PWSTR> {
        debug!("Ramsi::DisplayName");
        let amsi = Ramsi::DISPLAY_NAME.as_ptr();
        Ok(PWSTR(amsi as *mut u16))
    }
}

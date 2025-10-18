use std::{ffi::c_void, mem::zeroed};

use super::{AmsiEvent, Ramsi, Ramsi_Impl};

use crate::{debug, dprintln, winapi::E_NOT_SUFFICIENT_BUFFER};

use shared::RamsiMessage;
use std::sync::atomic::Ordering;
use tokio::runtime::Runtime;
use windows::Win32::System::Antimalware::*;
use windows_core::PWSTR;
use windows_core::Result as WindowsResult;

use std::sync::LazyLock;

pub(super) static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| Runtime::new().unwrap());

use macros::error;

impl Ramsi_Impl {
    fn u64_attribute<T>(s: &IAmsiStream, attribute: AMSI_ATTRIBUTE) -> T {
        unsafe {
            #[allow(unused_assignments)]
            let mut result: T = zeroed();

            let mut size: u32 = 0;
            let mut vec = Vec::new();
            vec.resize(size_of::<T>(), 0);

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

    pub fn string_from_vec(mut buf: Vec<u8>) -> String {
        let u16_buffer = unsafe { buf.align_to_mut::<u16>().1 };

        let mut ends_with_null = false;
        if let Some(c) = u16_buffer.last() {
            if *c == 0 {
                ends_with_null = true;
            }
        }

        let mut res_string = String::from_utf16_lossy(u16_buffer);
        if ends_with_null {
            res_string.pop();
        }

        return res_string;
    }

    fn string_attribute(s: &IAmsiStream, attribute: AMSI_ATTRIBUTE) -> String {
        let mut alloc_size: u32 = 0;
        let mut buf = Vec::new();

        unsafe {
            if let Err(err) = s.GetAttribute(attribute, buf.as_mut_slice(), &mut alloc_size) {
                if err.code().0 == E_NOT_SUFFICIENT_BUFFER {
                    buf.resize(alloc_size as usize, 0);

                    if let Err(err) = s.GetAttribute(attribute, buf.as_mut_slice(), &mut alloc_size)
                    {
                        debug!(
                            "get_string_attribute error: 0x{:08x}, msg: {}",
                            err.code().0,
                            err.message()
                        );
                        return String::new();
                    }

                    return Self::string_from_vec(buf);
                }
            }
        }
        String::new()
    }

    fn get_content(s: &IAmsiStream) -> Vec<u8> {
        let content_size = Self::u64_attribute::<u64>(s, AMSI_ATTRIBUTE_CONTENT_SIZE) as usize;
        let content_ptr = Self::u64_attribute::<*mut c_void>(s, AMSI_ATTRIBUTE_CONTENT_ADDRESS);
        let mut out_buf = Vec::with_capacity(content_size);
        out_buf.resize(content_size, 0);

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

impl IAntimalwareProvider_Impl for Ramsi_Impl {
    fn Scan(
        &self,
        stream: windows_core::Ref<'_, IAmsiStream>,
    ) -> WindowsResult<AMSI_RESULT> {
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

        // if !self.pipe.borrow_mut().active() {
        //     self.pipe.borrow_mut().connect().await;
        // }

        RUNTIME.block_on(async {
            if !self.pipe.borrow().active() {
                self.pipe.borrow_mut().connect().await;
            }

            let res = self
                .pipe
                .borrow_mut()
                .send(RamsiMessage::new(&amsi_event.content_name()))
                .await;

            if let Err(e) = res {
                error!("{e}");
            }
        });

        Ok(AMSI_RESULT_NOT_DETECTED)
    }

    fn CloseSession(&self, _: u64) {
        debug!("Ramsi::CloseSession");
    }

    fn DisplayName(&self) -> WindowsResult<PWSTR> {
        debug!("Ramsi::DisplayName");
        let amsi = Ramsi::DISPLAY_NAME.as_ptr();
        Ok(PWSTR(amsi as *mut u16))
    }
}

use std::{
    ffi::c_void,
    mem::{size_of, zeroed},
};

use log::{debug, error};
use windows::Win32::System::Antimalware::*;

use super::Ramsi_Impl;
use crate::{utils::AmsiString, winapi::E_NOT_SUFFICIENT_BUFFER};

impl Ramsi_Impl {
    pub fn u64_attribute<T>(s: &IAmsiStream, attribute: AMSI_ATTRIBUTE) -> T {
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

    pub fn string_attribute(s: &IAmsiStream, attribute: AMSI_ATTRIBUTE) -> String {
        let mut alloc_size: u32 = 0;
        let mut buf = Vec::new();

        unsafe {
            if let Err(err) = s.GetAttribute(attribute, buf.as_mut_slice(), &mut alloc_size)
                && err.code().0 == E_NOT_SUFFICIENT_BUFFER
            {
                buf.resize(alloc_size as usize, 0);
            }

            if let Err(err) = s.GetAttribute(attribute, buf.as_mut_slice(), &mut alloc_size) {
                error!(
                    "GetAttribute error: 0x{:08x}, msg: {}, size: {alloc_size}",
                    err.code().0,
                    err.message()
                );
                return String::new();
            }
            AmsiString::from(buf).into()
        }
    }

    pub fn get_content(s: &IAmsiStream) -> String {
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

        AmsiString::from(out_buf).into()
    }
}

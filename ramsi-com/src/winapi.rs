#![allow(clippy::upper_case_acronyms)]

use windows::Win32::{
    Foundation::{HMODULE, UNICODE_STRING},
    System::LibraryLoader::GetModuleFileNameA,
};
use windows_core::PWSTR;
pub type PVOID = *mut std::os::raw::c_void;
pub type DWORD = u32;
pub type LPVOID = PVOID;
pub type ULONG = ::std::os::raw::c_ulong;
pub type PULONG = *mut ULONG;
pub type BYTE = ::std::os::raw::c_uchar;
// pub type wchar_t = ::std::os::raw::c_ushort;
// pub type WCHAR = wchar_t;
// pub type LPWSTR = *mut WCHAR;
// pub type ULONGLONG = ::std::os::raw::c_ulonglong;
// pub type UINT = u32;
// pub type HRESULT = windows::Win32::Foundation::LRESULT;
// pub type CHAR = char;
// pub type LPSTR = *mut CHAR;
use core::ffi::c_void;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
use windows::Win32::{
    Foundation::*,
    System::{Diagnostics::Debug::*, Threading::*},
};

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        ProcessHandle: HANDLE,
        ProcessInformationClass: DWORD,
        ProcessInformation: *mut c_void,
        ProcessInformationLength: ULONG,
        ReturnLength: PULONG,
    ) -> u32;
}

#[allow(overflowing_literals)]
pub const E_NOT_SUFFICIENT_BUFFER: i32 = 0x8007007a_i32;

pub fn get_curr_module_file_name(module: HMODULE) -> String {
    let mut filename_buf = [0u8; 255];
    let filename_len = unsafe { GetModuleFileNameA(Some(module), filename_buf.as_mut_slice()) };
    if filename_len == 0 {
        String::from("unknown")
    } else {
        String::from_utf8_lossy(&filename_buf[..filename_len as usize]).to_string()
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct PROCESS_BASIC_INFORMATION {
    pub Reserved1: LPVOID,
    PebBaseAddress: *mut PEB,
    Reserved2: [LPVOID; 2],
    UniqueProcessId: ULONG,
    pub InheritedFromUniqueProcessId: LPVOID,
}

#[allow(dead_code, non_snake_case, clippy::upper_case_acronyms)]
#[repr(C)]
struct PEB {
    Reserved1: [BYTE; 2],
    BeingDebugged: BYTE,
    Reserved2: [BYTE; 1],
    Reserved3: [LPVOID; 2],
    Ldr: *mut c_void,
    ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    Reserved4: [LPVOID; 3],
    AtlThunkSListPtr: LPVOID,
    Reserved5: LPVOID,
    Reserved6: ULONG,
    Reserved7: LPVOID,
    Reserved8: ULONG,
    AtlThunkSListPtr32: ULONG,
    Reserved9: [LPVOID; 45],
    Reserved10: [BYTE; 96],
    PostProcessInitRoutine: *mut c_void,
    Reserved11: [BYTE; 128],
    Reserved12: [LPVOID; 1],
    SessionId: ULONG,
}

#[allow(dead_code, non_snake_case, non_camel_case_types)]
#[repr(C)]
struct RTL_USER_PROCESS_PARAMETERS {
    Reserved1: [BYTE; 16],
    Reserved2: [LPVOID; 10],
    ImagePathName: UNICODE_STRING,
    CommandLine: UNICODE_STRING,
}

pub fn get_command_line_from_pid(pid: u32) -> Result<String> {
    let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid)? };
    let pbi = process_basic_information(handle)?;

    let peb: PEB = read_memory(handle, pbi.PebBaseAddress as _)?;

    let params: RTL_USER_PROCESS_PARAMETERS = read_memory(handle, peb.ProcessParameters as _)?;

    if params.CommandLine.Buffer.is_null() {
        return Err("Command line is null".to_string().into());
    }
    // UNICODE_STRING.Length is already in bytes, not characters.
    // Multiplying by 2 would read beyond the actual buffer causing truncation.
    let data = read_bytes(
        handle,
        params.CommandLine.Buffer.as_ptr() as _,
        params.CommandLine.Length as usize,
    )?;

    let wide = PWSTR::from_raw(data.as_ptr() as _);

    unsafe { wide.to_string() }
        .map_err(|err| format!("Could not convert command line from UTF-16 ({err})").into())
}

pub fn process_basic_information(handle: HANDLE) -> Result<PROCESS_BASIC_INFORMATION> {
    let mut out_size: u32 = 0;

    let mut process_information: PROCESS_BASIC_INFORMATION = unsafe { core::mem::zeroed() };

    unsafe {
        match NtQueryInformationProcess(
            handle,
            0,
            &mut process_information as *mut _ as _,
            size_of::<PROCESS_BASIC_INFORMATION>() as _,
            &mut out_size,
        ) {
            0 => Ok(process_information),
            err => Err(format!("Cannot read PBI ({err})").into()),
        }
    }
}

pub fn read_memory<T>(handle: HANDLE, address: PVOID) -> Result<T> {
    let data = read_bytes(handle, address, size_of::<T>())?;
    Ok(unsafe { std::ptr::read(data.as_ptr() as *const _) })
}

pub fn read_bytes(handle: HANDLE, address: PVOID, size: usize) -> Result<Vec<u8>> {
    let mut data: Vec<u8> = vec![0; size];
    let mut out_size = 0;

    unsafe {
        ReadProcessMemory(
            handle,
            address as _,
            data.as_mut_ptr() as _,
            data.len(),
            Some(&mut out_size),
        )?;
    }
    Ok(data)
}

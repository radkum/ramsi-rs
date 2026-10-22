use windows::Win32::{
    Foundation::HMODULE,
    System::{Environment::GetCommandLineW, LibraryLoader::GetModuleFileNameW},
};

#[allow(overflowing_literals)]
pub const E_NOT_SUFFICIENT_BUFFER: i32 = 0x8007007a_i32;

pub fn get_curr_module_file_name(module: HMODULE) -> String {
    // long paths and non-ANSI characters
    let mut filename_buf = vec![0u16; 32768];
    let filename_len = unsafe { GetModuleFileNameW(Some(module), filename_buf.as_mut_slice()) };
    if filename_len == 0 {
        String::from("unknown")
    } else {
        String::from_utf16_lossy(&filename_buf[..filename_len as usize])
    }
}

pub fn get_command_line() -> String {
    unsafe { GetCommandLineW().to_string() }.unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    use super::*;

    #[test]
    fn module_file_name_of_current_exe() {
        let module = unsafe { GetModuleHandleW(None) }.unwrap();
        assert_eq!(
            get_curr_module_file_name(module),
            std::env::current_exe().unwrap().to_string_lossy()
        );
    }
}

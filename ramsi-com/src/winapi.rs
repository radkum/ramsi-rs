use windows::Win32::{Foundation::HMODULE, System::LibraryLoader::GetModuleFileNameA};

#[allow(overflowing_literals)]
pub const E_NOT_SUFFICIENT_BUFFER: i32 = 0x8007007a as i32;

pub fn get_curr_module_file_name(module: HMODULE) -> String {
    let mut filename_buf = [0u8; 255];
    let filename_len = unsafe { GetModuleFileNameA(Some(module), filename_buf.as_mut_slice()) };
    if filename_len == 0 {
        String::from("unknown")
    } else {
        String::from_utf8_lossy(&filename_buf[..filename_len as usize]).to_string()
    }
}

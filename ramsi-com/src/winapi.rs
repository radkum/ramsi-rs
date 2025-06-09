use windows_sys::Win32::{Foundation::HMODULE, System::LibraryLoader::GetModuleFileNameA};

#[allow(overflowing_literals)]
pub const E_NOT_SUFFICIENT_BUFFER: i32 = 0x8007007a as i32;

pub fn get_curr_module_file_name(module: HMODULE) -> String {
    const BUFF_SIZE: u32 = 255;
    let mut filename_buf = [0; 255];
    let filename_len = unsafe { GetModuleFileNameA(module, filename_buf.as_mut_ptr(), BUFF_SIZE) };
    if filename_len == 0 {
        String::from("unknown")
    } else {
        String::from_utf8_lossy(&filename_buf[..filename_len as usize]).to_string()
    }
}

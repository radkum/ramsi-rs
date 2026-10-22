use windows::Win32::{
    Foundation::{HANDLE, HMODULE},
    Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
    System::{
        Environment::GetCommandLineW,
        LibraryLoader::GetModuleFileNameW,
        Pipes::GetNamedPipeServerProcessId,
        Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};
use windows_core::{Owned, Result};

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

// elevated admins and SYSTEM, so a user cannot squat the pipe name
pub fn pipe_server_is_elevated(pipe: HANDLE) -> Result<bool> {
    let mut pid = 0;
    unsafe {
        GetNamedPipeServerProcessId(pipe, &mut pid)?;
        let process = Owned::new(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?);
        let mut token = HANDLE::default();
        OpenProcessToken(*process, TOKEN_QUERY, &mut token)?;
        token_is_elevated(*Owned::new(token))
    }
}

fn token_is_elevated(token: HANDLE) -> Result<bool> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut size = 0;
    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as _),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )?
    };
    Ok(elevation.TokenIsElevated != 0)
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    use super::*;

    #[test]
    fn lua_token_is_not_elevated() {
        use windows::Win32::{
            Security::{CreateRestrictedToken, LUA_TOKEN, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE},
            System::Threading::GetCurrentProcess,
        };

        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
                &mut token,
            )
            .unwrap();
            let token = Owned::new(token);
            let mut lua = HANDLE::default();
            CreateRestrictedToken(*token, LUA_TOKEN, None, None, None, &mut lua).unwrap();
            assert!(!token_is_elevated(*Owned::new(lua)).unwrap());
        }
    }

    #[test]
    fn module_file_name_of_current_exe() {
        let module = unsafe { GetModuleHandleW(None) }.unwrap();
        assert_eq!(
            get_curr_module_file_name(module),
            std::env::current_exe().unwrap().to_string_lossy()
        );
    }
}

use std::path::Path;

use shared::constants::LOG_DIR_SDDL;
use windows::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, HANDLE, HLOCAL, HMODULE, LocalFree},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_KERNEL_OBJECT,
        },
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::CreateDirectoryW,
    System::{Environment::GetCommandLineW, LibraryLoader::GetModuleFileNameW},
};
use windows_core::{HSTRING, Result};

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

// created with the protected DACL by whichever process comes first
pub fn create_log_dir(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(LOG_DIR_SDDL),
            SDDL_REVISION_1,
            &mut attributes.lpSecurityDescriptor as *mut _ as _,
            None,
        )?;
        let res = CreateDirectoryW(&HSTRING::from(dir.as_os_str()), Some(&attributes));
        LocalFree(Some(HLOCAL(attributes.lpSecurityDescriptor)));
        match res {
            Err(err) if err.code() != ERROR_ALREADY_EXISTS.to_hresult() => Err(err.into()),
            _ => Ok(()),
        }
    }
}

// owned by Administrators or SYSTEM, so a user cannot squat the pipe name
pub fn pipe_owner_is_admin(pipe: HANDLE) -> Result<bool> {
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetSecurityInfo(
            pipe,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        )
        .ok()?;
        let admin = IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
            || IsWellKnownSid(owner, WinLocalSystemSid).as_bool();
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(admin)
    }
}

#[cfg(test)]
mod tests {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    use super::*;

    #[test]
    fn log_dir_gets_protected_dacl() {
        use windows::Win32::Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
                SE_FILE_OBJECT,
            },
            DACL_SECURITY_INFORMATION,
        };
        use windows_core::PWSTR;

        // created on the first run, never removed
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/acl-test-dll/logs");
        create_log_dir(&dir).unwrap();

        let sddl = unsafe {
            let mut sd = PSECURITY_DESCRIPTOR::default();
            GetNamedSecurityInfoW(
                &HSTRING::from(dir.as_os_str()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                &mut sd,
            )
            .ok()
            .unwrap();
            let mut text = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
            .unwrap();
            let sddl = text.to_string().unwrap();
            LocalFree(Some(HLOCAL(text.0 as _)));
            LocalFree(Some(HLOCAL(sd.0)));
            sddl
        };
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(sddl.contains("(A;OICIIO;FA;;;CO)"), "{sddl}");
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

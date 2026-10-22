use std::path::Path;

use shared::constants::LOG_DIR_SDDL;
use windows::Win32::{
    Foundation::{ERROR_ALREADY_EXISTS, HANDLE, HLOCAL, HMODULE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
        },
        DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE, IsWellKnownSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
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

// only Administrators or SYSTEM can write, change or replace it
pub fn only_admins_can_write(path: &Path) -> Result<bool> {
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const WRITE_RIGHTS: u32 =
        0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000;

    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
        .ok()?;
        let is_admin = |sid: PSID| {
            IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
                || IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
        };
        // a NULL DACL grants everyone full access
        let mut safe = is_admin(owner) && !dacl.is_null();
        for i in 0..if dacl.is_null() {
            0
        } else {
            (*dacl).AceCount as u32
        } {
            let mut ace = std::ptr::null_mut();
            if GetAce(dacl, i, &mut ace).is_err() {
                safe = false;
                break;
            }
            let header = &*(ace as *const ACE_HEADER);
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                || header.AceFlags as u32 & INHERIT_ONLY_ACE.0 != 0
            {
                continue;
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            let sid = PSID(&allowed.SidStart as *const u32 as _);
            if allowed.Mask & WRITE_RIGHTS != 0 && !is_admin(sid) {
                safe = false;
                break;
            }
        }
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(safe)
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

    // a file under target/acl-test-rules created with `sddl`
    fn file_with_sddl(name: &str, sddl: &str) -> std::path::PathBuf {
        use windows::Win32::Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
        };

        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/acl-test-rules");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            ..Default::default()
        };
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut attributes.lpSecurityDescriptor as *mut _ as _,
                None,
            )
            .unwrap();
            let file = CreateFileW(
                &HSTRING::from(path.as_os_str()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_NONE,
                Some(&attributes),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .unwrap();
            let _ = windows::Win32::Foundation::CloseHandle(file);
        }
        path
    }

    fn current_user_sid() -> String {
        use windows::Win32::{
            Security::{
                Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY,
                TOKEN_USER, TokenUser,
            },
            System::Threading::{GetCurrentProcess, OpenProcessToken},
        };
        use windows_core::PWSTR;

        unsafe {
            let mut token = HANDLE::default();
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).unwrap();
            let mut buf = vec![0u8; 256];
            let mut size = 0;
            GetTokenInformation(
                token,
                TokenUser,
                Some(buf.as_mut_ptr() as _),
                buf.len() as u32,
                &mut size,
            )
            .unwrap();
            let _ = windows::Win32::Foundation::CloseHandle(token);
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut text = PWSTR::null();
            ConvertSidToStringSidW(user.User.Sid, &mut text).unwrap();
            let sid = text.to_string().unwrap();
            LocalFree(Some(HLOCAL(text.0 as _)));
            sid
        }
    }

    #[test]
    fn rules_file_must_be_admin_owned_and_admin_writable() {
        let secure = file_with_sddl("secure.toml", shared::constants::RULES_SDDL);
        assert!(only_admins_can_write(&secure).unwrap());

        let users_write = file_with_sddl("users-write.toml", "O:BAD:P(A;;FA;;;BA)(A;;FW;;;AU)");
        assert!(!only_admins_can_write(&users_write).unwrap());

        let user_owned = file_with_sddl(
            "user-owned.toml",
            &format!("O:{}D:P(A;;FA;;;BA)", current_user_sid()),
        );
        assert!(!only_admins_can_write(&user_owned).unwrap());
    }

    #[test]
    fn log_dir_gets_protected_dacl() {
        use windows::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW;
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

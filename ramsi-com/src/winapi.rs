use std::path::Path;

use shared::constants::LOG_DIR_SDDL;
use windows::Win32::{
    Foundation::{GENERIC_ALL, GENERIC_WRITE, HANDLE, HLOCAL, HMODULE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
            GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_KERNEL_OBJECT,
            SetNamedSecurityInfoW,
        },
        DACL_SECURITY_INFORMATION, GetAce, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        INHERIT_ONLY_ACE, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        DELETE, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_DATA, WRITE_DAC, WRITE_OWNER,
    },
    System::{Environment::GetCommandLineW, LibraryLoader::GetModuleFileNameW},
};
use windows_core::{BOOL, HSTRING, Result};

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

// owner BA needs an elevated caller, so only register can make a trusted log
// dir
pub fn secure_log_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    unsafe {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(LOG_DIR_SDDL),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )?;
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut owner = PSID::default();
        let res = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted)
            .and_then(|_| GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted))
            .and_then(|_| {
                SetNamedSecurityInfoW(
                    &HSTRING::from(dir.as_os_str()),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION
                        | PROTECTED_DACL_SECURITY_INFORMATION,
                    Some(owner),
                    None,
                    Some(dacl),
                    None,
                )
                .ok()
            });
        LocalFree(Some(HLOCAL(sd.0)));
        res
    }
}

// a dir a user created could let them read others' logs and dumps
pub fn path_owner_is_admin(path: &Path) -> Result<bool> {
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetNamedSecurityInfoW(
            &HSTRING::from(path.as_os_str()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        )
        .ok()?;
        let admin = is_admin(owner);
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(admin)
    }
}

// only Administrators or SYSTEM can write, change or replace it
pub fn only_admins_can_write(path: &Path) -> Result<bool> {
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const WRITE_RIGHTS: u32 = FILE_WRITE_DATA.0
        | FILE_APPEND_DATA.0
        | FILE_DELETE_CHILD.0
        | DELETE.0
        | WRITE_DAC.0
        | WRITE_OWNER.0
        | GENERIC_WRITE.0
        | GENERIC_ALL.0;

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
        let ace_is_safe = |i| {
            let mut ace = std::ptr::null_mut();
            if GetAce(dacl, i, &mut ace).is_err() {
                return false;
            }
            let header = &*(ace as *const ACE_HEADER);
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                || header.AceFlags as u32 & INHERIT_ONLY_ACE.0 != 0
            {
                return true;
            }
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            allowed.Mask & WRITE_RIGHTS == 0 || is_admin(PSID(&allowed.SidStart as *const u32 as _))
        };
        // a NULL DACL grants everyone full access
        let safe =
            is_admin(owner) && !dacl.is_null() && (0..(*dacl).AceCount as u32).all(ace_is_safe);
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(safe)
    }
}

fn is_admin(sid: PSID) -> bool {
    unsafe {
        IsWellKnownSid(sid, WinBuiltinAdministratorsSid).as_bool()
            || IsWellKnownSid(sid, WinLocalSystemSid).as_bool()
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
        let admin = is_admin(owner);
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(admin)
    }
}

#[cfg(test)]
pub(crate) fn current_user_sid() -> String {
    use windows::Win32::{
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
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

#[cfg(test)]
mod tests {
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;

    use super::*;

    // a file under target/acl-test-rules created with `sddl`
    fn file_with_sddl(name: &str, sddl: &str) -> std::path::PathBuf {
        use windows::Win32::{
            Security::SECURITY_ATTRIBUTES,
            Storage::FileSystem::{
                CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_NONE,
            },
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
    fn secured_log_dir_is_owned_by_admins() {
        // reused across runs, never removed
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/acl-test-dll/logs");
        secure_log_dir(&dir).unwrap();
        assert!(path_owner_is_admin(&dir).unwrap());

        let user_owned = file_with_sddl(
            "user-owned-dir-check.toml",
            &format!("O:{}D:P(A;;FA;;;BA)", current_user_sid()),
        );
        assert!(!path_owner_is_admin(&user_owned).unwrap());
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

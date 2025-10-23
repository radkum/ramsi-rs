#[repr(C)]
pub struct FfiString(*mut u8, usize);

impl FfiString {
    pub fn new(s: &str) -> Self {
        let cstr = std::ffi::CString::new(s).unwrap();
        let ptr = cstr.into_raw();
        Self(ptr as *mut u8, s.len())
    }

    pub fn into_string(self) -> Option<String> {
        if self.0.is_null() || self.1 == 0 {
            return None;
        }
        unsafe {
            let slice = std::slice::from_raw_parts(self.0, self.1);
            Some(String::from_utf8_lossy(slice).to_string())
        }
    }
}

impl Drop for FfiString {
    fn drop(&mut self) {
        unsafe {
            let _ = std::ffi::CString::from_raw(self.0 as *mut i8);
        }
    }
}

pub struct PipeName(String);
impl PipeName {
    pub fn from_suffix(suffix: &str) -> Self {
        let full_name = format!(r"\\.\pipe\{}", suffix);
        Self(full_name)
    }

    pub fn verify(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.0.is_empty() {
            return Err("Pipe name is empty".into());
        }

        // Must not end with space or period
        if self.0.ends_with([' ', '.']) {
            return Err("Pipe name must not end with space or period".into());
        }

        // Check forbidden characters
        const FORBIDDEN: [char; 9] = ['<', '>', ':', '"', '/', '|', '?', '*', '\0'];
        if self.0.chars().any(|c| FORBIDDEN.contains(&c)) {
            return Err("Pipe name contains forbidden characters".into());
        }

        // No control characters (ASCII < 32)
        if self.0.chars().any(|c| c as u32 <= 31) {
            return Err("Pipe name contains control characters".into());
        }

        // Length limit (approx 256 characters)
        if self.0.len() > 256 {
            return Err("Pipe name is too long".into());
        }

        Ok(())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn suffix(&self) -> &str {
        self.0.strip_prefix(r"\\.\pipe\").unwrap_or(&self.0)
    }
}

impl std::fmt::Display for PipeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

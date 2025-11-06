use log::error;
use windows_core::{PCSTR, PWSTR};
pub struct AmsiString(String);
impl AmsiString {
    pub fn parse_buff(mut buff: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
        let pwstr = PWSTR::from_raw(buff.as_mut_ptr() as *mut u16);
        unsafe {
            match pwstr.to_string() {
                Ok(s) => Ok(s),
                Err(e) => {
                    error!("Failed convert vector to wstring: {}", e);
                    Ok(PCSTR::from_raw(buff.as_mut_ptr()).to_string()?)
                },
            }
        }
    }
}

impl From<AmsiString> for String {
    fn from(amsi_str: AmsiString) -> Self {
        amsi_str.0
    }
}

impl From<Vec<u8>> for AmsiString {
    fn from(buff: Vec<u8>) -> Self {
        AmsiString(Self::parse_buff(buff).unwrap_or_else(|e| {
            error!("Failed to convert vector to string: {}", e);
            String::new()
        }))
    }
}

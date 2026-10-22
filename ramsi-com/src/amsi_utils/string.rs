use log::error;
pub struct AmsiString(String);
impl AmsiString {
    pub fn parse_buff(buff: Vec<u8>) -> Result<String, Box<dyn std::error::Error>> {
        let wide: Vec<u16> = buff
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
        match String::from_utf16(&wide[..end]) {
            Ok(s) => Ok(s),
            Err(e) => {
                error!("Failed convert vector to wstring: {}", e);
                let end = buff.iter().position(|&c| c == 0).unwrap_or(buff.len());
                Ok(String::from_utf8_lossy(&buff[..end]).into_owned())
            },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn without_nul_terminator() {
        assert_eq!(
            AmsiString::parse_buff(utf16("Write-Host 1")).unwrap(),
            "Write-Host 1"
        );
    }

    #[test]
    fn stops_at_nul_terminator() {
        assert_eq!(
            AmsiString::parse_buff(utf16("abc\0garbage")).unwrap(),
            "abc"
        );
    }

    #[test]
    fn odd_length_ignores_last_byte() {
        let mut buff = utf16("abc");
        buff.push(b'x');
        assert_eq!(AmsiString::parse_buff(buff).unwrap(), "abc");
    }

    #[test]
    fn empty() {
        assert_eq!(AmsiString::parse_buff(Vec::new()).unwrap(), "");
    }
}

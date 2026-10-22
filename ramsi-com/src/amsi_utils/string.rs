pub struct AmsiString(String);
impl AmsiString {
    // length-delimited content may hold NULs or lone surrogates; keep all of it
    pub fn parse_buff(buff: Vec<u8>) -> String {
        let wide: Vec<u16> = buff
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&wide)
    }
}

impl From<AmsiString> for String {
    fn from(amsi_str: AmsiString) -> Self {
        amsi_str.0
    }
}

impl From<Vec<u8>> for AmsiString {
    fn from(buff: Vec<u8>) -> Self {
        AmsiString(Self::parse_buff(buff))
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
            AmsiString::parse_buff(utf16("Write-Host 1")),
            "Write-Host 1"
        );
    }

    #[test]
    fn keeps_content_after_nul() {
        assert_eq!(
            AmsiString::parse_buff(utf16("#\0iex payload")),
            "#\0iex payload"
        );
    }

    #[test]
    fn lone_surrogate_keeps_rest_of_content() {
        let mut buff = utf16("W");
        buff.extend(0xD800u16.to_le_bytes());
        buff.extend(utf16("rite-Host"));
        assert_eq!(AmsiString::parse_buff(buff), "W\u{FFFD}rite-Host");
    }

    #[test]
    fn odd_length_ignores_last_byte() {
        let mut buff = utf16("abc");
        buff.push(b'x');
        assert_eq!(AmsiString::parse_buff(buff), "abc");
    }

    #[test]
    fn empty() {
        assert_eq!(AmsiString::parse_buff(Vec::new()), "");
    }
}

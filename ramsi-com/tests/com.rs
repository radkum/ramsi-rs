use windows::Win32::System::{Antimalware::*, Com::IClassFactory};
use windows_core::{GUID, HRESULT, Interface, implement};

const CLSID_RAMSI: GUID = GUID::from_u128(0xb8614e83_84ac_45fb_82a8_21711aaf07f2);
#[allow(overflowing_literals)]
const E_NOT_SUFFICIENT_BUFFER: HRESULT = HRESULT(0x8007007a_i32);

#[implement(IAmsiStream)]
struct Stream {
    app_name: Vec<u8>,
    content: Vec<u8>,
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

impl IAmsiStream_Impl for Stream_Impl {
    fn GetAttribute(
        &self,
        attribute: AMSI_ATTRIBUTE,
        datasize: u32,
        data: *mut u8,
        retdata: *mut u32,
    ) -> windows_core::Result<()> {
        let value = match attribute {
            AMSI_ATTRIBUTE_APP_NAME => self.app_name.clone(),
            AMSI_ATTRIBUTE_CONTENT_NAME => utf16("\0"),
            AMSI_ATTRIBUTE_CONTENT_SIZE => (self.content.len() as u64).to_le_bytes().to_vec(),
            AMSI_ATTRIBUTE_CONTENT_ADDRESS => (self.content.as_ptr() as u64).to_le_bytes().to_vec(),
            AMSI_ATTRIBUTE_SESSION => 1u64.to_le_bytes().to_vec(),
            _ => return Err(windows_core::Error::empty()),
        };
        unsafe { *retdata = value.len() as u32 };
        if (datasize as usize) < value.len() {
            return Err(E_NOT_SUFFICIENT_BUFFER.into());
        }
        unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), data, value.len()) };
        Ok(())
    }

    fn Read(&self, _: u64, _: u32, _: *mut u8, _: *mut u32) -> windows_core::Result<()> {
        Err(windows_core::Error::empty())
    }
}

fn provider() -> IAntimalwareProvider {
    let mut factory: Option<IClassFactory> = None;
    let hr = ramsi_com::DllGetClassObject(
        &CLSID_RAMSI,
        &IClassFactory::IID,
        &mut factory as *mut _ as _,
    );
    assert_eq!(hr, 0);
    unsafe { factory.unwrap().CreateInstance(None) }.unwrap()
}

fn scan(script: &str) -> AMSI_RESULT {
    let stream: IAmsiStream = Stream {
        app_name: utf16("PowerShell_C:\\Windows\\System32\\powershell.exe_10.0\0"),
        content: utf16(script),
    }
    .into();
    unsafe { provider().Scan(&stream) }.unwrap()
}

#[test]
fn unknown_clsid_is_rejected() {
    let mut ppv = std::ptr::null_mut();
    let hr = ramsi_com::DllGetClassObject(&GUID::zeroed(), &IClassFactory::IID, &mut ppv);
    assert_ne!(hr, 0);
    assert!(ppv.is_null());
}

#[test]
fn allowlisted_script_is_clean() {
    assert_eq!(scan("prompt"), AMSI_RESULT_CLEAN);
}

#[test]
fn benign_script_is_not_detected() {
    assert_eq!(scan("Get-Process | Out-Null"), AMSI_RESULT_NOT_DETECTED);
}

#[test]
fn provider_has_display_name() {
    let name = unsafe { provider().DisplayName() }.unwrap();
    assert_eq!(unsafe { name.to_string() }.unwrap(), "Ramsi");
}

pub mod constants;
pub mod debug_macros;
pub mod event;
pub mod ffi_string;
pub use event::{Command, ScanEvent, ScanStatus};
pub use ffi_string::PipeName;

pub type DynError = Box<dyn std::error::Error>;
pub type DynResult<T> = Result<T, DynError>;

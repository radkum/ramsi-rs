pub const DEBUG: bool = true;

#[macro_export]
macro_rules! dprintln {
    ($($arg:tt)*) => {
        {
            let mut res = std::fmt::format(format_args!($($arg)*));

            // carriage return should be dipslay only on windows
            #[cfg(windows)]
            res.push('\r');

            res.push_str("\n\0");

            #[allow(unused_unsafe)]
            unsafe {
                windows::Win32::System::Diagnostics::Debug::OutputDebugStringA(windows_core::PCSTR::from_raw(res.as_ptr()));
            }
        }

    }
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::DEBUG {
            $crate::dprintln!($($arg)*)
        }
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::dprintln!($($arg)*)
    }
}

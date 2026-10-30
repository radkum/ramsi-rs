//! The provider's self-check. A process asked to heartbeat scans its own nonce
//! through AMSI: if AMSI is intact the scan reaches the provider (a `heartbeat`
//! event); if AMSI was patched the scan never arrives and the heartbeat stops.

use std::{thread, time::Duration};

use log::debug;
use windows::Win32::System::Antimalware::{
    AmsiCloseSession, AmsiInitialize, AmsiOpenSession, AmsiScanBuffer, AmsiUninitialize,
};
use windows_core::{PCWSTR, w};

use crate::config::Config;

// the content name of a heartbeat scan carries this prefix and the process
// nonce
pub const HEARTBEAT_PREFIX: &str = "ramsi-heartbeat-";

/// Spawns the heartbeat thread when `heartbeat_secs` is set: every interval it
/// scans the nonce, but only if this process is in `heartbeat_pids_file`.
pub fn spawn(config: Config, nonce: String) {
    if config.heartbeat_secs == 0 {
        return;
    }
    let interval = Duration::from_secs(config.heartbeat_secs);
    let pid = std::process::id();
    thread::spawn(move || {
        loop {
            thread::sleep(interval);
            if config.heartbeats(pid) {
                debug!("heartbeat: scanning nonce");
                scan(&nonce);
            }
        }
    });
}

/// Runs the nonce through AMSI. If AMSI is intact this reaches the provider's
/// own `Scan`.
fn scan(nonce: &str) {
    let content_name: Vec<u16> = format!("{HEARTBEAT_PREFIX}{nonce}")
        .encode_utf16()
        .chain([0])
        .collect();
    unsafe {
        let Ok(context) = AmsiInitialize(w!("ramsi-heartbeat")) else {
            return;
        };
        if let Ok(session) = AmsiOpenSession(context) {
            let _ = AmsiScanBuffer(
                context,
                nonce.as_ptr() as *const core::ffi::c_void,
                nonce.len() as u32,
                PCWSTR(content_name.as_ptr()),
                Some(session),
            );
            AmsiCloseSession(context, session);
        }
        AmsiUninitialize(context);
    }
}

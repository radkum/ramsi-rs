#![allow(non_camel_case_types)]

mod antimalware;
mod attribute;
mod keywords;
mod report;
mod rules;
mod scan;

use core::result::Result;
use std::sync::{Arc, OnceLock, atomic::AtomicU32};

use antimalware::PsVersion;
pub use antimalware::ScriptType;
use fern::Dispatch;
use log::{LevelFilter, debug, error};
use report::PipeClient;
pub use rules::Rules;
pub use scan::{ScanResult, ScanStatus, Scanner};
use shared::win_log;
use tokio::sync::RwLock;
use windows::Win32::System::{
    Antimalware::*,
    Com::{IClassFactory, IClassFactory_Impl},
};
use windows_core::*;

use crate::{config::Config, utils::ProcessInfo};
// created lazily: heavy init is not allowed under the loader lock in DllMain
static CLASS_FACTORY: OnceLock<StaticComObject<Ramsi>> = OnceLock::new();

#[interface("b8614e83-84ac-45fb-82a8-21711aaf07f2")]
unsafe trait IRamsi: IAntimalwareProvider2 {}

#[implement(IRamsi, IClassFactory)]

pub struct Ramsi {
    scanner: Scanner,
    process_info: ProcessInfo,
    request_number: AtomicU32,
    pipe_client: Arc<RwLock<PipeClient>>,
    config: Config,
}

impl Ramsi {
    pub fn new() -> Self {
        // read once, when the DLL creates its class factory
        let config = Config::load();
        let process_info = ProcessInfo::current();

        if let Err(err) = Self::init_logging(&config, &process_info) {
            error!("Failed to initialize logging: {err}");
        }

        Self {
            scanner: Scanner::new(Self::load_rules(&config)),
            process_info,
            request_number: AtomicU32::new(0),
            pipe_client: Arc::new(RwLock::new(PipeClient::new(&config.pipe_name))),
            config,
        }
    }

    fn load_rules(config: &Config) -> Rules {
        let Some(path) = &config.rules else {
            return Rules::default();
        };
        Rules::load(path).unwrap_or_else(|err| {
            error!("Failed to load rules from {}: {err}", path.display());
            Rules::default()
        })
    }

    fn init_logging(
        config: &Config,
        process_info: &ProcessInfo,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let base = format!("amsi-{}-{}", process_info.pid(), process_info.tid());
        let log_dir = &config.log_dir;
        std::fs::create_dir_all(log_dir)?;

        let mut logger = Dispatch::new().format(|out, message, record| {
            out.finish(format_args!(
                "[{}][{}][{}::{}] {}",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S %Z"),
                record.level().short(),
                record.target(),
                record.line().unwrap_or(0),
                message,
            ))
        });

        logger = logger.chain(
            Dispatch::new()
                .level(LevelFilter::Off)
                .level_for(env!("CARGO_CRATE_NAME"), config.log_level)
                .chain(fern::DateBased::new(
                    log_dir,
                    format!("/{base}-%Y-%m-%d.log"),
                )),
        );

        logger.apply()?;

        Ok(())
    }
}

pub trait ShortName {
    fn short(&self) -> String;
}

impl ShortName for log::Level {
    fn short(&self) -> String {
        match self {
            Self::Info => "INF",
            Self::Warn => "WRN",
            Self::Error => "ERR",
            Self::Debug => "DBG",
            Self::Trace => "VER",
        }
        .to_owned()
    }
}

impl IRamsi_Impl for Ramsi_Impl {}

impl IClassFactory_Impl for Ramsi_Impl {
    fn CreateInstance(
        &self,
        _: windows_core::Ref<'_, IUnknown>,
        iid: *const windows_core::GUID,
        interface: *mut *mut std::ffi::c_void,
    ) -> windows_core::Result<()> {
        win_log!("Ramsi::CreateInstance");
        Self::query_interface(iid, interface)
    }

    fn LockServer(&self, _: BOOL) -> windows_core::Result<()> {
        win_log!("Ramsi::LockServer");
        Ok(())
    }
}

impl Ramsi {
    pub const NAME: &str = "Ramsi";
}

impl Ramsi {
    pub fn IID() -> String {
        format!("{{{:?}}}", IRamsi::IID)
    }
}

impl Ramsi_Impl {
    pub fn get_class_object(
        rclsid: *const ::windows_core::GUID,
        iid: *const ::windows_core::GUID,
        interface: *mut *mut ::core::ffi::c_void,
    ) -> windows_core::HRESULT {
        if rclsid.is_null() || IRamsi::IID != unsafe { *rclsid } {
            debug!(
                "Ramsi_Impl::get_class_object: Unsupported IID: {:?}",
                unsafe { *iid }
            );
            return windows_core::HRESULT(-2147221231); // E_NOINTERFACE
        }

        if let Err(r) = Self::query_interface(iid, interface) {
            debug!("Ramsi_Impl::get_class_object: {:?}", r);
            return r.into();
        }
        windows_core::HRESULT(0)
    }

    fn query_interface(
        iid: *const windows_core::GUID,
        interface: *mut *mut std::ffi::c_void,
    ) -> windows_core::Result<()> {
        let class_factory = CLASS_FACTORY.get_or_init(Self::create);
        let hr = unsafe { class_factory.QueryInterface(iid, interface) };
        if hr.is_err() {
            debug!("Ramsi_Impl::query_interface: {:?}", hr);
            return Err(hr.into());
        }

        Ok(())
    }

    fn create() -> StaticComObject<Ramsi> {
        debug!("Ramsi_Impl::create");
        // the default hook prints to the host's stderr
        std::panic::set_hook(Box::new(|info| error!("{info}")));
        Ramsi::new().into_static()
    }
}

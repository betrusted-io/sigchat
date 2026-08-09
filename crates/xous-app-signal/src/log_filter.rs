//! Target-filtered `log` backend for hardware builds.
//!
//! `xous-api-log`'s logger accepts every record (`enabled()` returns
//! `true`) and offers only one global level, so a dependency that logs
//! identifiers at info level puts them on the UART and we cannot stop
//! it at the call site. This installs the same log-server transport
//! behind a target filter instead.
//!
//! The filtered lines are diagnostically useful — websocket frame
//! counters are how a duplicate connection gets spotted — so
//! `verbose-upstream-logs` turns the filter off for debugging.

#[cfg(target_os = "xous")]
use core::fmt::Write as _;
#[cfg(target_os = "xous")]
use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(target_os = "xous")]
use num_traits::ToPrimitive;
#[cfg(target_os = "xous")]
use xous_api_log::api;

/// Crates whose info-level records carry account identifiers, the
/// provisioning URL, or storage auth credentials. Warnings and errors
/// still come through.
const MUFFLED: &[&str] = &["presage", "libsignal", "libsignal_service", "libsignal_protocol", "zkgroup"];

#[cfg(target_os = "xous")]
static CONN: AtomicU32 = AtomicU32::new(0);
#[cfg(target_os = "xous")]
static LOGGER: FilteredLogger = FilteredLogger {};

#[cfg(target_os = "xous")]
struct FilteredLogger;

/// Whether `target` belongs to a muffled crate. Matches on a full
/// crate-name segment: `presage_store_pddb` is ours and must not be
/// caught by the `presage` entry.
fn muffled(target: &str) -> bool {
    MUFFLED.iter().any(|c| target == *c || target.strip_prefix(*c).is_some_and(|rest| rest.starts_with("::")))
}

/// Bounded writer over `LogRecord::args`; excess output is truncated.
#[cfg(target_os = "xous")]
struct ArgsWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

#[cfg(target_os = "xous")]
impl core::fmt::Write for ArgsWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for b in s.as_bytes() {
            if self.len >= self.buf.len() {
                break;
            }
            self.buf[self.len] = *b;
            self.len += 1;
        }
        Ok(())
    }
}

#[cfg(target_os = "xous")]
fn copy_bounded(dest: &mut [u8], src: &[u8]) -> u32 {
    let n = src.len().min(dest.len());
    dest[..n].copy_from_slice(&src[..n]);
    n as u32
}

#[cfg(target_os = "xous")]
impl log::Log for FilteredLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        if cfg!(feature = "verbose-upstream-logs") {
            return true;
        }
        !(metadata.level() >= log::Level::Info && muffled(metadata.target()))
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let cid = CONN.load(Ordering::Relaxed);
        if cid == 0 {
            return;
        }

        let mut log_record = api::LogRecord::default();
        log_record.line = core::num::NonZeroU32::new(record.line().unwrap_or_default());
        log_record.level = record.level() as u32;
        log_record.file_length =
            copy_bounded(&mut log_record.file, record.file().unwrap_or_default().as_bytes());
        log_record.module_length =
            copy_bounded(&mut log_record.module, record.module_path().unwrap_or_default().as_bytes());

        let mut writer = ArgsWriter { buf: &mut log_record.args, len: 0 };
        write!(writer, "{}", record.args()).ok();
        log_record.args_length = writer.len as u32;

        let buf = unsafe {
            xous::MemoryRange::new(
                &log_record as *const api::LogRecord as usize,
                core::mem::size_of::<api::LogRecord>(),
            )
            .unwrap()
        };
        xous::send_message(
            cid,
            xous::Message::new_lend(api::Opcode::LogRecord.to_usize().unwrap(), buf, None, None),
        )
        .ok();
    }

    fn flush(&self) {}
}

/// Connect to the log server and install the filter. `Err` if the
/// server is unreachable or a logger is already installed; the caller
/// should fall back to `xous_api_log`.
#[cfg(target_os = "xous")]
pub fn init() -> Result<(), ()> {
    let cid = xous::connect(xous::SID::from_bytes(b"xous-log-server ").unwrap()).or(Err(()))?;
    CONN.store(cid, Ordering::Relaxed);
    log::set_logger(&LOGGER).or(Err(()))?;
    log::set_max_level(log::LevelFilter::Info);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::muffled;

    #[test]
    fn muffles_upstream_crates() {
        assert!(muffled("presage"));
        assert!(muffled("presage::manager::linking"));
        assert!(muffled("libsignal_service::push_service"));
        assert!(muffled("libsignal_protocol::group_cipher"));
        assert!(muffled("zkgroup::api"));
    }

    #[test]
    fn does_not_muffle_our_own_crates() {
        assert!(!muffled("presage_store_pddb"));
        assert!(!muffled("presage_store_pddb::backend_pddb"));
        assert!(!muffled("xas::gam_app"));
        assert!(!muffled("xous_signal_worker"));
        assert!(!muffled("xous_net_bridge::ws_pump"));
    }

    #[test]
    fn does_not_muffle_unrelated_targets() {
        assert!(!muffled(""));
        assert!(!muffled("net"));
        assert!(!muffled("libsignalfoo"));
    }
}

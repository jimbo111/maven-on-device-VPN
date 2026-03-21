pub mod engine;
pub mod ip;
pub mod dns;
pub mod domain;
pub mod storage;
pub mod site_mapper;
pub mod errors;
pub mod constants;

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic;
use std::ptr;
use std::sync::Mutex;

use engine::{PacketEngine, ProcessResult};

/// Global last error message (shared across threads, protected by Mutex).
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn set_last_error(msg: String) {
    if let Ok(mut err) = LAST_ERROR.lock() {
        *err = Some(msg);
    }
}

// ═══════════════════════════════════════════════════════════
// FFI Stats Struct
// ═══════════════════════════════════════════════════════════

/// Stats struct returned to Swift.
#[repr(C)]
pub struct EngineStatsFFI {
    pub packets_processed: u64,
    pub dns_domains_found: u64,
    pub packets_skipped: u64,
}

// ═══════════════════════════════════════════════════════════
// Lifecycle Functions
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_init(
    db_path: *const c_char,
) -> *mut PacketEngine {
    let result = panic::catch_unwind(|| {
        if db_path.is_null() {
            set_last_error("db_path is null".into());
            return ptr::null_mut();
        }

        let path = match CStr::from_ptr(db_path).to_str() {
            Ok(s) => s,
            Err(e) => {
                set_last_error(format!("Invalid UTF-8 in db_path: {}", e));
                return ptr::null_mut();
            }
        };

        match PacketEngine::new(path) {
            Ok(engine) => Box::into_raw(Box::new(engine)),
            Err(e) => {
                set_last_error(format!("Engine init failed: {}", e));
                ptr::null_mut()
            }
        }
    });

    match result {
        Ok(ptr) => ptr,
        Err(_) => {
            set_last_error("Panic during engine init".into());
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_destroy(engine: *mut PacketEngine) {
    if !engine.is_null() {
        let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
            let _ = Box::from_raw(engine);
        }));
    }
}

// ═══════════════════════════════════════════════════════════
// Packet Processing
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_process(
    engine: *mut PacketEngine,
    packet_data: *const u8,
    packet_len: usize,
    out_buf: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> c_int {
    if engine.is_null() || packet_data.is_null() || packet_len == 0 {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        let packet = std::slice::from_raw_parts(packet_data, packet_len);

        match engine.process_packet(packet) {
            ProcessResult::Forward => {
                if !out_len.is_null() {
                    *out_len = 0;
                }
                0
            }
            ProcessResult::Replace(new_packet) => {
                if out_buf.is_null() || out_capacity < new_packet.len() {
                    return 0;
                }
                let out_slice = std::slice::from_raw_parts_mut(out_buf, out_capacity);
                out_slice[..new_packet.len()].copy_from_slice(&new_packet);
                if !out_len.is_null() {
                    *out_len = new_packet.len();
                }
                1
            }
        }
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during packet processing".into());
            -1
        }
    }
}

// ═══════════════════════════════════════════════════════════
// Control Functions
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_flush(engine: *mut PacketEngine) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        engine.flush();
        0 as c_int
    }));

    match result {
        Ok(code) => code,
        Err(_) => {
            set_last_error("Panic during flush".into());
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_set_noise_filter(
    engine: *mut PacketEngine,
    enabled: bool,
) -> c_int {
    if engine.is_null() {
        return -1;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &mut *engine;
        engine.noise_filter_enabled = enabled;
        0
    }));

    match result {
        Ok(code) => code,
        Err(_) => -1,
    }
}

// ═══════════════════════════════════════════════════════════
// Diagnostics
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_get_stats(
    engine: *const PacketEngine,
) -> EngineStatsFFI {
    let zero = EngineStatsFFI {
        packets_processed: 0,
        dns_domains_found: 0,
        packets_skipped: 0,
    };

    if engine.is_null() {
        return zero;
    }

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let engine = &*engine;
        let stats = engine.stats();
        EngineStatsFFI {
            packets_processed: stats.packets_processed,
            dns_domains_found: stats.dns_domains_found,
            packets_skipped: stats.packets_skipped,
        }
    }));

    result.unwrap_or(zero)
}

// ═══════════════════════════════════════════════════════════
// Error Reporting
// ═══════════════════════════════════════════════════════════

#[no_mangle]
pub unsafe extern "C" fn packet_engine_last_error() -> *mut c_char {
    match LAST_ERROR.lock() {
        Ok(mut err) => match err.take() {
            Some(msg) => CString::new(msg).unwrap_or_default().into_raw(),
            None => ptr::null_mut(),
        },
        Err(_) => ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn packet_engine_free_string(s: *mut c_char) {
    if !s.is_null() {
        let _ = CString::from_raw(s);
    }
}

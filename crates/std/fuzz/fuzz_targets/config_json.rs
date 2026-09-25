//! Fuzz target `config_json` (plan step 08.2): the Go-semantics JSON reader behind `-c <file>`
//! must never panic, whatever a user (or an attacker who can write that file) puts in it.
//!
//! The first byte picks the side, so both field tables are exercised; the rest is the file.
//! Both configurations start from their defaults, so the overlay runs against real values.
#![no_main]

use libfuzzer_sys::fuzz_target;

use kcptun_std::config::{ClientConfig, ServerConfig, parse_json_bytes};

fuzz_target!(|data: &[u8]| {
    let Some((&side, body)) = data.split_first() else {
        return;
    };
    if side % 2 == 0 {
        let mut config = ClientConfig::defaults();
        let _ = parse_json_bytes(&mut config, body);
        let _ = config.base.apply_mode();
        let _ = config.check_conn();
        let _ = config.base.check_fec();
        let _ = config.base.check_smux_ver();
        let _ = config.base.normalize_rate_limit();
    } else {
        let mut config = ServerConfig::defaults();
        let _ = parse_json_bytes(&mut config, body);
        let _ = config.base.apply_mode();
        let _ = config.base.check_fec();
    }
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use verd::config::model::Config;

fuzz_target!(|data: &[u8]| {
    // TOML parse + full validation must never panic on arbitrary input
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(cfg) = toml::from_str::<Config>(text) {
        let _ = verd::config::validate(&cfg);
    }
});

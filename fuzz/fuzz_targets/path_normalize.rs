#![no_main]
use libfuzzer_sys::fuzz_target;
use verd::router::normalize::normalize_path;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // never panic; output must stay inside the root
    if let Ok(norm) = normalize_path(&text) {
        assert!(norm.starts_with('/'));
        assert!(!norm.split('/').any(|s| s == ".."));
    }
});

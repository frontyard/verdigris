#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // feed arbitrary bytes as a disk-cache object file; boot-time index
    // rebuild must reject corrupt input without panicking
    let dir = std::env::temp_dir().join(format!("verd-fuzz-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let obj = dir.join("fuzz.obj");
    if std::fs::write(&obj, data).is_err() {
        return;
    }
    let cfg_text = format!(
        r#"
[cache.fz]
tier = "disk"
disk_path = "{}"
"#,
        dir.display()
    );
    if let Ok(cfg) = toml::from_str::<verd::config::model::Config>(&cfg_text) {
        let _ = verd::cache::Cache::build_all(&cfg, None, verd::BuildMode::Live);
    }
    let _ = std::fs::remove_file(&obj);
});

#![no_main]
use libfuzzer_sys::fuzz_target;

use verd::router::normalize::normalize_path;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // bound: filesystem paths don't need >2KiB of fuzz input
    let raw: String = text.chars().take(2048).collect();

    let Ok(norm) = normalize_path(&raw) else {
        return;
    };
    assert!(norm.starts_with('/'), "normalized path must be absolute");
    assert!(
        !norm.starts_with("//"),
        "normalized path has exactly one leading slash"
    );

    // the core safety invariant: no `..` segment may survive — joining
    // onto a document root can then never climb above it lexically.
    // (symlink escape is an intentional nginx-parity policy, not part
    // of this invariant; on Windows `\` is also a separator — this
    // target is exercised on unix where it is an ordinary byte)
    for seg in norm.split('/') {
        assert_ne!(seg, "..", "traversal segment survived normalization");
        assert!(!seg.contains('\0'), "NUL survived normalization");
        assert!(
            !seg.chars().any(|c| c.is_control()),
            "control char survived normalization: {seg:?}"
        );
    }
    let root = std::path::Path::new("/var/www/site");
    let joined = root.join(norm.trim_start_matches('/'));
    assert!(joined.starts_with(root));
    assert!(
        !joined
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir)),
        "{joined:?} escapes the document root"
    );
});

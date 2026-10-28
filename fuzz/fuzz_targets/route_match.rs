#![no_main]
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn index() -> &'static verd::router::HostIndex {
    static IDX: OnceLock<verd::router::HostIndex> = OnceLock::new();
    IDX.get_or_init(|| {
        let cfg: verd::config::model::Config = toml::from_str(
            r#"
[[site]]
hosts = ["a.test", "*.wild.test"]
default = true
tls = "off"

[[site.route]]
exact = "/exact"
respond = { body = "e" }

[[site.route]]
prefix = "/p/"
respond = { body = "p" }

[[site.route]]
regex = "^/rx/[0-9]+$"
respond = { body = "r" }
"#,
        )
        .unwrap();
        let mw = verd::middleware::Factory::new(&cfg, None, verd::BuildMode::Live).unwrap();
        verd::router::build(&cfg, &mw).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let (host, path) = text.split_once('\n').unwrap_or((&text, "/"));
    let Ok(norm) = verd::router::normalize::normalize_path(path) else {
        return;
    };
    let idx = index();
    let Some((_, site)) = idx.lookup_idx(host) else {
        return;
    };
    let Ok(req) = http::Request::builder()
        .method("GET")
        .uri(format!("http://{host}{norm}"))
        .body(())
    else {
        return;
    };
    let req = req.into_parts().0;
    // never panics on arbitrary host/path pairs
    let _ = site.match_route_idx(&req, &norm);
});

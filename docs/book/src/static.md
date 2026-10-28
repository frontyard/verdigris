# Static file serving

```toml
[[site.route]]
prefix = "/"
static = { root = "/var/www/site", index = ["index.html"] }
```

- **Ranges**: `Range: bytes=…` single-range requests return `206` with
  correct `Content-Range`; unsatisfiable ranges get `416`.
- **Validators**: `ETag` and `Last-Modified` are emitted; `If-None-Match`
  and `If-Modified-Since` answer `304`.
- **Precompressed variants**: a `file.css.br`/`.zst`/`.gz` next to
  `file.css` is served directly when the client accepts that encoding —
  the content-encoded bytes are never re-compressed.
- **Traversal safety**: `..` escapes are clamped to the root; NUL and bad
  UTF-8 in paths are rejected with `400` before touching the filesystem.

Directory listings are off by default — requests to a directory redirect
to its `index` or return `404`.

`site.root` is a shorthand for exactly this — `root = "/var/www/site"`
at site level materializes a catch-all `static` route.

## Cache-Control and error pages

`cache_control` maps path globs to `Cache-Control` values. Matching is
by **specificity, not declaration order**: fewest `*` first, then
most literal characters — `"/app.css"` beats `"*.css"` beats `"*"`, so
a catch-all never shadows the specific entries:

```toml
[[site]]
hosts = ["example.com"]
[[site.route]]
prefix = "/"
static = { root = "/var/www/site",
           cache_control = { "*" = "no-cache", "*.css" = "public, max-age=86400" },
           error_pages = { "5xx" = "oops.html", 404 = "not-found.html" } }
```

`error_pages` maps statuses to pages inside `root` — exact codes
(`404`) or whole classes (`"4xx"`, `"5xx"`); an exact code wins over
its class.

# Static file serving

```toml
[[site.route]]
path = "/"
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

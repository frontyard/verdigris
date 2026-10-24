# Caching

A full HTTP response cache in front of any handler — static files and
proxied responses alike.

```toml
[cache.main]
tier = "hybrid"            # ram | disk | hybrid
policy = "lru"           # lru | lfu | fifo
ram_bytes = "256MiB"
disk_bytes = "4GiB"
disk_path = "/var/lib/verd/cache"
max_object_bytes = "16MiB"

[[site.route]]
prefix = "/assets"
cache = { store = "main", ttl = "5m",
          stale_while_revalidate = "30s", stale_if_error = "5m" }
```

## Semantics

Honours `Cache-Control`/`Expires` on responses, request directives
(`no-cache`, `no-store`, `only-if-cached`, `max-age`, `max-stale`,
`min-fresh`), `Vary` (plus forced `vary_headers`), client conditionals
(`If-None-Match`/`If-Modified-Since` → `304`), heuristic freshness,
negative caching (`negative_ttl`, 404s et al. via `cache_statuses`),
`must-revalidate`, `stale-while-revalidate` (background refresh) and
`stale-if-error`. HEAD shares GET's entry.

Requests for the same key **coalesce**: one leader fetches, followers
wait and read the committed entry.

## Bypass and purge

`cache.bypass` skips the cache by path glob, method, request header, or
for authenticated requests (default). `x_cache = true` emits
`X-Cache: HIT|MISS|STALE|BYPASS` on responses.

```sh
curl -XPOST localhost:2019/purge -d '{"store":"main","prefix":"/assets"}'
curl -XPOST localhost:2019/purge -d '{"all":true}'
```

## Tiers

- `ram`: in-memory, budgeted by bytes/items.
- `disk`: content-addressed object files with self-describing heads; the
  index rebuilds at boot, dropping corrupt or partial files.
- `hybrid`: RAM read-through in front of disk; hits promote, the disk
  copy is authoritative.

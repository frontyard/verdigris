# Upgrading

- **Binary**: replace the binary (or image tag) and send `SIGTERM`; the
  drain window lets in-flight requests finish. Rolling upgrades across a
  cluster need no special handling — `/ready` drops first.
- **Config**: `verd validate` after upgrading catches renamed or
  removed fields before rollout. The schema is versioned with the binary;
  `verd schema` prints it.
- **State**: disk caches and ACME storage are forward-compatible within
  V1; entries that fail to parse are dropped at rebuild, never fatal.
- Zero-downtime config changes never need a binary restart — see
  [reload semantics](./admin.md#reload-semantics).

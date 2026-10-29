# Installation

## Prebuilt binaries

Release tags publish static musl binaries for `x86_64` and `aarch64`
Linux. Download the archive for your platform, verify the checksum, and
place the binary on your `PATH`:

```sh
curl -LO https://github.com/frontyard/verdigris/releases/download/v1.0.0/verd-x86_64-unknown-linux-musl.tar.gz
sha256sum -c checksums.txt --ignore-missing
tar xzf verd-*.tar.gz
sudo install -m755 verd /usr/local/bin/
```

Release artifacts are signed with cosign (keyless). The SBOM
(`verd-sbom.json`) is attached to every release.

## Docker

```sh
docker run --read-only \
  -v $PWD/verd.toml:/etc/verd/verd.toml:ro \
  -v verd-data:/var/lib/verd \
  -p 8080:8080 -p 127.0.0.1:2019:2019 \
  ghcr.io/frontyard/verdigris:latest
```

See [Docker & deployment](./docker.md).

## From source

Rust 1.88 or newer:

```sh
cargo install --path .
verd version
```

> **Crates.io note:** the package publishes as **`verd`** — `cargo
> install verd` installs the `verd` binary once the first crates release
> lands. Until then, installing from a checkout or a release artifact
> always works.

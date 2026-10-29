# Installation

## Prebuilt binaries

Release tags publish static musl binaries for `x86_64` and `aarch64`
Linux. Download the archive for your platform, verify the checksum, and
place the binary on your `PATH`:

```sh
curl -LO https://github.com/frontyard/verdigris/releases/download/v1.1.0/verd-x86_64-unknown-linux-musl.tar.gz
sha256sum -c checksums.txt --ignore-missing
tar xzf verd-*.tar.gz
sudo install -m755 verd /usr/local/bin/
```

Release artifacts are signed with cosign (keyless). The SBOM
(`verd-sbom.json`) is attached to every release.

## Debian package

Releases also publish `.deb` packages (`amd64`/`arm64`) wrapping the
same musl binary. Installing one creates the `verd` system user, a
commented default config at `/etc/verd/verd.toml` (a conffile —
upgrades keep your edits), and enables the `verd.service` systemd
unit, which starts on port 80 answering 404/421 until you add a site:

```sh
curl -LO https://github.com/frontyard/verdigris/releases/download/v1.1.0/verd_1.0.0-1_amd64.deb
sudo apt install ./verd_1.0.0-1_amd64.deb
sudoedit /etc/verd/verd.toml && sudo systemctl reload verd
```

State lives in `/var/lib/verd` (ACME accounts, issued certs, disk
cache) and logs in `/var/log/verd`. `apt remove verd` keeps them and
your config; `apt purge verd` removes everything except the `verd`
user.

## RPM package

The same layout is published as `.rpm` (`x86_64`/`aarch64`) for
Fedora, RHEL, openSUSE, and friends:

```sh
curl -LO https://github.com/frontyard/verdigris/releases/download/v1.1.0/verd-1.0.0-1.x86_64.rpm
sudo dnf install ./verd-1.0.0-1.x86_64.rpm
sudoedit /etc/verd/verd.toml && sudo systemctl enable --now verd
```

Unlike the `.deb`, the unit follows the distro's preset policy — on
most RPM systems it stays disabled until you `systemctl enable --now`.
`rpm -e verd` removes the package but keeps state and your edited
config (saved as `.rpmsave`).

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

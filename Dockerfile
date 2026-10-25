# Verdigris — static musl build on distroless, non-root, read-only root.
#
# Writable directories at runtime (mount volumes or tmpfs as needed):
#   /var/lib/verd   — disk cache tiers and ACME account/cert storage
#   /var/log/verd   — access-log files when `log.access.output` is a path
#   /etc/verd       — mount your verd.toml (+ cert files) read-only
#
# Build:  docker build -t verd .
# Run:    docker run --read-only -v $PWD/verd.toml:/etc/verd/verd.toml:ro \
#           -v verd-data:/var/lib/verd -p 8080:8080 verd

FROM clux/muslrust:stable@sha256:cdcf741f1f5f6f2c3cd6328ba925940742c180ad22c15d99f40035c34ad2cb45 AS build
WORKDIR /src
# bake the source SHA into the binary (/version, --version):
#   docker build --build-arg VERD_GIT_SHA=$(git rev-parse HEAD) -t verd .
ARG VERD_GIT_SHA=
ENV VERD_GIT_SHA=${VERD_GIT_SHA}
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked \
    && strip target/x86_64-unknown-linux-musl/release/verd

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/verd /usr/bin/verd
USER nonroot
VOLUME ["/var/lib/verd", "/var/log/verd"]
EXPOSE 8080 2019
ENTRYPOINT ["/usr/bin/verd"]
CMD ["run", "--config", "/etc/verd/verd.toml"]

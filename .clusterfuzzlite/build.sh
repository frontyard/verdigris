#!/bin/bash -eu
# Build every fuzz target and copy the binaries to $OUT.
# Consumed by ClusterFuzzLite (.clusterfuzzlite/Dockerfile copies this
# to $SRC); for an OSS-Fuzz resubmission it copies verbatim to
# projects/verdigris/build.sh.
cd "$SRC"/verdigris/fuzz

if [ "$SANITIZER" = "coverage" ]; then
  export RUSTFLAGS="$RUSTFLAGS -C debug-assertions=no"
  export CFLAGS=""
fi

cargo fuzz build -O --debug-assertions

for target in config_parse path_normalize route_match cache_index \
              http_semantics headers_policy static_resolve; do
    cp target/x86_64-unknown-linux-gnu/release/$target "$OUT"/
done

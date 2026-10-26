# ClusterFuzzLite build image for verdigris.
#
# Consumed by .github/workflows/cflite_*.yml through
# google/clusterfuzzlite/actions/build_fuzzers. The docker build
# context is the repo checkout, so .dockerignore applies — `COPY .`
# pulls in only what's needed (src/, fuzz/, Cargo.*, build.rs).
#
# For an OSS-Fuzz resubmission this becomes
# projects/verdigris/Dockerfile with `COPY . $SRC/verdigris` replaced
# by `RUN git clone --depth 1 https://github.com/frontyard/verdigris
# $SRC/verdigris` (OSS-Fuzz clones the repo itself; ClusterFuzzLite
# copies the workflow checkout in).
FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:3428d0a90b1e7efbe2ba947bd1d0c9a70594986b4b6553804547f1fb24cfc92f
COPY . $SRC/verdigris
WORKDIR $SRC/verdigris
COPY ./.clusterfuzzlite/build.sh $SRC/

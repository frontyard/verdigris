#!/bin/sh
# %pre — runs before the payload is unpacked, so the account must exist
# already for rpm to resolve the verd-owned directory assets
getent group verd >/dev/null 2>&1 || groupadd -r verd
getent passwd verd >/dev/null 2>&1 || useradd -r -g verd \
    -d /var/lib/verd -M -s /sbin/nologin verd

exit 0

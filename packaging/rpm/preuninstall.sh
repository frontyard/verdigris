#!/bin/sh
# %preun — $1 = number of installed copies remaining after removal
# (0 = final erase, 1 = upgrade in progress)
if [ "$1" -eq 0 ]; then
    systemctl --no-reload disable --now verd.service >/dev/null 2>&1 || true
fi

exit 0

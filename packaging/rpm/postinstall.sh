#!/bin/sh
# %post — $1 = number of installed copies after this run (1 = fresh
# install, 2 = upgrade)
install -d -o verd -g verd -m 0750 /var/lib/verd /var/log/verd

systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" -eq 1 ]; then
    # fresh install: leave enablement to the distro's preset policy
    # (Fedora/RHEL presets disable new units by default)
    systemctl preset verd.service >/dev/null 2>&1 || true
fi

exit 0

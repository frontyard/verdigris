#!/bin/sh
# %postun — on upgrade the package stays, so just restart onto the new
# binary; on final erase only the daemon reload matters. State under
# /var/lib/verd and /var/log/verd is kept (rpm has no purge).
systemctl daemon-reload >/dev/null 2>&1 || true
if [ "$1" -ge 1 ]; then
    systemctl try-restart verd.service >/dev/null 2>&1 || true
fi

exit 0

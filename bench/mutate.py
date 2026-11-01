#!/usr/bin/env python3
"""Sliding-window mutator: bumps EXT-X-MEDIA-SEQUENCE and slides the
segment list on a random playlist every ~0.25s, like a live 24h-DVR
HLS origin. Atomic replace so readers never see a torn file."""
import os, random, sys, time

d = sys.argv[1] if len(sys.argv) > 1 else "bench/www/m3u8"
files = sorted(f for f in os.listdir(d) if f.endswith(".m3u8"))
if not files:
    sys.exit(0)
seq_path = os.path.join(d, ".seq")
seq = int(open(seq_path).read()) if os.path.exists(seq_path) else 87000
while True:
    f = os.path.join(d, random.choice(files))
    lines = open(f).read().splitlines()
    seq += 1
    # slide: drop one segment line, append the next one
    out, dropped = [], False
    for ln in lines:
        if ln.startswith("#EXT-X-MEDIA-SEQUENCE:"):
            out.append(f"#EXT-X-MEDIA-SEQUENCE:{seq}")
        elif not dropped and ln.endswith(".ts"):
            dropped = True          # consume the EXTINF+uri pair
            if out and out[-1].startswith("#EXTINF"):
                out.pop()
            continue
        else:
            out.append(ln)
    out.append("#EXTINF:4.000,")
    out.append(f"seg{seq:08d}.ts")
    tmp = f + ".tmp.%d" % os.getpid()  # pid-unique: stale mutators can't collide
    open(tmp, "w").write("\n".join(out) + "\n")
    os.replace(tmp, f)
    open(seq_path, "w").write(str(seq))
    time.sleep(0.25)

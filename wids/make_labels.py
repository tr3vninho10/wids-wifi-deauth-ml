"""Label a REAL lab capture. Frames are 'attack' if they are deauth/disassoc frames sent
during the interval when you ran the attack (seconds from start of capture).
  python -m wids.make_labels data/lab1 --start 60 --end 120     (expects data/lab1.pcap)
Then:  python -m wids.train lab1_train lab1_test   (split your captures into train/test files)"""
import argparse, numpy as np
from .frames import read_pcap

ap = argparse.ArgumentParser()
ap.add_argument("base"); ap.add_argument("--start", type=float, required=True)
ap.add_argument("--end", type=float, required=True)
a = ap.parse_args()
frames = list(read_pcap(a.base + ".pcap"))
n_all = max(f.idx for f in frames) + 1
t0 = frames[0].ts
lab = np.zeros(n_all, dtype=int)
for f in frames:
    if f.ftype == 0 and f.subtype in (10, 12) and a.start <= f.ts - t0 <= a.end:
        lab[f.idx] = 1
np.savetxt(a.base + ".labels.csv", lab, fmt="%d")
print(f"{lab.sum()} attack frames labelled of {n_all}")

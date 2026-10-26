"""Turn frames into per-device, per-window feature rows.

One row = one transmitter MAC during one time window (default 1 s).
The same function is used for training and live detection.
"""
import numpy as np
from collections import defaultdict

WINDOW = 1.0
DEAUTH, DISASSOC = 12, 10

FEATURES = [
    "frames_per_s",     # how chatty the device is
    "deauth_per_s",     # deauthentication frames
    "disassoc_per_s",   # disassociation frames
    "mgmt_ratio",       # share of management frames
    "data_ratio",       # share of data frames
    "deauth_ratio",     # deauth share of all frames
    "bcast_ratio",      # share sent to broadcast address
    "unique_dst",       # number of distinct targets
    "rssi_mean",        # average signal strength
    "rssi_std",         # signal variation (spoofed frames differ from real AP)
    "seq_jumps",        # sequence-number discontinuities (spoofing clue)
]


def window_features(frames, window=WINDOW):
    """frames: list[Frame] for ONE device in ONE window -> list of feature values."""
    n = len(frames)
    de = sum(f.ftype == 0 and f.subtype == DEAUTH for f in frames)
    di = sum(f.ftype == 0 and f.subtype == DISASSOC for f in frames)
    mg = sum(f.ftype == 0 for f in frames)
    da = sum(f.ftype == 2 for f in frames)
    bc = sum(f.dst == "ff:ff:ff:ff:ff:ff" for f in frames)
    rs = [f.rssi for f in frames if f.rssi is not None]
    sq = [f.seq for f in sorted(frames, key=lambda f: f.ts) if f.seq is not None]
    jumps = sum(((b - a) % 4096) > 20 for a, b in zip(sq, sq[1:]))
    return [n / window, de / window, di / window, mg / n, da / n, de / n, bc / n,
            len({f.dst for f in frames}),
            float(np.mean(rs)) if rs else -100.0,
            float(np.std(rs)) if rs else 0.0,
            jumps]


def extract(frames, window=WINDOW, labels=None):
    """Batch extraction. labels: optional list/array indexed by Frame.idx (1 = attack frame).
    Returns (rows, meta, y). Window label = 1 if it contains any attack frame."""
    groups = defaultdict(list)
    for f in frames:
        groups[(f.src, int(f.ts // window))].append(f)
    rows, meta, y = [], [], []
    for (src, w), fs in sorted(groups.items(), key=lambda kv: kv[0][1]):
        rows.append(window_features(fs, window))
        meta.append((src, w * window))
        if labels is not None:
            y.append(int(any(labels[f.idx] for f in fs)))
    return np.array(rows), meta, np.array(y)

"""Run the trained model on a pcap (replay) or a live monitor-mode interface.

  python -m wids.detect --pcap data/test.pcap            # WIDS: alerts only
  python -m wids.detect --pcap data/test.pcap --prevent  # WIPS: also log + blocklist offender
  sudo python -m wids.detect --iface wlan0mon --prevent  # live (authorised lab only)
"""
import argparse, json, time
from collections import defaultdict
import joblib
from .frames import read_pcap, live_sniff
from .features import window_features, WINDOW, FEATURES


class Detector:
    def __init__(self, model, prevent=False, log="results/alerts.jsonl", blocklist="results/blocklist.txt"):
        self.model, self.prevent = model, prevent
        self.log, self.blocklist = log, blocklist
        self.buf = defaultdict(list)     # src -> frames in current window
        self.win = None
        self.known_aps = set()           # learned from beacons
        self.blocked = set()
        self.alerts = []

    def feed(self, f):
        if f.ftype == 0 and f.subtype == 8:
            self.known_aps.add(f.src)
        w = int(f.ts // WINDOW)
        if self.win is None:
            self.win = w
        if w > self.win:
            self.flush()
            self.win = w
        self.buf[f.src].append(f)

    def flush(self):
        if not self.buf:
            return
        srcs = list(self.buf)
        X = [window_features(self.buf[s]) for s in srcs]
        for s, x, pred in zip(srcs, X, self.model.predict(X)):
            if pred:
                self.alert(s, dict(zip(FEATURES, x)))
        self.buf = defaultdict(list)

    def alert(self, src, feats):
        t = self.win * WINDOW
        spoofed = src in self.known_aps
        msg = (f"[ALERT] t={t:.0f}s deauth/disassoc flood from {src} "
               f"({feats['deauth_per_s']:.0f} deauth/s, {feats['disassoc_per_s']:.0f} disassoc/s)"
               + ("  [source is a known AP -> BSSID spoofing]" if spoofed else ""))
        print(msg)
        rec = {"t": t, "src": src, "spoofed_ap": spoofed, **{k: round(v, 2) for k, v in feats.items()}}
        self.alerts.append(rec)
        if self.prevent:
            self.respond(src, spoofed, rec)

    def respond(self, src, spoofed, rec):
        """WIPS action: log every detection; add non-AP offenders to a blocklist.
        A spoofed AP MAC is NOT blocked (that would block the real AP)."""
        with open(self.log, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        if spoofed:
            return
        if src not in self.blocked:
            self.blocked.add(src)
            with open(self.blocklist, "a") as fh:
                fh.write(src + "\n")
            print(f"   [WIPS] blocked {src}  (dry-run: hostapd_cli deny_acl ADD_MAC {src})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap"); ap.add_argument("--iface")
    ap.add_argument("--model", default="models/wids_rf.joblib")
    ap.add_argument("--prevent", action="store_true", help="enable WIPS action")
    a = ap.parse_args()
    det = Detector(joblib.load(a.model), prevent=a.prevent)
    if a.pcap:
        for f in read_pcap(a.pcap):
            det.feed(f)
        det.flush()
        print(f"\n{len(det.alerts)} alerts raised")
    elif a.iface:
        print(f"Sniffing on {a.iface} (Ctrl+C to stop)")
        try:
            live_sniff(a.iface, det.feed)
        except KeyboardInterrupt:
            det.flush()
    else:
        ap.error("give --pcap or --iface")


if __name__ == "__main__":
    main()

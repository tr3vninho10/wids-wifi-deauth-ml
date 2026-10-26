"""Generate a synthetic 802.11 capture (pcap + per-frame labels) for development.

Simulates one AP, several clients, normal traffic, occasional *legitimate* deauths,
and deauth/disassoc flood attacks from a spoofing attacker. This is only a stand-in
for real data: replace it with your own lab capture (see README) for the final results.
"""
import random, sys
import numpy as np
from scapy.all import RadioTap, Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, wrpcap

AP = "aa:bb:cc:00:00:01"
CLIENTS = [f"de:ad:be:ef:00:{i:02x}" for i in range(1, 6)]
BCAST = "ff:ff:ff:ff:ff:ff"
ATTACKER = "66:66:66:00:00:99"


def make(ftype, subtype, src, dst, bssid, seq, rssi, ts, payload=None):
    p = RadioTap(present="dBm_AntSignal", dBm_AntSignal=int(rssi)) / Dot11(
        type=ftype, subtype=subtype, addr1=dst, addr2=src, addr3=bssid, SC=(seq % 4096) << 4)
    if payload is not None:
        p = p / payload
    p.time = ts
    return p


def simulate(duration=900, seed=0, attack_prob=0.35):
    rng = random.Random(seed)
    seqs = {m: rng.randrange(4096) for m in [AP] + CLIENTS}
    pkts = []  # (packet, is_attack)

    def nxt(m):
        seqs[m] += 1
        return seqs[m]

    attack_secs = {}
    t = 0
    while t < duration:                       # schedule attack bursts
        if rng.random() < attack_prob:
            dur = rng.randint(5, 15)
            rate = rng.choice([4, 8, 20, 50, 100, 200])
            kind = rng.choice(["deauth"] * 4 + ["disassoc"])
            spoof = rng.random() < 0.6          # spoof the AP MAC, or use own MAC
            for s in range(t, min(t + dur, duration)):
                attack_secs[s] = (rate, kind, spoof)
            t += dur + rng.randint(5, 20)
        else:
            t += 5
    atk_seq = rng.randrange(4096)

    for s in range(duration):
        for _ in range(10):                   # beacons ~10/s
            ts = s + rng.random()
            pkts.append((make(0, 8, AP, BCAST, AP, nxt(AP), rng.gauss(-45, 3), ts,
                              Dot11Beacon()), 0))
        for c in CLIENTS:                     # client data traffic
            for _ in range(rng.randint(2, 30)):
                ts = s + rng.random()
                pkts.append((make(2, 0, c, AP, AP, nxt(c), rng.gauss(-55, 3), ts), 0))
            if rng.random() < 0.05:           # probe request
                pkts.append((make(0, 4, c, BCAST, BCAST, nxt(c), rng.gauss(-55, 3), s + rng.random()), 0))
        if rng.random() < 0.08:               # legitimate deauth burst (roaming, logoff)
            for _ in range(rng.randint(1, 6)):
                pkts.append((make(0, 12, AP, rng.choice(CLIENTS), AP, nxt(AP),
                                  rng.gauss(-45, 3), s + rng.random(), Dot11Deauth(reason=3)), 0))
        if s in attack_secs:                  # attacker spoofs the AP's MAC
            rate, kind, spoof = attack_secs[s]
            for _ in range(int(rate * rng.uniform(0.8, 1.2))):
                atk_seq += 1
                dst = rng.choice(CLIENTS + [BCAST])
                payload = Dot11Deauth(reason=7) if kind == "deauth" else Dot11Disas(reason=8)
                pkts.append((make(0, 12 if kind == "deauth" else 10, AP if spoof else ATTACKER, dst, AP, atk_seq,
                                  rng.gauss(-49, 4), s + rng.random(), payload), 1))

    pkts = [x for x in pkts if rng.random() > 0.03]    # 3% capture loss
    pkts.sort(key=lambda x: x[0].time)
    return [p for p, _ in pkts], [a for _, a in pkts]


if __name__ == "__main__":
    name, seed = sys.argv[1], int(sys.argv[2])
    pk, lb = simulate(seed=seed)
    wrpcap(f"data/{name}.pcap", pk)
    np.savetxt(f"data/{name}.labels.csv", lb, fmt="%d")
    print(f"{name}: {len(pk)} frames, {sum(lb)} attack frames")

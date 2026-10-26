"""Read 802.11 frames from a pcap file or a live monitor-mode interface."""
from dataclasses import dataclass
from typing import Iterator, Optional
from scapy.all import RadioTap, Dot11, PcapReader, sniff


@dataclass
class Frame:
    idx: int            # position in the capture (used to line up labels)
    ts: float           # timestamp (seconds)
    src: str            # transmitter address (addr2)
    dst: str            # receiver address (addr1)
    ftype: int          # 0 = management, 1 = control, 2 = data
    subtype: int        # e.g. mgmt: 8 beacon, 12 deauth, 10 disassoc
    rssi: Optional[int] # signal strength in dBm (from RadioTap)
    seq: Optional[int]  # 12-bit sequence number


def parse(pkt, idx=0) -> Optional[Frame]:
    if not pkt.haslayer(Dot11):
        return None
    d = pkt[Dot11]
    if d.addr2 is None:          # ACK/CTS have no transmitter
        return None
    rssi = getattr(pkt, "dBm_AntSignal", None) if pkt.haslayer(RadioTap) else None
    seq = (d.SC >> 4) if d.SC is not None else None
    return Frame(idx, float(pkt.time), d.addr2.lower(), (d.addr1 or "").lower(),
                 d.type, d.subtype, rssi, seq)


def read_pcap(path) -> Iterator[Frame]:
    with PcapReader(str(path)) as r:
        for i, pkt in enumerate(r):
            f = parse(pkt, i)
            if f:
                yield f


def live_sniff(iface, handler):
    """Capture on a monitor-mode interface; calls handler(Frame) per frame."""
    counter = {"i": 0}
    def cb(pkt):
        f = parse(pkt, counter["i"]); counter["i"] += 1
        if f:
            handler(f)
    sniff(iface=iface, prn=cb, store=False)

# WIDS/WIPS prototype: ML detection of Wi-Fi deauthentication floods

Detects deauth/disassoc flood attacks from 802.11 frames using a scikit-learn Random Forest.
Optional WIPS mode logs the offender and adds its MAC to a blocklist.

## Pipeline
`pcap / live monitor-mode capture -> Frame (frames.py) -> 1 s window per transmitter MAC (features.py)
-> 11 features -> Random Forest (train.py) -> alert (+ WIPS action) (detect.py)`

Features: frames/s, deauth/s, disassoc/s, mgmt ratio, data ratio, deauth ratio, broadcast ratio,
unique destinations, RSSI mean, RSSI std, sequence-number jumps.
(A spoofed-AP flood mixes attacker and real-AP frames in one window, so RSSI spread and
sequence jumps expose it.)

## Run
```
pip install -r requirements.txt
python -m wids.simulate train 1        # synthetic capture (stand-in data)
python -m wids.simulate test 3
python -m wids.train                   # accuracy, confusion matrices -> results/
python -m wids.detect --pcap data/test.pcap             # WIDS
python -m wids.detect --pcap data/test.pcap --prevent   # WIPS
sudo python -m wids.detect --iface wlan0mon --prevent   # live, lab only
```

## Using real data (do this for the final results)
Only on your own isolated lab network (own AP + own client + monitor-mode adapter), or an
approved testbed:
1. `sudo airmon-ng start wlan0`, then capture: `sudo airodump-ng -w data/lab1 --output-format pcap wlan0mon`
   (or `tcpdump -i wlan0mon -w data/lab1.pcap`). Capture normal traffic first, then run your
   authorised deauth test against your own AP for a known time window, then stop.
2. `python -m wids.make_labels data/lab1 --start 60 --end 120` (seconds into the capture).
3. Capture a second file for testing, label it, and run `python -m wids.train lab1 lab2`.
Alternative: convert a small AWID3 subset to pcap and label with the same script.

## Notes / honest limitations
- Included results come from the **simulator**, so they are optimistic. Report real-capture
  numbers on the poster and say which data you used.
- Train and test captures are separate files (different random seeds), not a random split of one file.
- WIPS never blocks a MAC that is a known AP (attackers usually spoof the AP's MAC; blocking it would
  cut off the real AP). In that case it logs a "BSSID spoofing" alert. The blocklist action is a
  dry-run print of `hostapd_cli deny_acl`. Real mitigation is 802.11w (PMF).
- Not a substitute for PMF; window-level labels mean attack edges add a little label noise.

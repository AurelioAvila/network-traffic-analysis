#!/usr/bin/env python3
"""
demo_baseline_vs_fixed.py -- Side-by-side proof that fixed thresholds miss
what a statistical baseline catches.
SOC Home Lab Project | github.com/AurelioAvila

Builds a quiet-network baseline (low, tight per-host traffic) and a
"stealthy flood" capture where an attacker stays deliberately under the
fixed HIGH_VOLUME_THRESHOLD (50 packets) from pcap_analyzer.py, then runs
the analyzer in both modes and prints the verdicts side by side.
"""
import random
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from scapy.all import wrpcap, Ether, IP, TCP, RandShort

from baseline_profile import build_baseline_profile, save_profile, load_profile
from pcap_analyzer import analyze_pcap, HIGH_VOLUME_THRESHOLD

QUIET_BASELINE_PCAP = "baseline_quiet_office.pcap"
QUIET_BASELINE_PROFILE = "baseline_quiet_office.json"
STEALTHY_FLOOD_PCAP = "stealthy_flood_demo.pcap"


def build_quiet_baseline(seed=7):
    random.seed(seed)
    packets = []
    for i in range(20):
        src = f"192.168.2.{10 + i}"
        for _ in range(random.randint(4, 9)):
            packets.append(Ether() / IP(src=src, dst="93.184.216.34") / TCP(sport=RandShort(), dport=443))
    wrpcap(QUIET_BASELINE_PCAP, packets)
    return QUIET_BASELINE_PCAP


def build_stealthy_flood_capture(seed=7, flood_packets=35):
    """Same quiet background traffic, plus one host flooding at a volume
    deliberately kept under the fixed-threshold trigger point."""
    assert flood_packets < HIGH_VOLUME_THRESHOLD, (
        f"Demo requires flood_packets < HIGH_VOLUME_THRESHOLD ({HIGH_VOLUME_THRESHOLD}) "
        "to prove the fixed-threshold blind spot"
    )
    random.seed(seed)
    packets = []
    for i in range(20):
        src = f"192.168.2.{10 + i}"
        for _ in range(random.randint(4, 9)):
            packets.append(Ether() / IP(src=src, dst="93.184.216.34") / TCP(sport=RandShort(), dport=443))
    for _ in range(flood_packets):
        packets.append(Ether() / IP(src="192.168.2.250", dst="192.168.2.1") / TCP(sport=RandShort(), dport=445))
    wrpcap(STEALTHY_FLOOD_PCAP, packets)
    return STEALTHY_FLOOD_PCAP, flood_packets


def main():
    print("=" * 70)
    print(" DEMO: fixed threshold vs. statistical baseline")
    print("=" * 70)

    build_quiet_baseline()
    profile = build_baseline_profile(QUIET_BASELINE_PCAP)
    save_profile(profile, QUIET_BASELINE_PROFILE)
    print(f"\n[*] Quiet-office baseline: mean {profile['packets_per_ip']['mean']} "
          f"packets/host, stdev {profile['packets_per_ip']['stdev']}")

    _, flood_packets = build_stealthy_flood_capture()
    print(f"[*] Stealthy flood capture: attacker sends {flood_packets} packets "
          f"(fixed threshold triggers at {HIGH_VOLUME_THRESHOLD})")

    fixed_findings = analyze_pcap(STEALTHY_FLOOD_PCAP, baseline=None)
    baseline_findings = analyze_pcap(STEALTHY_FLOOD_PCAP, baseline=load_profile(QUIET_BASELINE_PROFILE))

    print("\n" + "-" * 70)
    print(" RESULT")
    print("-" * 70)
    print(f" Fixed-threshold mode  -> high_volume_ips flagged: {len(fixed_findings['high_volume_ips'])}"
          f"  (needs >= {HIGH_VOLUME_THRESHOLD} packets, attacker sent {flood_packets})")
    print(f" Baseline mode         -> anomaly_flood_ips flagged: {len(baseline_findings['anomaly_flood_ips'])}")
    for ip, data in baseline_findings["anomaly_flood_ips"].items():
        print(f"   {ip}: {data['packets']} packets, z-score {data['z_score']}")

    if not fixed_findings["high_volume_ips"] and baseline_findings["anomaly_flood_ips"]:
        print("\n[+] Confirmed: the fixed threshold missed this flood entirely.")
        print("    The baseline flagged it because it's tuned to *this* network's")
        print("    actual normal traffic, not a number that happened to work elsewhere.")
    else:
        print("\n[!] Unexpected result for this seed/threshold combination.")


if __name__ == "__main__":
    main()

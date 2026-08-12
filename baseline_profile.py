#!/usr/bin/env python3
"""
baseline_profile.py -- Statistical baseline builder for network anomaly detection
SOC Home Lab Project | github.com/AurelioAvila

Fixed thresholds ("50 packets = flood") break the moment traffic volume on a
network changes -- a threshold tuned for a quiet home lab floods a Tier 1
analyst with false positives on a busy office segment, and misses a slow
flood on a quiet one. This module builds a statistical baseline of what
*normal* traffic looks like on a given network and flags deviations from it
(z-score), instead of hardcoding what "too much" means.
"""
import argparse
import json
import statistics
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from scapy.all import rdpcap, wrpcap, Ether, IP, TCP, UDP, Raw, RandShort
except ImportError:
    print("[!] scapy not installed. Run: python -m pip install scapy")
    sys.exit(1)

import random

BASELINE_PROFILE_FILE = "baseline_profile.json"


# ── Baseline traffic generator ─────────────────────────────────────────────

def generate_baseline_pcap(output_file="baseline_normal.pcap", n_ips=25, seed=42):
    """Simulate a normal business-hours traffic sample: many IPs, moderate and
    varied packet counts and port diversity, no attack patterns.
    """
    random.seed(seed)
    packets = []
    print(f"[*] Generating baseline traffic sample from {n_ips} internal hosts...")

    common_dports = [80, 443, 53, 22, 445, 3389, 25, 993]

    for i in range(n_ips):
        src = f"192.168.1.{10 + i}"
        # Each host talks to a handful of destinations over a small number
        # of common ports -- this is what "normal" looks like.
        packet_count = random.randint(8, 45)
        port_diversity = random.randint(1, 4)
        dports = random.sample(common_dports, k=port_diversity)
        for _ in range(packet_count):
            dport = random.choice(dports)
            dst = f"93.184.216.{random.randint(1, 250)}"
            proto = random.choice([TCP, UDP])
            pkt = (Ether() / IP(src=src, dst=dst) /
                   proto(sport=RandShort(), dport=dport))
            packets.append(pkt)

    wrpcap(output_file, packets)
    print(f"[+] Baseline PCAP saved: {output_file} ({len(packets)} packets, {n_ips} hosts)")
    return output_file


# ── Baseline statistics ─────────────────────────────────────────────────────

def build_baseline_profile(pcap_file):
    """Compute per-metric mean/stdev across all source IPs in a known-normal
    capture: packets-per-IP and unique-destination-ports-per-IP.
    """
    packets = rdpcap(pcap_file)
    packet_counts = defaultdict(int)
    port_sets = defaultdict(set)

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
        src = pkt[IP].src
        packet_counts[src] += 1
        if pkt.haslayer(TCP):
            port_sets[src].add(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            port_sets[src].add(pkt[UDP].dport)

    pkt_values = list(packet_counts.values())
    port_values = [len(p) for p in port_sets.values()]

    profile = {
        "source_pcap": pcap_file,
        "hosts_observed": len(packet_counts),
        "packets_per_ip": {
            "mean": round(statistics.mean(pkt_values), 2),
            "stdev": round(statistics.stdev(pkt_values), 2) if len(pkt_values) > 1 else 1.0,
        },
        "ports_per_ip": {
            "mean": round(statistics.mean(port_values), 2),
            "stdev": round(statistics.stdev(port_values), 2) if len(port_values) > 1 else 1.0,
        },
    }
    return profile


def save_profile(profile, path=BASELINE_PROFILE_FILE):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile, f, indent=2)
    print(f"[+] Baseline profile saved: {path}")


def load_profile(path=BASELINE_PROFILE_FILE):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def zscore(value, mean, stdev):
    if stdev == 0:
        stdev = 1.0
    return (value - mean) / stdev


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true",
                         help="Generate a synthetic normal-traffic baseline PCAP first")
    parser.add_argument("pcap", nargs="?", default="baseline_normal.pcap",
                         help="Known-normal PCAP to build the baseline from")
    parser.add_argument("--output", default=BASELINE_PROFILE_FILE,
                         help="Where to save the baseline profile JSON")
    args = parser.parse_args()

    if args.generate:
        generate_baseline_pcap(args.pcap)

    profile = build_baseline_profile(args.pcap)
    save_profile(profile, args.output)

    print("\n[*] Baseline profile:")
    print(json.dumps(profile, indent=2))


if __name__ == "__main__":
    main()

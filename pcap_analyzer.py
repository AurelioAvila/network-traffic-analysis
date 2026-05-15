#!/usr/bin/env python3
"""
pcap_analyzer.py -- Network Traffic Analysis Tool
SOC Home Lab Project | github.com/AurelioAvila
"""

import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import argparse
from datetime import datetime
from collections import defaultdict

if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    from scapy.all import (
        rdpcap, wrpcap, Ether, IP, TCP, UDP,
        Raw, RandShort
    )
except ImportError:
    print("[!] scapy not installed. Run: python -m pip install scapy")
    sys.exit(1)


# ── Configuration ──────────────────────────────────────────────────────────────

SUSPICIOUS_PORTS = {
    4444:  "Metasploit default listener",
    1337:  "Common backdoor port",
    6666:  "Common C2 channel",
    6667:  "IRC / botnet communication",
    31337: "Elite backdoor port",
    9001:  "Tor relay",
    9050:  "Tor SOCKS proxy",
    8888:  "Common malware C2",
}

PORT_SCAN_THRESHOLD  = 10   # unique dst ports from one IP triggers port scan alert
HIGH_VOLUME_THRESHOLD = 50  # packets from one IP triggers flood alert
SEP = "=" * 70


# ── Sample PCAP Generator ──────────────────────────────────────────────────────

def generate_sample_pcap(output_file="sample_capture.pcap"):
    """Generate a realistic PCAP with mixed normal and suspicious traffic."""
    packets = []
    print("[*] Generating sample PCAP with suspicious traffic...")

    # 1. Normal HTTP traffic (background noise)
    for i in range(20):
        pkt = (Ether() /
               IP(src=f"192.168.1.{10 + i}", dst="93.184.216.34") /
               TCP(sport=RandShort(), dport=80, flags="S"))
        packets.append(pkt)

    # 2. Port scan from attacker IP (T1046)
    attacker_ip = "192.168.1.105"
    target_ip   = "192.168.1.1"
    scan_ports  = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443,
                   445, 3306, 3389, 5900, 8080, 8443]
    for port in scan_ports:
        pkt = (Ether() /
               IP(src=attacker_ip, dst=target_ip) /
               TCP(sport=RandShort(), dport=port, flags="S"))
        packets.append(pkt)

    # 3. C2 connection to port 4444 -- Metasploit (T1071)
    for _ in range(5):
        pkt = (Ether() /
               IP(src="10.0.0.50", dst="185.220.101.45") /
               TCP(sport=RandShort(), dport=4444, flags="S"))
        packets.append(pkt)

    # 4. UDP flood -- potential DoS (T1498)
    flood_ip = "10.0.0.77"
    for _ in range(60):
        pkt = (Ether() /
               IP(src=flood_ip, dst="192.168.1.1") /
               UDP(sport=RandShort(), dport=53) /
               Raw(load=b"X" * 512))
        packets.append(pkt)

    # 5. IRC/botnet communication on port 6667 (T1071)
    pkt = (Ether() /
           IP(src="192.168.1.200", dst="91.108.4.167") /
           TCP(sport=RandShort(), dport=6667, flags="S"))
    packets.append(pkt)

    wrpcap(output_file, packets)
    print(f"[+] Sample PCAP saved: {output_file} ({len(packets)} packets)")
    return output_file


# ── Analysis Engine ────────────────────────────────────────────────────────────

def analyze_pcap(pcap_file):
    """Load and analyze a PCAP file. Returns a findings dictionary."""
    print(f"[*] Loading: {pcap_file}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error reading PCAP: {e}")
        sys.exit(1)

    print(f"[+] {len(packets)} packets loaded.")

    findings = {
        "pcap_file":            pcap_file,
        "total_packets":        len(packets),
        "unique_src_ips":       set(),
        "unique_dst_ips":       set(),
        "protocol_counts":      defaultdict(int),
        "ip_packet_counts":     defaultdict(int),
        "ip_dst_ports":         defaultdict(set),
        "port_scan_suspects":   {},
        "high_volume_ips":      {},
        "suspicious_port_hits": [],
    }

    for pkt in packets:
        if not pkt.haslayer(IP):
            continue

        src = pkt[IP].src
        dst = pkt[IP].dst
        findings["unique_src_ips"].add(src)
        findings["unique_dst_ips"].add(dst)
        findings["ip_packet_counts"][src] += 1

        if pkt.haslayer(TCP):
            findings["protocol_counts"]["TCP"] += 1
            dport = pkt[TCP].dport
            findings["ip_dst_ports"][src].add(dport)
            if dport in SUSPICIOUS_PORTS:
                findings["suspicious_port_hits"].append({
                    "src": src, "dst": dst,
                    "port": dport, "proto": "TCP",
                    "reason": SUSPICIOUS_PORTS[dport],
                })

        elif pkt.haslayer(UDP):
            findings["protocol_counts"]["UDP"] += 1
            dport = pkt[UDP].dport
            if dport in SUSPICIOUS_PORTS:
                findings["suspicious_port_hits"].append({
                    "src": src, "dst": dst,
                    "port": dport, "proto": "UDP",
                    "reason": SUSPICIOUS_PORTS[dport],
                })
        else:
            findings["protocol_counts"]["OTHER"] += 1

    # Post-processing: port scan & flood detection
    for ip, ports in findings["ip_dst_ports"].items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings["port_scan_suspects"][ip] = ports

    for ip, count in findings["ip_packet_counts"].items():
        if count >= HIGH_VOLUME_THRESHOLD:
            findings["high_volume_ips"][ip] = count

    return findings


# ── Report Generator ───────────────────────────────────────────────────────────

def generate_report(findings, output_file="report_output.txt"):
    """Generate a structured SOC analyst report and save it to disk."""
    lines = []
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_alerts = (
        len(findings["suspicious_port_hits"]) +
        len(findings["port_scan_suspects"])    +
        len(findings["high_volume_ips"])
    )
    severity = "HIGH" if total_alerts >= 3 else "MEDIUM" if total_alerts >= 1 else "LOW"

    # Header
    lines += [
        SEP,
        " SOC NETWORK TRAFFIC ANALYSIS REPORT",
        f" {now}",
        SEP,
        f" File           : {findings['pcap_file']}",
        f" Total packets  : {findings['total_packets']}",
        f" Unique src IPs : {len(findings['unique_src_ips'])}",
        f" Unique dst IPs : {len(findings['unique_dst_ips'])}",
        " Protocol breakdown:",
    ]
    for proto, count in findings["protocol_counts"].items():
        lines.append(f"   {proto:<6}: {count} packets")
    lines.append(SEP)

    # Section 1 -- Port Scan
    lines += [" [1] PORT SCAN DETECTION", "-" * 70]
    if findings["port_scan_suspects"]:
        for ip, ports in findings["port_scan_suspects"].items():
            lines += [
                f" [!] ALERT -- Port scan detected from: {ip}",
                f"     Unique destination ports : {len(ports)}",
                f"     Ports scanned            : {sorted(ports)}",
                f"     MITRE                    : T1046 -- Network Service Scanning",
            ]
    else:
        lines.append(" [OK] No port scan activity detected.")
    lines.append("")

    # Section 2 -- Suspicious Ports
    lines += [" [2] SUSPICIOUS PORT CONNECTIONS", "-" * 70]
    if findings["suspicious_port_hits"]:
        for hit in findings["suspicious_port_hits"]:
            lines += [
                f" [!] ALERT -- {hit['src']} -> {hit['dst']}:{hit['port']}/{hit['proto']}",
                f"     Reason : {hit['reason']}",
                f"     MITRE  : T1071 -- Application Layer Protocol (C2)",
            ]
    else:
        lines.append(" [OK] No suspicious port connections detected.")
    lines.append("")

    # Section 3 -- High Volume
    lines += [" [3] HIGH VOLUME / FLOOD DETECTION", "-" * 70]
    if findings["high_volume_ips"]:
        for ip, count in findings["high_volume_ips"].items():
            lines += [
                f" [!] ALERT -- High packet volume from: {ip}",
                f"     Packets : {count}",
                f"     MITRE   : T1498 -- Network Denial of Service",
            ]
    else:
        lines.append(" [OK] No high-volume flood activity detected.")
    lines.append("")

    # Verdict
    action = "Escalate to Tier 2 immediately" if severity == "HIGH" else "Monitor and investigate"
    lines += [
        SEP,
        f" VERDICT : {severity} -- {action}",
        f" ALERTS  : {total_alerts} anomalies detected",
        SEP,
    ]

    report_text = "\n".join(lines)
    print("\n" + report_text)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report_text)
    print(f"\n[+] Report saved: {output_file}")

    return report_text


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SOC Network Traffic Analyzer -- AurelioAvila"
    )
    parser.add_argument(
        "pcap", nargs="?", default="sample_capture.pcap",
        help="PCAP file to analyze (default: sample_capture.pcap)"
    )
    parser.add_argument(
        "--generate", action="store_true",
        help="Generate a sample PCAP with suspicious traffic before analyzing"
    )
    parser.add_argument(
        "--output", default="report_output.txt",
        help="Output file for the report (default: report_output.txt)"
    )
    args = parser.parse_args()

    print(SEP)
    print(" SOC Network Traffic Analyzer | github.com/AurelioAvila")
    print(SEP)

    if args.generate:
        generate_sample_pcap(args.pcap)

    findings = analyze_pcap(args.pcap)
    generate_report(findings, args.output)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
DicomGhost - Medical Device Network Traffic Analyzer
Author: Shantanu Shastri
"""

import argparse
import sys
import os
from dicomghost.capture import start_live_capture, load_pcap
from dicomghost.engine import DicomGhostEngine
from dicomghost.output.reporter import Reporter

BANNER = r"""
       ___                            __               __ 
  ____/ (_)________  ____ ___  ____ _/ /_  ____  _____/ /_
 / __  / / ___/ __ \/ __ `__ \/ __ `/ __ \/ __ \/ ___/ __/
/ /_/ / / /__/ /_/ / / / / / / /_/ / / / / /_/ (__  ) /_  
\__,_/_/\___/\____/_/ /_/ /_/\__, /_/ /_/\____/____/\__/  
                            /____/                        
  DICOM Medical Device Network Recon Tool
  Author: Shantanu Shastri
  For authorized security assessments only.
"""

def parse_args():
    parser = argparse.ArgumentParser(
        prog="dicomghost",
        description="Medical device network traffic analyzer for security assessments",
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", metavar="FILE", help="Path to PCAP/PCAPNG file")
    source.add_argument("--iface", metavar="INTERFACE", help="Network interface for live capture")
    parser.add_argument("--duration", type=int, default=30, metavar="SECONDS")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    parser.add_argument("--out", metavar="FILE")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--no-banner", action="store_true")
    parser.add_argument("--version", action="version", version="DicomGhost 0.1.0")
    return parser.parse_args()

def main():
    args = parse_args()
    if not args.no_banner:
        print(BANNER)
    if args.pcap:
        if not os.path.isfile(args.pcap):
            print(f"[!] File not found: {args.pcap}")
            sys.exit(1)
        print(f"[*] Loading PCAP: {args.pcap}")
        packets = load_pcap(args.pcap)
    else:
        print(f"[*] Starting live capture on {args.iface} for {args.duration}s ...")
        packets = start_live_capture(args.iface, args.duration)
    if not packets:
        print("[!] No packets captured or loaded.")
        sys.exit(1)
    print(f"[*] Packets loaded: {len(packets)}")
    print("[*] Running analysis modules...\n")
    engine = DicomGhostEngine(packets, verbose=args.verbose)
    results = engine.run()
    reporter = Reporter(results, fmt=args.output, verbose=args.verbose)
    reporter.print_report()
    if args.out:
        reporter.save(args.out)
        print(f"\n[*] Report saved to: {args.out}")
    if results.has_critical():
        sys.exit(2)
    elif results.has_high():
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()

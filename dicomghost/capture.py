"""medhunt.capture"""
import sys
try:
    from scapy.all import rdpcap, sniff
except ImportError:
    print("[!] Scapy not installed. Run: pip install scapy")
    sys.exit(1)

def load_pcap(filepath):
    try:
        return list(rdpcap(filepath))
    except Exception as e:
        print(f"[!] Failed to read PCAP: {e}")
        sys.exit(1)

def start_live_capture(iface, duration):
    try:
        return list(sniff(iface=iface, timeout=duration, store=True))
    except PermissionError:
        print("[!] Permission denied. Try running with sudo.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Capture failed: {e}")
        sys.exit(1)

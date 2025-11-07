"""
Packet capture and analysis using pyshark
"""

import pyshark
import json
import os
import sys
import subprocess
from datetime import datetime
from typing import Dict, Any


class PacketMetadata:
    def __init__(self, packet):
        self.timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
        self.src_ip = packet.ip.src if hasattr(packet, 'ip') else None
        self.dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
        self.protocol = packet.highest_layer
        self.length = packet.length
        self.src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else None
        self.dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "length": self.length,
            "src_port": self.src_port,
            "dst_port": self.dst_port
        }


class HTTPPacket:
    def __init__(self, packet):
        self.metadata = PacketMetadata(packet)
        self.http = packet.http if hasattr(packet, 'http') else None
        self.headers = {}
        self.body = None
        self.method = None
        self.uri = None
        self.response_code = None
        self._parse_http_layer(packet)

    def _parse_http_layer(self, packet):
        if not self.http:
            return

        for field in dir(packet.http):
            if field.startswith(('request_', 'response_')):
                header_name = field.replace('request_', '').replace('response_', '')
                self.headers[header_name] = getattr(packet.http, field)

        self.method = getattr(packet.http, "request_method", None)
        self.uri = getattr(packet.http, "request_uri", None)
        self.response_code = getattr(packet.http, "response_code", None)

        if hasattr(packet.http, 'file_data'):
            self.body = packet.http.file_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "http_info": {
                "method": self.method,
                "uri": self.uri,
                "response_code": self.response_code,
                "headers": self.headers,
                "body": self.body
            }
        }


class PacketCapture:
    def __init__(self, interface="any", save_raw=False, data_dir="data/raw"):
        self.interface = interface
        self.capture = None
        self.packets = []
        self.save_raw = save_raw
        self.data_dir = data_dir
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")

        if self.save_raw:
            os.makedirs(self.data_dir, exist_ok=True)

        self.stats = {
            "total_packets": 0,
            "http_packets": 0,
            "get_requests": 0,
            "post_requests": 0,
            "high_risk_packets": 0,
            "sensitive_data_detected": 0
        }

    def start_capture(self, duration=None):
        self.capture = pyshark.LiveCapture(
            interface=self.interface,
            display_filter='http'
        )

        print(f"Starting packet capture on interface: {self.interface}")
        print(f"Duration: {'∞' if duration is None else f'{duration}s'}")

        try:
            self.capture.sniff(timeout=duration)

            for packet in self.capture:
                self.process_packet(packet)

        except KeyboardInterrupt:
            print("Stopping packet capture...")
        finally:
            if self.capture:
                self.capture.close()

    def process_packet(self, packet):
        try:
            http_packet = HTTPPacket(packet)
            self.packets.append(http_packet)

            if self.save_raw and http_packet.http:
                self._save_raw_packet(http_packet)

            self.stats["total_packets"] += 1
            if http_packet.http:
                self.stats["http_packets"] += 1
                if http_packet.method == "GET":
                    self.stats["get_requests"] += 1
                elif http_packet.method == "POST":
                    self.stats["post_requests"] += 1

        except Exception as e:
            print(f"Error processing packet: {str(e)}")

    def _save_raw_packet(self, http_packet):
        try:
            filename = f"packets_{self.session_id}.jsonl"
            filepath = os.path.join(self.data_dir, filename)

            packet_data = {
                "timestamp": http_packet.metadata.timestamp.isoformat(),
                "session_id": self.session_id,
                "packet_data": http_packet.to_dict()
            }

            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(json.dumps(packet_data) + '\n')

        except Exception as e:
            print(f"Error saving raw packet: {str(e)}")

    def print_statistics(self):
        print("\nCapture Statistics")
        print("=" * 40)
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"HTTP Packets: {self.stats['http_packets']}")
        print(f"GET Requests: {self.stats['get_requests']}")
        print(f"POST Requests: {self.stats['post_requests']}")
        print("=" * 40)

def list_tshark_interfaces() -> Dict[int, str]:
    """
    Run `tshark -D` and return mapping index -> interface string.
    Returns an empty dict if tshark can't be run.
    """
    try:
        res = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True)
        lines = [l.strip() for l in res.stdout.splitlines() if l.strip()]
        mapping = {}
        for line in lines:
            # Typical lines: "1. \Device\NPF_{...}" or "2. Wi-Fi"
            try:
                idx_s, iface = line.split(".", 1)
                idx = int(idx_s.strip())
                mapping[idx] = iface.strip()
            except Exception:
                # fallback: enumerate
                mapping[len(mapping) + 1] = line
        return mapping
    except Exception:
        return {}
if __name__ == "__main__":
    print("🚀 Real Packet Capture (Windows)")
    print("⚠️  This requires Administrator PowerShell")
    print()

    # enumerate interfaces
    mapping = list_tshark_interfaces()
    if not mapping:
        print("❌ tshark -D returned nothing. Install Wireshark+TShark and ensure tshark in PATH.")
        sys.exit(1)

    print("Available Interfaces:\n")
    for idx, iface in mapping.items():
        print(f"  {idx}) {iface}")
    print()

    while True:
        try:
            choice = int(input("Select interface number: ").strip())
            if choice in mapping:
                break
        except Exception:
            pass
        print("Invalid selection. Try again.\n")

    # mapping[choice] looks like: r"\Device\NPF_{...} (Wi-Fi)" or sometimes just the raw name.
    full_iface = mapping[choice]

    # Extract the raw interface token (left side before " (FriendlyName)")
    # If there is no " (", this returns the whole string unchanged.
    raw_iface = full_iface.split(" (", 1)[0]

    print()
    dur_s = input("Capture duration seconds (ENTER=30): ").strip()
    duration = 30
    if dur_s:
        try:
            duration = int(dur_s)
        except Exception:
            print("Invalid duration, using 30.")

    print(f"\nInterface selected: {full_iface}")
    print(f"Using interface token: {raw_iface}")
    print(f"Duration: {duration}s\n")

    print("💡 Generate HTTP traffic now (browse web etc.)\n")

    try:
        cap = PacketCapture(interface=raw_iface, save_raw=True, data_dir="data/raw")
        cap.start_capture(duration=duration)
        cap.print_statistics()

        if cap.packets:
            print("\nSample packets:")
            for i, packet in enumerate(cap.packets[:3], 1):
                print(f"  {i}: {packet.method} {packet.uri}")
    except PermissionError:
        print("❌ Permission denied: run PowerShell as Administrator")
    except Exception as e:
        print(f"❌ Error: {e}")

"""
Packet capture and analysis using pyshark
"""

import pyshark
import asyncio
import json
import uuid
import os
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
            
        # Extract HTTP headers
        for field in dir(packet.http):
            if field.startswith(('request_', 'response_')):
                header_name = field.replace('request_', '').replace('response_', '')
                self.headers[header_name] = getattr(packet.http, field)
        
        # Extract method, URI, and response code
        self.method = getattr(packet.http, "request_method", None)
        self.uri = getattr(packet.http, "request_uri", None)
        self.response_code = getattr(packet.http, "response_code", None)
        
        # Extract body if available
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
        
        # Create data directory if it doesn't exist
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
        
    async def start_capture(self, duration=None):
        """Start capturing packets with optional duration"""
        # Create capture with custom display filter for HTTP
        self.capture = pyshark.LiveCapture(
            interface=self.interface,
            display_filter='http'  # Focus on HTTP traffic
        )
        
        print(f"Starting packet capture on interface: {self.interface}")
        print(f"Duration: {'∞' if duration is None else f'{duration}s'}")
        
        try:
            # Start packet processing
            if duration:
                self.capture.sniff(timeout=duration)
            else:
                self.capture.sniff_continuously()
                
            for packet in self.capture:
                await self.process_packet(packet)
                
        except KeyboardInterrupt:
            print("\n⛔ Stopping packet capture...")
        finally:
            if self.capture:
                self.capture.close()
                
    async def process_packet(self, packet):
        """Process a single packet"""
        try:
            # Create HTTPPacket object
            http_packet = HTTPPacket(packet)
            self.packets.append(http_packet)
            
            # Save raw packet data if enabled
            if self.save_raw and http_packet.http:
                await self._save_raw_packet(http_packet)
            
            # Update basic statistics
            self.stats["total_packets"] += 1
            if http_packet.http:
                self.stats["http_packets"] += 1
                if http_packet.method == "GET":
                    self.stats["get_requests"] += 1
                elif http_packet.method == "POST":
                    self.stats["post_requests"] += 1
            
            return http_packet
            
        except Exception as e:
            print(f"Error processing packet: {str(e)}")
            return None
    
    async def _save_raw_packet(self, http_packet):
        """Save raw packet data to file"""
        try:
            filename = f"packets_{self.session_id}.jsonl"
            filepath = os.path.join(self.data_dir, filename)
            
            packet_data = {
                "timestamp": http_packet.metadata.timestamp.isoformat(),
                "session_id": self.session_id,
                "packet_data": http_packet.to_dict()
            }
            
            # Append to JSONL file
            with open(filepath, 'a', encoding='utf-8') as f:
                f.write(json.dumps(packet_data) + '\n')
                
        except Exception as e:
            print(f"Error saving raw packet: {str(e)}")
            
    def load_saved_packets(self, session_id=None):
        """Load previously saved packets from file"""
        if session_id is None:
            session_id = self.session_id
            
        filename = f"packets_{session_id}.jsonl"
        filepath = os.path.join(self.data_dir, filename)
        
        packets = []
        try:
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        data = json.loads(line.strip())
                        packets.append(data)
            return packets
        except Exception as e:
            print(f"Error loading packets: {str(e)}")
            return []
        
    def print_statistics(self):
        """Print capture statistics"""
        print("\n📊 Capture Statistics")
        print("=" * 40)
        print(f"Total Packets: {self.stats['total_packets']}")
        print(f"HTTP Packets: {self.stats['http_packets']}")
        print(f"GET Requests: {self.stats['get_requests']}")
        print(f"POST Requests: {self.stats['post_requests']}")
        print(f"High Risk Packets: {self.stats['high_risk_packets']}")
        print(f"Sensitive Data Detected: {self.stats['sensitive_data_detected']}")
        if self.save_raw:
            print(f"Raw data saved to: {self.data_dir}/packets_{self.session_id}.jsonl")
        print("=" * 40)


if __name__ == "__main__":
    """Real packet capture demonstration"""
    import sys
    
    print("🚀 Starting Real Packet Capture...")
    print("⚠️  This requires administrator privileges!")
    
    async def main():
        try:
            # Initialize real packet capture
            capture = PacketCapture(interface="any", save_raw=True, data_dir="data/raw")
            
            # Start capturing for 30 seconds by default
            duration = 30
            if len(sys.argv) > 1:
                try:
                    duration = int(sys.argv[1])
                except ValueError:
                    print("Invalid duration, using default 30 seconds")
            
            print(f"📡 Capturing HTTP traffic for {duration} seconds...")
            print("💡 Generate some HTTP traffic (browse websites, API calls, etc.)")
            print("🛑 Press Ctrl+C to stop early")
            
            await capture.start_capture(duration=duration)
            
            # Print final statistics
            capture.print_statistics()
            
            # Show some captured packets
            if capture.packets:
                print(f"\n📦 Sample captured packets:")
                for i, packet in enumerate(capture.packets[:3], 1):
                    print(f"  Packet {i}: {packet.method} {packet.uri}")
                    print(f"    From: {packet.metadata.src_ip}:{packet.metadata.src_port}")
                    print(f"    To: {packet.metadata.dst_ip}:{packet.metadata.dst_port}")
                    if len(capture.packets) > 3:
                        print(f"  ... and {len(capture.packets) - 3} more packets")
                        break
            else:
                print("\n📦 No HTTP packets captured")
                print("💡 Try browsing websites or making API calls during capture")
            
        except PermissionError:
            print("❌ Permission denied!")
            print("💡 Run as administrator: Right-click PowerShell -> 'Run as administrator'")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            print("� Make sure Wireshark/TShark is installed")
    
    # Run real packet capture
    try:
        import asyncio
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Capture stopped by user")
        print("✅ Real packet capture completed!")
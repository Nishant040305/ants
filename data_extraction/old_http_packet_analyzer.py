"""
Main HTTP Packet Analyzer
Combines packet capture, LLM analysis, and pattern detection
"""

import asyncio
import json
import uuid
from datetime import datetime

from data_extraction.pyshark_packet_capture import PacketCapture, HTTPPacket
from rules.pattern_analyzer import PatternAnalyzer
from model.llm_analyzer import LLMAnalyzer
from .database import DatabaseManager


class HTTPPacketAnalyzer:
    def __init__(self, interface="any"):
        self.packet_capture = PacketCapture(interface)
        self.pattern_analyzer = PatternAnalyzer()
        self.llm_analyzer = LLMAnalyzer()
        self.db = DatabaseManager()
        
        self.stats = {
            "total_packets": 0,
            "http_packets": 0,
            "high_risk_packets": 0,
            "sensitive_data_detected": 0
        }
        
    async def start_analysis(self, duration=None):
        """Start live packet capture and analysis"""
        print(f"🚀 Starting HTTP packet analysis...")
        print(f"⏱️  Duration: {'Continuous' if duration is None else f'{duration} seconds'}")
        print("\n📝 Analysis Configuration:")
        print("- Capturing: HTTP traffic")
        print("- Analysis: Pattern matching + LLM-powered inspection")
        print("- Detection: Sensitive data and security risks")
        print("- Logging: Events to SQLite database")
        print("\n⚡ Live Analysis Feed:")
        
        try:
            await self._capture_and_analyze(duration)
        except KeyboardInterrupt:
            print("\n\n⛔ Analysis stopped by user")
        except Exception as e:
            print(f"\n❌ Error during analysis: {str(e)}")
        finally:
            self._print_final_stats()
            
    async def _capture_and_analyze(self, duration):
        """Internal method to handle packet capture and analysis"""
        # Override the packet capture's process_packet method
        original_process = self.packet_capture.process_packet
        
        async def enhanced_process(packet):
            http_packet = await original_process(packet)
            if http_packet:
                await self._analyze_packet(http_packet)
                
        self.packet_capture.process_packet = enhanced_process
        await self.packet_capture.start_capture(duration)
        
    async def _analyze_packet(self, http_packet: HTTPPacket):
        """Analyze a single HTTP packet"""
        try:
            self.stats["total_packets"] += 1
            
            if not http_packet.http:
                return
                
            self.stats["http_packets"] += 1
            
            # Create payload for analysis
            payload = {
                "id": str(uuid.uuid4()),
                "ts": http_packet.metadata.timestamp.timestamp(),
                "direction": "request" if http_packet.method else "response",
                "host": http_packet.metadata.dst_ip,
                "path": http_packet.uri,
                "method": http_packet.method,
                "headers": http_packet.headers,
                "body": http_packet.body,
                "source": "packet_capture"
            }
            
            # Pattern-based analysis
            pattern_result = self.pattern_analyzer.analyze_payload(payload)
            
            # LLM analysis for packets with content
            llm_result = None
            if http_packet.body or http_packet.headers:
                llm_result = await self.llm_analyzer.analyze_packet(http_packet)
                
            # Determine final risk assessment
            final_result = self._combine_analyses(pattern_result, llm_result)
            
            # Handle high-risk packets
            if final_result["risk_level"] in ["high", "critical"]:
                self.stats["high_risk_packets"] += 1
                await self._handle_high_risk_packet(http_packet, final_result)
                
            if final_result.get("sensitive_data_detected", False):
                self.stats["sensitive_data_detected"] += 1
                
        except Exception as e:
            print(f"Error analyzing packet: {str(e)}")
            
    def _combine_analyses(self, pattern_result, llm_result):
        """Combine pattern and LLM analysis results"""
        if not llm_result:
            # Use pattern analysis only
            risk_mapping = {
                "allow": "low", 
                "alert": "medium",
                "redact": "high", 
                "block": "critical"
            }
            return {
                "severity": pattern_result["severity"],
                "risk_level": risk_mapping.get(pattern_result["decision"], "medium"),
                "findings": pattern_result["tags"],
                "recommendations": [f"Pattern-based decision: {pattern_result['decision']}"],
                "sensitive_data_detected": len(pattern_result["tags"]) > 0,
                "explanation": pattern_result["reason"]
            }
        
        # Combine both analyses (prefer LLM for final decision)
        combined_severity = max(pattern_result["severity"], llm_result["severity"])
        combined_findings = list(set(pattern_result["tags"] + llm_result["findings"]))
        
        return {
            "severity": combined_severity,
            "risk_level": llm_result["risk_level"],
            "findings": combined_findings,
            "recommendations": llm_result["recommendations"],
            "sensitive_data_detected": llm_result["sensitive_data_detected"] or len(pattern_result["tags"]) > 0,
            "explanation": f"Pattern: {pattern_result['reason']} | LLM: {llm_result['explanation']}"
        }
        
    async def _handle_high_risk_packet(self, packet, analysis):
        """Handle high-risk packet detection"""
        print("\n🚨 High Risk Packet Detected!")
        print("=" * 60)
        print(f"Time: {packet.metadata.timestamp}")
        print(f"Risk Level: {analysis['risk_level'].upper()}")
        print(f"Severity Score: {analysis['severity']}/10")
        print(f"\nSource: {packet.metadata.src_ip}:{packet.metadata.src_port}")
        print(f"Destination: {packet.metadata.dst_ip}:{packet.metadata.dst_port}")
        print(f"Method: {packet.method}")
        print(f"URI: {packet.uri}")
        print("\nFindings:")
        for finding in analysis["findings"]:
            print(f"• {finding}")
        print("\nRecommendations:")
        for rec in analysis["recommendations"]:
            print(f"• {rec}")
        print("=" * 60)
        
        # Store event in database
        event = {
            "ts": packet.metadata.timestamp.timestamp(),
            "id": str(uuid.uuid4()),
            "host": packet.metadata.dst_ip,
            "path": packet.uri,
            "direction": "request" if packet.method else "response",
            "severity": analysis["severity"],
            "tags": analysis["findings"],
            "decision": analysis["risk_level"],
            "reason": analysis["explanation"]
        }
        self.db.store_event(event)
        
    def _print_final_stats(self):
        """Print final analysis statistics"""
        print("\n📊 Final Analysis Statistics")
        print("=" * 50)
        print(f"Total Packets Processed: {self.stats['total_packets']}")
        print(f"HTTP Packets: {self.stats['http_packets']}")
        print(f"High Risk Packets: {self.stats['high_risk_packets']}")
        print(f"Sensitive Data Detected: {self.stats['sensitive_data_detected']}")
        
        # Database stats
        db_stats = self.db.get_stats()
        print(f"\n📂 Database Statistics:")
        print(f"Total Events Stored: {db_stats['total_events']}")
        print(f"Recent Events (24h): {db_stats['recent_events']}")
        if db_stats['decisions']:
            print("Events by Risk Level:")
            for decision, count in db_stats['decisions'].items():
                print(f"  {decision}: {count}")
        print("=" * 50)


async def main():
    """Main entry point"""
    print("🔄 Starting HTTP Packet Analyzer...")
    
    try:
        analyzer = HTTPPacketAnalyzer()
        await analyzer.start_analysis()
    except KeyboardInterrupt:
        print("\n👋 Analyzer stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        print("\nTroubleshooting:")
        print("1. Make sure you're running as administrator")
        print("2. Check that Wireshark/TShark is installed")
        print("3. Verify your .env file contains GOOGLE_API_KEY")


async def test_main():
    """Unit tests with sample toy data"""
    print("🧪 Testing HTTPPacketAnalyzer with sample data...")
    print("⚠️  Note: This is a mock test that doesn't require admin privileges")
    
    # Mock HTTPPacket for testing
    class MockHTTPPacket:
        def __init__(self, method, uri, body="", headers=None):
            self.method = method
            self.uri = uri
            self.body = body
            self.headers = headers or {}
            self.timestamp = datetime.now().timestamp()
            self.src_ip = "192.168.1.100"
            self.dst_ip = "10.0.0.1"
            self.src_port = 8080
            self.dst_port = 443
            self.packet_id = str(uuid.uuid4())[:8]
    
    # Create test analyzer (will show warnings for missing API keys)
    print("\n🔧 Initializing components...")
    analyzer = HTTPPacketAnalyzer(interface="test")
    
    # Sample packets for testing
    test_packets = [
        MockHTTPPacket("GET", "/api/health", ""),
        MockHTTPPacket("POST", "/api/login", '{"username": "admin", "password": "secret"}'),
        MockHTTPPacket("GET", "/api/users?token=sk-1234567890", ""),
        MockHTTPPacket("POST", "/api/payment", '{"card": "4111111111111111", "cvv": "123"}'),
        MockHTTPPacket("GET", "/api/profile", "", {"authorization": "Bearer abc123"})
    ]
    
    print(f"\n📦 Processing {len(test_packets)} sample packets...")
    
    # Process each packet through the full pipeline
    results = []
    for i, packet in enumerate(test_packets, 1):
        print(f"\nPacket {i}: {packet.method} {packet.uri}")
        
        try:
            # Pattern analysis - create payload dict for analyzer
            payload = {
                "method": packet.method,
                "uri": packet.uri,
                "body": packet.body,
                "headers": packet.headers
            }
            pattern_result = analyzer.pattern_analyzer.analyze_payload(payload)
            print(f"  📋 Pattern matches: {len(pattern_result.get('issues', []))}")
            
            # Mock LLM analysis (since we may not have API key)
            llm_mock_results = {
                "/api/health": {"decision": "ALLOW", "risk_score": 1.0, "reasoning": "Health check"},
                "/api/login": {"decision": "BLOCK", "risk_score": 8.5, "reasoning": "Credentials in body"},
                "/api/users": {"decision": "BLOCK", "risk_score": 9.0, "reasoning": "Token in URL"},
                "/api/payment": {"decision": "BLOCK", "risk_score": 9.8, "reasoning": "Payment data"},
                "/api/profile": {"decision": "ALLOW", "risk_score": 3.2, "reasoning": "Authorized request"}
            }
            
            llm_result = llm_mock_results.get(packet.uri, {
                "decision": "ALLOW", "risk_score": 2.5, "reasoning": "Default analysis"
            })
            print(f"  🤖 LLM Decision: {llm_result['decision']} (Risk: {llm_result['risk_score']})")
            
            # Combine results
            combined_result = {
                "packet": packet,
                "pattern_analysis": pattern_result,
                "llm_analysis": llm_result,
                "final_decision": llm_result['decision'],
                "total_risk_score": llm_result['risk_score']
            }
            results.append(combined_result)
            
            # Mock database storage
            event_data = {
                "packet_id": packet.packet_id,
                "timestamp": packet.timestamp, 
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "method": packet.method,
                "uri": packet.uri,
                "risk_score": llm_result['risk_score'],
                "pattern_matches": pattern_result.get('issues', []),
                "llm_decision": llm_result['decision'],
                "llm_reasoning": llm_result['reasoning']
            }
            print(f"  💾 Would store event: {event_data['packet_id']}")
            
        except Exception as e:
            print(f"  ❌ Error processing packet: {str(e)}")
    
    # Print summary statistics
    print(f"\n📊 Test Results Summary:")
    print(f"   Total packets processed: {len(results)}")
    
    if results:
        blocked = sum(1 for r in results if r['final_decision'] == 'BLOCK')
        avg_risk = sum(r['total_risk_score'] for r in results) / len(results)
        
        print(f"   Blocked packets: {blocked} ({blocked/len(results)*100:.1f}%)")
        print(f"   Allowed packets: {len(results) - blocked}")
        print(f"   Average risk score: {avg_risk:.2f}")
        
        # Show high-risk packets
        high_risk = [r for r in results if r['total_risk_score'] >= 8.0]
        if high_risk:
            print(f"\n🚨 High-risk packets (score >= 8.0):")
            for packet_result in high_risk:
                p = packet_result['packet']
                score = packet_result['total_risk_score']
                decision = packet_result['final_decision']
                print(f"     {p.method} {p.uri} - Risk: {score}, Decision: {decision}")
    
    print(f"\n✅ HTTPPacketAnalyzer tests completed!")
    print(f"\n💡 To run real analysis:")
    print(f"   1. Set GOOGLE_API_KEY in .env file")
    print(f"   2. Run as administrator") 
    print(f"   3. Use: python -m src.main")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        # Run unit tests
        asyncio.run(test_main())
    else:
        # Run main application
        asyncio.run(main())
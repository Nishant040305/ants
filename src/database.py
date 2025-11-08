"""
Database operations for storing security events
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, Any


class DatabaseManager:
    def __init__(self, db_path: str = "events.db"):
        self.db_path = db_path
        self.init_db()
        
    def init_db(self):
        """Initialize SQLite database for storing security events"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute('''CREATE TABLE IF NOT EXISTS events
                       (ts REAL, id TEXT, host TEXT, path TEXT, direction TEXT, 
                        severity INTEGER, tags TEXT, decision TEXT, reason TEXT)''')
        conn.commit()
        conn.close()
        
    def store_event(self, event: Dict[str, Any]):
        """Store a security event in the database"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?)",
                    (event["ts"], event["id"], event["host"], event["path"], 
                     event["direction"], event["severity"], json.dumps(event["tags"]), 
                     event["decision"], event["reason"]))
        conn.commit()
        conn.close()
        
    def get_events(self, limit: int = 100) -> list:
        """Retrieve recent security events"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
        events = cur.fetchall()
        conn.close()
        return events
        
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        
        # Total events
        cur.execute("SELECT COUNT(*) FROM events")
        total_events = cur.fetchone()[0]
        
        # Events by decision
        cur.execute("SELECT decision, COUNT(*) FROM events GROUP BY decision")
        decisions = dict(cur.fetchall())
        
        # Recent events (last 24 hours)
        yesterday = datetime.now().timestamp() - (24 * 60 * 60)
        cur.execute("SELECT COUNT(*) FROM events WHERE ts > ?", (yesterday,))
        recent_events = cur.fetchone()[0]
        
        conn.close()
        
        return {
            "total_events": total_events,
            "decisions": decisions,
            "recent_events": recent_events
        }


if __name__ == "__main__":
    """Unit tests with sample toy data"""
    import json
    
    print("🧪 Testing DatabaseManager with sample data...")
    
    # Initialize with test database
    db = DatabaseManager(db_path="test.db")
    
    # Sample security events (matching database schema)
    test_events = [
        {
            "ts": datetime.now().timestamp(),
            "id": "pkt_001",
            "host": "192.168.1.100->10.0.0.1",
            "path": "/api/login",
            "direction": "outbound",
            "severity": 8,
            "tags": ["password_in_url", "weak_auth"],
            "decision": "BLOCK",
            "reason": "Credentials exposed in URL parameters"
        },
        {
            "ts": datetime.now().timestamp(),
            "id": "pkt_002",
            "host": "192.168.1.200->10.0.0.2",
            "path": "/api/users",
            "direction": "outbound",
            "severity": 2,
            "tags": [],
            "decision": "ALLOW",
            "reason": "Normal user data request"
        },
        {
            "ts": datetime.now().timestamp(),
            "id": "pkt_003",
            "host": "192.168.1.150->10.0.0.3",
            "path": "/api/auth",
            "direction": "outbound",
            "severity": 9,
            "tags": ["api_key_detected", "sensitive_token"],
            "decision": "BLOCK",
            "reason": "API key exposed in request body"
        }
    ]
    
    # Test storing events
    print(f"\nStoring {len(test_events)} test events...")
    for i, event in enumerate(test_events, 1):
        db.store_event(event)
        print(f"  ✓ Event {i} stored (Severity: {event['severity']}, Decision: {event['decision']})")
    
    # Test retrieving events  
    print("\n📊 Testing event retrieval...")
    recent_events = db.get_events(limit=10)
    print(f"Retrieved {len(recent_events)} recent events")
    
    if recent_events:
        print("\nSample event:")
        sample = recent_events[0]
        print(f"  Timestamp: {sample[0]}")
        print(f"  Packet ID: {sample[1]}")
        print(f"  Host: {sample[2]}")
        print(f"  Path: {sample[3]}")
        print(f"  Direction: {sample[4]}")
        print(f"  Severity: {sample[5]}")
        print(f"  Tags: {sample[6]}")
        print(f"  Decision: {sample[7]}")
        if len(sample) > 8:
            print(f"  Reason: {sample[8][:50]}...")
    
    # Test statistics
    print("\n📈 Testing statistics...")
    stats = db.get_stats()
    print("Database statistics:")
    for key, value in stats.items():
        if isinstance(value, dict):
            print(f"  {key}:")
            for sub_key, sub_value in value.items():
                print(f"    {sub_key}: {sub_value}")
        else:
            print(f"  {key}: {value}")
    
    # Test high-severity events (manual filtering)
    print("\n🚨 Testing high-severity event filtering...")
    all_events = db.get_events()
    high_severity = [event for event in all_events if event[5] >= 8]  # severity is index 5
    print(f"Found {len(high_severity)} high-severity events (severity >= 8)")
    
    # Cleanup test database
    import os
    if os.path.exists("test.db"):
        os.remove("test.db")
        print("\n🧹 Test database cleaned up")
    
    print("\n✅ DatabaseManager tests completed!")
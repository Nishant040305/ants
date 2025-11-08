#!/usr/bin/env python3
"""
ANTS HTTP Packet Analyzer - Main Entry Point
"""
import sys
import asyncio
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.main import main

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 ANTS analyzer stopped by user")
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)
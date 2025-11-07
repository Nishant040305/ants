#!/usr/bin/env python3
"""
Test Runner for ANTS HTTP Packet Analyzer
Runs unit tests for all modules with sample toy data
"""

import subprocess
import sys
import os
from pathlib import Path

def run_module_test(module_path, module_name):
    """Run unit tests for a specific module"""
    print(f"\n{'='*60}")
    print(f"🧪 TESTING: {module_name}")
    print(f"{'='*60}")
    
    try:
        # Change to the ants directory for proper imports
        os.chdir(Path(__file__).parent)
        
        # Run the module's __main__ block
        result = subprocess.run([
            sys.executable, "-m", module_path
        ], capture_output=False, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"✅ {module_name} tests PASSED")
        else:
            print(f"❌ {module_name} tests FAILED (exit code: {result.returncode})")
            
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"⏰ {module_name} tests TIMED OUT")
        return False
    except Exception as e:
        print(f"💥 {module_name} tests ERROR: {str(e)}")
        return False

def main():
    """Run all unit tests"""
    print("🚀 ANTS HTTP Packet Analyzer - Unit Test Runner")
    print("=" * 60)
    print("Running unit tests for all modules with sample toy data...")
    
    # Test modules in dependency order (excluding packet capture which requires admin)
    test_modules = [
        ("rules.pattern_analyzer", "Pattern Analyzer"),
        ("model.llm_analyzer", "LLM Analyzer"),
        ("src.database", "Database Manager"),
        ("src.main", "Main Application (with --test flag)")
    ]
    
    # Note about packet capture
    print("📝 Note: Packet Capture testing skipped (requires admin privileges for real capture)")
    print("   To test packet capture: python -m data_extraction.pyshark_packet_capture")
    
    results = []
    
    for module_path, module_name in test_modules:
        # Special handling for main module test flag
        if "main" in module_path:
            try:
                os.chdir(Path(__file__).parent)
                result = subprocess.run([
                    sys.executable, "-m", module_path, "--test"
                ], capture_output=False, text=True, timeout=60)
                success = result.returncode == 0
            except Exception as e:
                print(f"💥 {module_name} tests ERROR: {str(e)}")
                success = False
        else:
            success = run_module_test(module_path, module_name)
        
        results.append((module_name, success))
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for module_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {module_name}")
    
    print(f"\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! The ANTS system is ready for development.")
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        print("\nCommon issues:")
        print("- Missing GOOGLE_API_KEY in .env file (required for LLM tests)")
        print("- Import path issues (run from ants/ directory)")
    
    print(f"\n💡 To run individual tests:")
    for module_path, module_name in test_modules:
        if "main" in module_path:
            print(f"   python -m {module_path} --test")
        else:
            print(f"   python -m {module_path}")
    print(f"   python -m data_extraction.pyshark_packet_capture  # Real packet capture (admin required)")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
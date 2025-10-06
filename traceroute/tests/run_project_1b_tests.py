#!/usr/bin/env python3
"""
Comprehensive test runner for CS 168 Project 1B - Traceroute Error Handling

This script runs all the test suites for Project 1B error handling scenarios:
- Duplicate packet handling
- Unrelated packet filtering
- Packet drop scenarios
- Non-responsive router/host handling
- Mixed error scenarios

Usage:
    python3 run_project_1b_tests.py
    python3 run_project_1b_tests.py --verbose
    python3 run_project_1b_tests.py --specific test_1b_duplicate_packets
"""

import sys
import unittest
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
for path in (PROJECT_ROOT.parent, PROJECT_ROOT):
    path_str = str(path)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)


def load_test_suite():
    """Load all Project 1B test suites"""
    
    # Import all test modules
    test_modules = [
        'test_1b_error_handling',
        'test_1b_duplicate_packets', 
        'test_1b_unrelated_packets',
        'test_1b_packet_drops',
        'test_1b_non_responsive',
        'test_1b_mixed_scenarios'
    ]
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    for module_name in test_modules:
        try:
            # Import the test module
            module = __import__(module_name)
            
            # Load tests from the module
            module_suite = loader.loadTestsFromModule(module)
            suite.addTest(module_suite)
            
            print(f"✓ Loaded test suite: {module_name}")
            
        except ImportError as e:
            print(f"✗ Failed to import {module_name}: {e}")
            continue
        except Exception as e:
            print(f"✗ Error loading {module_name}: {e}")
            continue
    
    return suite


def load_specific_test_suite(module_name):
    """Load a specific test suite"""
    try:
        module = __import__(module_name)
        loader = unittest.TestLoader()
        return loader.loadTestsFromModule(module)
    except ImportError as e:
        print(f"✗ Failed to import {module_name}: {e}")
        return None
    except Exception as e:
        print(f"✗ Error loading {module_name}: {e}")
        return None


def print_test_summary():
    """Print a summary of what the tests cover"""
    print("=" * 80)
    print("CS 168 Project 1B - Traceroute Error Handling Test Suite")
    print("=" * 80)
    print()
    print("This comprehensive test suite covers all Project 1B error handling scenarios:")
    print()
    
    test_categories = [
        ("Duplicate Packets", [
            "• Identical ICMP Time Exceeded packets",
            "• Duplicate packets with different identifiers",
            "• Duplicate packets with different TTLs", 
            "• Duplicate destination unreachable packets",
            "• Cross-TTL duplicates (late arriving)",
            "• Same router responding at multiple TTLs",
            "• Mixed ICMP type duplicates",
            "• Extreme duplicate scenarios"
        ]),
        ("Unrelated Packets", [
            "• ICMP Echo Request/Reply packets",
            "• UDP packets",
            "• TCP packets", 
            "• ICMP Redirect packets",
            "• ICMP Parameter Problem packets",
            "• ICMP Timestamp packets",
            "• Invalid ICMP types and codes",
            "• Malformed packets",
            "• Wrong protocol packets"
        ]),
        ("Packet Drops", [
            "• Some probes dropped, others respond",
            "• All probes dropped for single TTL",
            "• Intermittent drops across TTLs",
            "• High packet loss rates",
            "• Complete packet loss until destination",
            "• Late arriving responses",
            "• Selective drops by router",
            "• Maximum packet loss scenarios"
        ]),
        ("Non-Responsive Routers/Hosts", [
            "• Single non-responsive router",
            "• Multiple non-responsive routers",
            "• Alternating responsive/non-responsive",
            "• Non-responsive destination host",
            "• Firewall-like blocking behavior",
            "• Partially responsive routers",
            "• Load balancing with non-responsive routers",
            "• Timeout behavior scenarios"
        ]),
        ("Mixed Error Scenarios", [
            "• Duplicates + unrelated + drops combined",
            "• Non-responsive + duplicates + unrelated",
            "• Intermittent drops + duplicates + unrelated",
            "• Late arriving duplicates + drops",
            "• Mixed ICMP types + drops + unrelated",
            "• Extreme mixed scenarios",
            "• Network congestion simulation",
            "• Load balancing with mixed errors"
        ])
    ]
    
    for category, scenarios in test_categories:
        print(f"{category}:")
        for scenario in scenarios:
            print(f"  {scenario}")
        print()
    
    print("Total test scenarios: 50+ individual test cases")
    print("Coverage: All major error handling requirements for Project 1B")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Run CS 168 Project 1B Traceroute Error Handling Tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run_project_1b_tests.py                    # Run all tests
  python3 run_project_1b_tests.py --verbose          # Run with detailed output
  python3 run_project_1b_tests.py --specific test_1b_duplicate_packets  # Run specific suite
  python3 run_project_1b_tests.py --summary          # Show test summary only
        """
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Run tests with verbose output'
    )
    
    parser.add_argument(
        '--specific', '-s',
        type=str,
        help='Run a specific test suite (e.g., test_1b_duplicate_packets)'
    )
    
    parser.add_argument(
        '--summary',
        action='store_true',
        help='Show test summary and exit'
    )
    
    args = parser.parse_args()
    
    if args.summary:
        print_test_summary()
        return 0
    
    print_test_summary()
    
    # Load test suite
    if args.specific:
        print(f"Loading specific test suite: {args.specific}")
        suite = load_specific_test_suite(args.specific)
        if suite is None:
            return 1
    else:
        print("Loading all Project 1B test suites...")
        suite = load_test_suite()
    
    if not suite.countTestCases():
        print("No tests found!")
        return 1
    
    print(f"\nRunning {suite.countTestCases()} test cases...")
    print("=" * 80)
    
    # Configure test runner
    verbosity = 2 if args.verbose else 1
    
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        stream=sys.stdout,
        descriptions=True,
        failfast=False
    )
    
    # Run tests
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print(f"\nFAILURES ({len(result.failures)}):")
        for test, _ in result.failures:
            print(f"  • {test}")
    
    if result.errors:
        print(f"\nERRORS ({len(result.errors)}):")
        for test, _ in result.errors:
            print(f"  • {test}")
    
    if result.wasSuccessful():
        print("\n🎉 All tests passed! Your Project 1B implementation handles errors correctly.")
        return 0
    else:
        print(f"\n❌ {len(result.failures + result.errors)} test(s) failed. Review the output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())

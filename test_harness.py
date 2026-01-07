#!/usr/bin/env python3
"""
DNS Injector Test Harness

Automated testing framework for validating DNS injection implementations
against reference test suite (blackbox-tests.inc).

Usage:
    python test_harness.py blackbox-tests.inc localhost 9000
    python test_harness.py blackbox-tests.inc localhost 9000 --verbose
    python test_harness.py blackbox-tests.inc localhost 9000 --save-report
"""

import sys
import socket
import argparse

from dnsUtils import send_query, receive_response
from testing import (
    parse_blackbox_tests,
    compare_responses,
    calculate_statistics,
    print_test_result,
    print_summary,
    print_failure_details,
    save_detailed_report
)


def query_injector(query_bytes, host, port, timeout=0.5):
    """Send query to injector and get response"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        send_query(sock, query_bytes, host, port)
        response_bytes, _ = receive_response(sock, timeout)
        return response_bytes
    except Exception as e:
        print(f"Error querying injector: {e}")
        return None
    finally:
        sock.close()


def run_tests(tests, host, port, verbose=False):
    """Run all tests and collect results"""
    results = []

    print(f"\n{'=' * 70}")
    print(f"Running {len(tests)} tests against {host}:{port}")
    print(f"{'=' * 70}\n")

    for i, test in enumerate(tests):
        # Query injector
        actual = query_injector(test['query'], host, port)

        # Compare with expected
        result = compare_responses(i, test, actual)
        results.append(result)

        # Print result
        if verbose or not result['passed']:
            print_test_result(result, verbose)
        elif i % 10 == 0:
            # Progress indicator for passing tests
            print(f"Tests {i:3d}-{min(i + 9, len(tests) - 1):3d}: ", end='', flush=True)

    print()  # Final newline
    return results


def main():
    parser = argparse.ArgumentParser(
        description='Test DNS injector against blackbox reference tests',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python test_harness.py blackbox-tests.inc localhost 9000
  python test_harness.py blackbox-tests.inc localhost 9000 --verbose
  python test_harness.py blackbox-tests.inc localhost 9000 -s -o report.txt
        """
    )

    parser.add_argument('tests_file',
                        help='Path to blackbox-tests.inc file')
    parser.add_argument('host',
                        help='Injector hostname or IP address')
    parser.add_argument('port',
                        type=int,
                        help='Injector port number')
    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        help='Show all test results (not just failures)')
    parser.add_argument('--save-report', '-s',
                        action='store_true',
                        help='Save detailed report to file')
    parser.add_argument('--report-file', '-o',
                        default='test_report.txt',
                        help='Report filename (default: test_report.txt)')

    args = parser.parse_args()

    # Parse tests
    print(f"Parsing {args.tests_file}...")
    try:
        tests = parse_blackbox_tests(args.tests_file)
        print(f"Loaded {len(tests)} tests")
    except FileNotFoundError:
        print(f"ERROR: Test file '{args.tests_file}' not found")
        return 1
    except Exception as e:
        print(f"ERROR parsing test file: {e}")
        import traceback
        traceback.print_exc()
        return 1

    if not tests:
        print("ERROR: No tests found in file")
        return 1

    # Run tests
    try:
        results = run_tests(tests, args.host, args.port, args.verbose)
    except KeyboardInterrupt:
        print("\n\nTest run interrupted by user")
        return 1
    except Exception as e:
        print(f"ERROR during test run: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Calculate statistics
    stats = calculate_statistics(results)

    # Print summary
    print_summary(stats)

    # Print failure details (unless verbose already showed them)
    if not args.verbose:
        print_failure_details(results, max_show=10)

    # Save report if requested
    if args.save_report:
        try:
            save_detailed_report(results, stats, args.report_file)
        except Exception as e:
            print(f"ERROR saving report: {e}")
            return 1

    # Exit code: 0 if all passed, 1 if any failed
    return 0 if stats['failed'] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
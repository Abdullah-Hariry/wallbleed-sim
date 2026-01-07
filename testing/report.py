# generates report based on comparator.py findings
"""
Report generation and output formatting
"""
from datetime import datetime


def format_bytes(data, max_len=64):
    """Format bytes as hex string with optional truncation"""
    if data is None:
        return 'None'
    hex_str = data.hex()
    if len(hex_str) > max_len:
        return hex_str[:max_len] + f'... ({len(data)} bytes total)'
    return hex_str


def print_test_result(result, verbose=False):
    """Print a single test result"""
    status = '✓ PASS' if result['passed'] else '✗ FAIL'
    print(f"Test {result['test_num']:3d}: {status} - {result['reason']}")

    if verbose and not result['passed']:
        test = result['test']
        print(f"  Query:    {format_bytes(test['query'])}")
        print(f"  Expected: {format_bytes(test['expected'])}")
        print(f"  Got:      {format_bytes(result['actual'])}")
        print()


def print_summary(stats):
    """Print summary statistics"""
    print(f"\n{'=' * 70}")
    print("TEST SUMMARY")
    print(f"{'=' * 70}\n")

    print(f"Total tests:  {stats['total']}")
    print(f"Passed:       {stats['passed']} ({stats['pass_rate']:.1f}%)")
    print(f"Failed:       {stats['failed']}")

    if stats['failure_categories']:
        print(f"\nFailure breakdown:")
        for cat, count in sorted(stats['failure_categories'].items()):
            print(f"  {cat:25s}: {count}")


def print_failure_details(results, max_show=10):
    """Print detailed failure information"""
    failures = [r for r in results if not r['passed']]

    if not failures:
        return

    print(f"\n{'=' * 70}")
    print(f"FIRST {min(max_show, len(failures))} FAILURES:")
    print(f"{'=' * 70}\n")

    for r in failures[:max_show]:
        print(f"Test {r['test_num']}: {r['reason']}")
        print(f"  Query:    {format_bytes(r['test']['query'], 60)}")
        print(f"  Expected: {format_bytes(r['test']['expected'], 60)}")
        print(f"  Got:      {format_bytes(r['actual'], 60)}")
        print()


def save_detailed_report(results, stats, filename):
    """Save detailed report to file"""
    with open(filename, 'w') as f:
        # Header
        f.write("DNS Injector Test Report\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'=' * 70}\n\n")

        # Summary
        f.write("SUMMARY\n")
        f.write(f"{'=' * 70}\n")
        f.write(f"Total tests: {stats['total']}\n")
        f.write(f"Passed:      {stats['passed']} ({stats['pass_rate']:.1f}%)\n")
        f.write(f"Failed:      {stats['failed']}\n\n")

        if stats['failure_categories']:
            f.write("Failure Categories:\n")
            for cat, count in sorted(stats['failure_categories'].items()):
                f.write(f"  {cat}: {count}\n")
            f.write("\n")

        # Detailed results
        f.write(f"\n{'=' * 70}\n")
        f.write("DETAILED RESULTS\n")
        f.write(f"{'=' * 70}\n\n")

        for r in results:
            status = "PASS" if r['passed'] else "FAIL"
            f.write(f"Test {r['test_num']}: {status}\n")
            f.write(f"  Category: {r['category']}\n")
            f.write(f"  Reason:   {r['reason']}\n")
            f.write(f"  Query:    {r['test']['query'].hex()}\n")

            if r['test']['expected']:
                f.write(f"  Expected: {r['test']['expected'].hex()}\n")
            else:
                f.write(f"  Expected: None\n")

            if r['actual']:
                f.write(f"  Got:      {r['actual'].hex()}\n")
            else:
                f.write(f"  Got:      None\n")

            f.write("\n")

    print(f"Detailed report saved to: {filename}")
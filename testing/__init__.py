"""
DNS Injector Testing Framework
"""
from .blackbox_tests_parser import parse_blackbox_tests
from .comparator import compare_responses, calculate_statistics
from .report import (
    print_test_result,
    print_summary,
    print_failure_details,
    save_detailed_report
)

__all__ = [
    'parse_blackbox_tests',
    'compare_responses',
    'calculate_statistics',
    'print_test_result',
    'print_summary',
    'print_failure_details',
    'save_detailed_report',
]

"""
Compare expected vs actual DNS responses
"""


def compare_responses(test_num, test, actual):
    """
    Compare expected and actual responses

    Returns:
        dict with keys: test_num, test, actual, passed, category, reason
    """
    expected = test['expected']
    category, reason = analyze_difference(expected, actual)

    return {
        'test_num': test_num,
        'test': test,
        'actual': actual,
        'passed': category == 'match',
        'category': category,
        'reason': reason
    }


def analyze_difference(expected, actual):
    """
    Analyze difference between expected and actual

    Returns:
        (category, reason) tuple
    """
    # Both no response
    if expected is None and actual is None:
        return 'match', 'Both no response'

    # Expected no response but got one
    if expected is None and actual is not None:
        return 'unexpected_response', f'Expected no response, got {len(actual)} bytes'

    # Expected response but got none
    if expected is not None and actual is None:
        return 'missing_response', f'Expected {len(expected)} bytes, got no response'

    # Length mismatch
    if len(expected) != len(actual):
        return 'length_mismatch', f'Expected {len(expected)} bytes, got {len(actual)} bytes'

    # Compare byte by byte
    differences = []
    for i, (e, a) in enumerate(zip(expected, actual)):
        if e != a:
            differences.append((i, e, a))

    if not differences:
        return 'match', 'Identical'

    # Content mismatch
    diff_msg = f'{len(differences)} byte(s) differ'
    if len(differences) <= 5:
        details = [f'byte {i}: expected 0x{e:02x}, got 0x{a:02x}'
                   for i, e, a in differences]
        diff_msg += ': ' + '; '.join(details)
    else:
        first_3 = [f'byte {i}: expected 0x{e:02x}, got 0x{a:02x}'
                   for i, e, a in differences[:3]]
        diff_msg += ': ' + '; '.join(first_3) + f'; ... and {len(differences) - 3} more'

    return 'content_mismatch', diff_msg


def calculate_statistics(results):
    """
    Calculate statistics from test results

    Returns:
        dict with: total, passed, failed, pass_rate, failure_categories
    """
    total = len(results)
    passed = sum(1 for r in results if r['passed'])
    failed = total - passed

    # Categorize failures
    categories = {}
    for r in results:
        if not r['passed']:
            cat = r['category']
            categories[cat] = categories.get(cat, 0) + 1

    return {
        'total': total,
        'passed': passed,
        'failed': failed,
        'pass_rate': (passed / total * 100) if total > 0 else 0,
        'failure_categories': categories
    }
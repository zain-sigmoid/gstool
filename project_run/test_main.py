#!/usr/bin/env python3
"""
Test file for testing testability analyzer.
"""

import pytest
from main_code import TestClass


def test_unsafe_sql():
    """Test for unsafe SQL injection pattern."""
    tc = TestClass()
    result = tc.unsafe_sql("test")
    assert "test" in result
    assert "SELECT * FROM users WHERE name = 'test'" == result


def test_calculate_total():
    """Test calculate_total method."""
    tc = TestClass()
    result = tc.calculate_total([1, 2, 3, 4])
    assert result == 10


def test_validate_input():
    """Test validate_input method."""
    tc = TestClass()
    assert tc.validate_input("valid") == True
    assert tc.validate_input("") == False
    assert tc.validate_input(None) == False


def test_process_data():
    """Test process_data method."""
    tc = TestClass()
    result = tc.process_data([1, -1, 2, -2, 3])
    assert result == [2, 4, 6]  # Only positive numbers doubled

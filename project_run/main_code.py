#!/usr/bin/env python3
"""
Test file for testing testability analyzer.
"""


class TestClass:
    """Test class for demonstrating various code patterns."""

    def __init__(self):
        self.data = {}

    def unsafe_sql(self, user_input):
        """Demonstrates unsafe SQL injection pattern."""
        query = f"SELECT * FROM users WHERE name = '{user_input}'"
        return query

    def calculate_total(self, items):
        """Calculate total of items."""
        return sum(items)

    def validate_input(self, data):
        """Validate input data."""
        if not data:
            return False
        return True

    def process_data(self, data):
        """Process data with potential issues."""
        result = []
        for item in data:
            if item > 0:
                result.append(item * 2)
        return result

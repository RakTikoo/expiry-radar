#!/usr/bin/env python3
"""Run the full Expiry Radar test suite (stdlib unittest, zero deps).

Usage:  python3 run_tests.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def main() -> int:
    suite = unittest.defaultTestLoader.discover(
        os.path.join(HERE, "tests"), pattern="test_*.py", top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())

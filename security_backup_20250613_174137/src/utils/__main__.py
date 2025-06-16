#!/usr/bin/env python3
"""
Main entry point for the unified utilities module.

This allows the utils package to be executed as a module:
    python -m src.utils [command] [options]
"""

import sys
from .integration import main

if __name__ == "__main__":
    sys.exit(main())
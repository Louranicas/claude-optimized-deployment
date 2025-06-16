#!/usr/bin/env python3
"""Development Server Runner - Handles imports properly"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'python_src'))

from server import main
import asyncio

if __name__ == "__main__":
    asyncio.run(main())
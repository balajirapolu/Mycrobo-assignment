#!/usr/bin/env python3
"""
Root entrypoint for SlopSentinel.
Can be run directly via `python main.py [scan|triage|fix|dashboard]`.
"""

import sys
from antislop.cli import main

if __name__ == "__main__":
    main()

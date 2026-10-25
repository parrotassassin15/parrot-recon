#!/usr/bin/env python3
"""
Parrot Recon - Web Server Entry Point
Wrapper around webdav/serve_results.py for backward compatibility.
"""
import os
import sys

base_dir = os.path.dirname(os.path.abspath(__file__))
serve_script = os.path.join(base_dir, "serve_results.py")

if __name__ == "__main__":
    os.execv(sys.executable, [sys.executable, serve_script] + sys.argv[1:])

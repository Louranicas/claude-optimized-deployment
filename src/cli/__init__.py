"""
Enhanced CLI package for Claude-Optimized Deployment Engine.

This module provides an intuitive command-line interface with:
- Progressive disclosure of complexity
- Smart defaults and auto-detection
- Clear error messages with recovery suggestions
- Interactive help and tutorials
"""

from .main import cli, create_app

__all__ = ['cli', 'create_app']
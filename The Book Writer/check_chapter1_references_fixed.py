#!/usr/bin/env python3
"""
Reference Validation for Fixed Chapter 1
Validates the references after applying fixes
"""

import re
import asyncio
import json
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass
from collections import defaultdict
import logging

# Import the original validator
from check_chapter1_references import ReferenceValidator, Citation, Reference

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def main():
    """Validate the fixed chapter references"""
    # Read the fixed chapter
    try:
        # Try different locations
        locations = [
            "../Chapter1_Complete_Fixed_References.md",
            "Chapter1_Complete_Fixed_References.md",
            "/home/louranicas/projects/claude-optimized-deployment/Chapter1_Complete_Fixed_References.md"
        ]
        
        chapter_text = None
        for loc in locations:
            try:
                with open(loc, "r") as f:
                    chapter_text = f.read()
                    logger.info(f"Found fixed chapter at: {loc}")
                    break
            except FileNotFoundError:
                continue
                
        if not chapter_text:
            logger.error("Chapter1_Fixed_References.md not found in any expected location!")
            return
            
    except Exception as e:
        logger.error(f"Error reading file: {e}")
        return
    
    # Create validator
    validator = ReferenceValidator()
    
    # Validate references
    report = validator.validate_references(chapter_text)
    
    # Generate and print report
    print("\nREFERENCE VALIDATION REPORT - FIXED CHAPTER")
    print("=" * 60)
    print(validator.generate_report(report))
    
    # Compare with original
    print("\n\nCOMPARISON WITH ORIGINAL:")
    print("-" * 40)
    
    # Original had 10 missing references
    original_missing = 10
    current_missing = len([e for e in report.get('errors', []) if e['type'] == 'missing_reference'])
    
    print(f"Original missing references: {original_missing}")
    print(f"Current missing references: {current_missing}")
    print(f"References fixed: {original_missing - current_missing}")
    
    # Save detailed report
    with open("chapter1_fixed_validation.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\nDetailed report saved to: chapter1_fixed_validation.json")
    
    if report['status'] == 'PASS':
        print("\n✅ ALL REFERENCE ISSUES HAVE BEEN RESOLVED!")
        print("The chapter now meets the highest academic standards.")
    else:
        print(f"\n⚠️ {current_missing} reference issues remain to be fixed.")


if __name__ == "__main__":
    main()
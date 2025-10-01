"""
Core generation logic for the Trivy Test Data Generator.
This module provides backward compatibility by importing from the new trivy module.
"""

# Import from the new trivy module for backward compatibility
from .trivy.generator import TrivyDataGenerator

# Re-export for backward compatibility
__all__ = ["TrivyDataGenerator"]
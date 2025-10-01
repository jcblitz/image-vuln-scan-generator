"""
Field-specific randomization logic for Trivy JSON data.
This module provides backward compatibility by importing from the new trivy module.
"""

# Import from the new trivy module for backward compatibility
from .trivy.randomizers import TrivyRandomizer

# Re-export for backward compatibility with old name
VulnerabilityRandomizer = TrivyRandomizer

__all__ = ["VulnerabilityRandomizer", "TrivyRandomizer"]
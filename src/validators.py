"""
JSON schema validation and integrity checks for Trivy data.
This module provides backward compatibility by importing from the new trivy module.
"""

# Import from the new trivy module for backward compatibility
from .trivy.validators import TrivyValidator

# Re-export for backward compatibility
__all__ = ["TrivyValidator"]
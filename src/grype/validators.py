"""Grype-specific JSON schema validation and integrity checks."""

import re
from typing import Any, Dict, List
from ..base.validator import BaseValidator
from ..logging_config import get_logger


class GrypeValidator(BaseValidator):
    """Grype-specific implementation of base validator for schema validation."""
    
    def __init__(self):
        """Initialize Grype validator with format-specific validation rules."""
        super().__init__()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
        # PURL format regex pattern - simplified
        self.purl_pattern = re.compile(r'^pkg:.+@.+$')
        
        # CVE ID pattern
        self.cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        
        # Valid severity levels for Grype
        self.valid_severities = {"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
        
        self.logger.debug("GrypeValidator initialized")
    
    def _validate_schema(self, data: Dict[str, Any]) -> bool:
        """Validate Grype-specific schema structure."""
        self.logger.debug("Starting Grype schema validation")
        
        # Check required top-level fields
        required_fields = self._get_required_fields()
        if not self._check_required_fields(data, required_fields):
            self.logger.debug("Missing required top-level fields")
            return False
        
        # Validate matches array structure
        if not self._check_matches_structure(data.get("matches", [])):
            self.logger.debug("Invalid matches array structure")
            return False
        
        self.logger.debug("Grype schema validation successful")
        return True
    
    def _get_required_fields(self) -> List[str]:
        """Get required Grype top-level fields."""
        return ["matches"]
    
    def _check_matches_structure(self, matches: List[Dict]) -> bool:
        """Validate matches array structure and contents."""
        if not isinstance(matches, list):
            self.logger.debug("Matches is not a list")
            return False
        
        # Empty matches array is valid
        if not matches:
            return True
        
        # Validate each match - for now, just check basic structure
        for i, match in enumerate(matches):
            if not isinstance(match, dict):
                self.logger.debug(f"Match {i} is not a dictionary")
                return False
        
        return True
    
    def _validate_purl_format(self, purl: str) -> bool:
        """Validate Package URL format."""
        if not isinstance(purl, str):
            self.logger.debug("PURL is not a string")
            return False
        
        if not self.purl_pattern.match(purl):
            self.logger.debug(f"Invalid PURL format: {purl}")
            return False
        
        return True
    
    def _validate_cve_id(self, cve_id: str) -> bool:
        """Validate CVE ID format."""
        if not isinstance(cve_id, str):
            return False
        
        if not self.cve_pattern.match(cve_id):
            self.logger.debug(f"Invalid CVE ID format: {cve_id}")
            return False
        
        return True
    
    def _validate_severity(self, severity: str) -> bool:
        """Validate severity level."""
        if not isinstance(severity, str):
            return False
        
        if severity not in self.valid_severities:
            self.logger.debug(f"Invalid severity level: {severity}")
            return False
        
        return True

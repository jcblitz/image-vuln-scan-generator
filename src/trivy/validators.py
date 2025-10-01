"""
Trivy-specific JSON schema validation extending base validation interface.
"""

from typing import Any, Dict, List

from ..base import BaseValidator
from ..exceptions import ValidationError
from ..logging_config import get_logger


class TrivyValidator(BaseValidator):
    """Trivy-specific implementation of base validator."""
    
    def __init__(self):
        """Initialize Trivy validator."""
        super().__init__()
        self.required_vulnerability_fields = ["VulnerabilityID", "PkgName", "Severity"]
    
    def _validate_schema(self, data: Dict[str, Any]) -> bool:
        """
        Validate Trivy-specific schema.
        
        Args:
            data: JSON data to validate
            
        Returns:
            True if structure is valid
        """
        self.logger.debug("Checking Trivy structure")
        
        # Check required root fields
        required_fields = self._get_required_fields()
        if not self._check_required_fields(data, required_fields):
            self.logger.debug(f"Missing required root fields: {required_fields}")
            return False
        
        # Check SchemaVersion is reasonable
        if not self._validate_field_type(data, "SchemaVersion", int):
            return False
        
        schema_version = data.get("SchemaVersion")
        if schema_version is not None and schema_version < 1:
            self.logger.debug(f"Invalid SchemaVersion: {schema_version}")
            return False
        
        # Check Results structure if present
        if "Results" in data:
            if not self._validate_field_type(data, "Results", list):
                return False
            
            results = data["Results"]
            for i, result in enumerate(results):
                if not isinstance(result, dict):
                    self.logger.debug(f"Result {i} is not a dictionary")
                    return False
                
                # Check vulnerabilities if present
                if "Vulnerabilities" in result:
                    if not self._validate_field_type(result, "Vulnerabilities", list):
                        return False
                    
                    vulnerabilities = result["Vulnerabilities"]
                    if not self._validate_list_items(vulnerabilities, self._check_vulnerability_structure):
                        self.logger.debug(f"Invalid vulnerability structure in result {i}")
                        return False
        
        self.logger.debug("Trivy structure validation passed")
        return True
    
    def _get_required_fields(self) -> List[str]:
        """
        Get required Trivy top-level fields.
        
        Returns:
            List of required field names
        """
        return ["SchemaVersion", "ArtifactName", "ArtifactType"]
    
    def _check_vulnerability_structure(self, vuln: Dict[str, Any]) -> bool:
        """
        Check if vulnerability object has valid Trivy structure.
        
        Args:
            vuln: Vulnerability object to validate
            
        Returns:
            True if structure is valid
        """
        if not isinstance(vuln, dict):
            self.logger.debug("Vulnerability is not a dictionary")
            return False
        
        # Check required vulnerability fields
        if not self._check_required_fields(vuln, self.required_vulnerability_fields):
            missing_fields = [field for field in self.required_vulnerability_fields if field not in vuln]
            self.logger.debug(f"Vulnerability missing required fields: {missing_fields}")
            return False
        
        # Validate severity if present
        if "Severity" in vuln:
            valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
            severity = vuln["Severity"]
            if severity not in valid_severities:
                self.logger.debug(f"Invalid severity: {severity}, valid options: {valid_severities}")
                return False
        
        # Validate CVSS structure if present
        if "CVSS" in vuln:
            if not self._validate_field_type(vuln, "CVSS", dict):
                return False
            
            cvss = vuln["CVSS"]
            # Check CVSS scores are valid floats
            for source_name, source_data in cvss.items():
                if isinstance(source_data, dict):
                    for score_key in ["V2Score", "V3Score"]:
                        if score_key in source_data:
                            score = source_data[score_key]
                            if not self._validate_numeric_range(score, 0.0, 10.0):
                                self.logger.debug(f"Invalid CVSS {score_key} in {source_name}: {score}")
                                return False
        
        # Validate date fields if present
        date_fields = ["PublishedDate", "LastModifiedDate"]
        for date_field in date_fields:
            if date_field in vuln:
                if not self._validate_field_type(vuln, date_field, str):
                    return False
                # Could add more specific date format validation here if needed
        
        return True
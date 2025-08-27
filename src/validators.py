"""
JSON schema validation and integrity checks for Trivy data.
"""

import json
from pathlib import Path
from typing import Any, Dict


class TrivyValidator:
    """Handles validation of Trivy JSON files and generated data."""
    
    def __init__(self):
        """Initialize validator."""
        self.required_root_fields = ["SchemaVersion", "ArtifactName", "ArtifactType"]
        self.required_vulnerability_fields = ["VulnerabilityID", "PkgName", "Severity"]
    
    def validate_input_file(self, file_path: str) -> bool:
        """
        Validate input file is valid Trivy JSON.
        
        Args:
            file_path: Path to the input file
            
        Returns:
            True if valid, False otherwise
        """
        try:
            path = Path(file_path)
            if not path.exists() or not path.is_file():
                return False
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return self._check_trivy_structure(data)
            
        except (json.JSONDecodeError, IOError, KeyError):
            return False
    
    def validate_generated_file(self, data: Dict[str, Any]) -> bool:
        """
        Validate generated file maintains schema.
        
        Args:
            data: Generated JSON data as dictionary
            
        Returns:
            True if valid, False otherwise
        """
        try:
            return self._check_trivy_structure(data)
        except (KeyError, TypeError):
            return False
    
    def _check_trivy_structure(self, data: Dict[str, Any]) -> bool:
        """
        Check if data has valid Trivy structure.
        
        Args:
            data: JSON data to validate
            
        Returns:
            True if structure is valid
        """
        # Check required root fields
        if not self._check_required_fields(data, self.required_root_fields):
            return False
        
        # Check SchemaVersion is reasonable
        if not isinstance(data.get("SchemaVersion"), int) or data["SchemaVersion"] < 1:
            return False
        
        # Check Results structure if present
        if "Results" in data:
            if not isinstance(data["Results"], list):
                return False
            
            for result in data["Results"]:
                if not isinstance(result, dict):
                    return False
                
                # Check vulnerabilities if present
                if "Vulnerabilities" in result:
                    if not isinstance(result["Vulnerabilities"], list):
                        return False
                    
                    for vuln in result["Vulnerabilities"]:
                        if not self._check_vulnerability_structure(vuln):
                            return False
        
        return True
    
    def _check_required_fields(self, data: Dict[str, Any], required_fields: list) -> bool:
        """
        Check presence of required fields.
        
        Args:
            data: Data dictionary to check
            required_fields: List of required field names
            
        Returns:
            True if all required fields are present
        """
        return all(field in data for field in required_fields)
    
    def _check_vulnerability_structure(self, vuln: Dict[str, Any]) -> bool:
        """
        Check if vulnerability object has valid structure.
        
        Args:
            vuln: Vulnerability object to validate
            
        Returns:
            True if structure is valid
        """
        if not isinstance(vuln, dict):
            return False
        
        # Check required vulnerability fields
        if not self._check_required_fields(vuln, self.required_vulnerability_fields):
            return False
        
        # Validate severity if present
        if "Severity" in vuln:
            valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
            if vuln["Severity"] not in valid_severities:
                return False
        
        # Validate CVSS structure if present
        if "CVSS" in vuln:
            if not isinstance(vuln["CVSS"], dict):
                return False
            
            # Check CVSS scores are valid floats
            for source_data in vuln["CVSS"].values():
                if isinstance(source_data, dict):
                    for score_key in ["V2Score", "V3Score"]:
                        if score_key in source_data:
                            score = source_data[score_key]
                            if not isinstance(score, (int, float)) or not (0 <= score <= 10):
                                return False
        
        return True
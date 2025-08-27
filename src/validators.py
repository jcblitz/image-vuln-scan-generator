"""
JSON schema validation and integrity checks for Trivy data.
"""

import json
from pathlib import Path
from typing import Any, Dict

from .exceptions import ValidationError
from .logging_config import get_logger


class TrivyValidator:
    """Handles validation of Trivy JSON files and generated data."""
    
    def __init__(self):
        """Initialize validator."""
        self.required_root_fields = ["SchemaVersion", "ArtifactName", "ArtifactType"]
        self.required_vulnerability_fields = ["VulnerabilityID", "PkgName", "Severity"]
        self.logger = get_logger(f"{__name__}.TrivyValidator")
    
    def validate_input_file(self, file_path: str) -> bool:
        """
        Validate input file is valid Trivy JSON.
        
        Args:
            file_path: Path to the input file
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If validation fails
        """
        self.logger.debug(f"Validating input file: {file_path}")
        
        try:
            path = Path(file_path)
            if not path.exists():
                raise ValidationError(
                    f"Input file does not exist",
                    file_path=file_path,
                    details="File path not found on filesystem"
                )
            
            if not path.is_file():
                raise ValidationError(
                    f"Input path is not a file",
                    file_path=file_path,
                    details="Path exists but is not a regular file"
                )
            
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not self._check_trivy_structure(data):
                raise ValidationError(
                    "File does not have valid Trivy JSON structure",
                    file_path=file_path,
                    details="Missing required fields or invalid structure"
                )
            
            self.logger.info(f"Successfully validated input file: {file_path}")
            return True
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode error in file {file_path}: {e}")
            raise ValidationError(
                "File contains invalid JSON",
                file_path=file_path,
                details=f"JSON parsing failed: {e}"
            )
        except IOError as e:
            self.logger.error(f"IO error reading file {file_path}: {e}")
            raise ValidationError(
                "Failed to read input file",
                file_path=file_path,
                details=f"IO error: {e}"
            )
        except ValidationError:
            # Re-raise ValidationError as-is
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error validating file {file_path}: {e}")
            raise ValidationError(
                "Unexpected error during validation",
                file_path=file_path,
                details=f"Unexpected error: {e}"
            )
    
    def validate_generated_file(self, data: Dict[str, Any]) -> bool:
        """
        Validate generated file maintains schema.
        
        Args:
            data: Generated JSON data as dictionary
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If validation fails
        """
        self.logger.debug("Validating generated file data")
        
        try:
            if not self._check_trivy_structure(data):
                raise ValidationError(
                    "Generated data does not have valid Trivy JSON structure",
                    details="Missing required fields or invalid structure in generated data"
                )
            
            self.logger.debug("Generated file data validation successful")
            return True
            
        except (KeyError, TypeError) as e:
            self.logger.error(f"Structure error in generated data: {e}")
            raise ValidationError(
                "Generated data has invalid structure",
                details=f"Structure validation failed: {e}"
            )
        except ValidationError:
            # Re-raise ValidationError as-is
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error validating generated data: {e}")
            raise ValidationError(
                "Unexpected error during generated data validation",
                details=f"Unexpected error: {e}"
            )
    
    def _check_trivy_structure(self, data: Dict[str, Any]) -> bool:
        """
        Check if data has valid Trivy structure.
        
        Args:
            data: JSON data to validate
            
        Returns:
            True if structure is valid
        """
        self.logger.debug("Checking Trivy structure")
        
        # Check required root fields
        if not self._check_required_fields(data, self.required_root_fields):
            self.logger.debug(f"Missing required root fields: {self.required_root_fields}")
            return False
        
        # Check SchemaVersion is reasonable
        schema_version = data.get("SchemaVersion")
        if not isinstance(schema_version, int) or schema_version < 1:
            self.logger.debug(f"Invalid SchemaVersion: {schema_version}")
            return False
        
        # Check Results structure if present
        if "Results" in data:
            results = data["Results"]
            if not isinstance(results, list):
                self.logger.debug("Results field is not a list")
                return False
            
            for i, result in enumerate(results):
                if not isinstance(result, dict):
                    self.logger.debug(f"Result {i} is not a dictionary")
                    return False
                
                # Check vulnerabilities if present
                if "Vulnerabilities" in result:
                    vulnerabilities = result["Vulnerabilities"]
                    if not isinstance(vulnerabilities, list):
                        self.logger.debug(f"Vulnerabilities in result {i} is not a list")
                        return False
                    
                    for j, vuln in enumerate(vulnerabilities):
                        if not self._check_vulnerability_structure(vuln):
                            self.logger.debug(f"Vulnerability {j} in result {i} has invalid structure")
                            return False
        
        self.logger.debug("Trivy structure validation passed")
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
            cvss = vuln["CVSS"]
            if not isinstance(cvss, dict):
                self.logger.debug("CVSS field is not a dictionary")
                return False
            
            # Check CVSS scores are valid floats
            for source_name, source_data in cvss.items():
                if isinstance(source_data, dict):
                    for score_key in ["V2Score", "V3Score"]:
                        if score_key in source_data:
                            score = source_data[score_key]
                            if not isinstance(score, (int, float)) or not (0 <= score <= 10):
                                self.logger.debug(f"Invalid CVSS {score_key} in {source_name}: {score}")
                                return False
        
        return True
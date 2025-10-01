"""
Grype-specific JSON schema validation and integrity checks.
"""

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
        
        # PURL format regex pattern
        self.purl_pattern = re.compile(
            r'^pkg:[a-zA-Z][a-zA-Z0-9+.-]*(/[^@?#]+)*@[^@?#]+(\?[^#]*)?(#.*)?$'
        )
        
        # CVE ID pattern
        self.cve_pattern = re.compile(r'^CVE-\d{4}-\d{4,}$')
        
        # Valid severity levels for Grype
        self.valid_severities = {"Critical", "High", "Medium", "Low", "Negligible", "Unknown"}
        
        self.logger.debug("GrypeValidator initialized")
    
    def _validate_schema(self, data: Dict[str, Any]) -> bool:
        """
        Validate Grype-specific schema structure.
        
        Args:
            data: JSON data to validate
            
        Returns:
            True if schema is valid
        """
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
        """
        Get required Grype top-level fields.
        
        Returns:
            List of required field names
        """
        return ["matches"]
    
    def _check_matches_structure(self, matches: List[Dict]) -> bool:
        """
        Validate matches array structure and contents.
        
        Args:
            matches: Matches array to validate
            
        Returns:
            True if matches structure is valid
        """
        if not isinstance(matches, list):
            self.logger.debug("Matches is not a list")
            return False
        
        # Empty matches array is valid
        if not matches:
            return True
        
        # Validate each match
        for i, match in enumerate(matches):
            if not self._validate_single_match(match, i):
                return False
        
        return True
    
    def _validate_single_match(self, match: Dict[str, Any], index: int) -> bool:
        """
        Validate a single match object.
        
        Args:
            match: Match object to validate
            index: Index of match for logging
            
        Returns:
            True if match is valid
        """
        if not isinstance(match, dict):
            self.logger.debug(f"Match {index} is not a dictionary")
            return False
        
        # Validate vulnerability if present
        if "vulnerability" in match:
            if not self._validate_vulnerability(match["vulnerability"]):
                self.logger.debug(f"Match {index} has invalid vulnerability")
                return False
        
        # Validate related vulnerabilities if present
        if "relatedVulnerabilities" in match:
            if not self._validate_related_vulnerabilities(match["relatedVulnerabilities"]):
                self.logger.debug(f"Match {index} has invalid related vulnerabilities")
                return False
        
        # Validate match details if present
        if "matchDetails" in match:
            if not self._validate_match_details(match["matchDetails"]):
                self.logger.debug(f"Match {index} has invalid match details")
                return False
        
        # Validate artifact if present
        if "artifact" in match:
            if not self._validate_artifact(match["artifact"]):
                self.logger.debug(f"Match {index} has invalid artifact")
                return False
        
        return True
    
    def _validate_vulnerability(self, vulnerability: Dict[str, Any]) -> bool:
        """
        Validate vulnerability object structure.
        
        Args:
            vulnerability: Vulnerability object to validate
            
        Returns:
            True if vulnerability is valid
        """
        if not isinstance(vulnerability, dict):
            return False
        
        # Validate CVE ID format if present
        if "id" in vulnerability:
            if not self._validate_cve_id(vulnerability["id"]):
                return False
        
        # Validate severity if present
        if "severity" in vulnerability:
            if not self._validate_severity(vulnerability["severity"]):
                return False
        
        # Validate CVSS structure if present
        if "cvss" in vulnerability:
            if not self._validate_cvss_structure(vulnerability["cvss"]):
                return False
        
        # Validate EPSS structure if present
        if "epss" in vulnerability:
            if not self._validate_epss_structure(vulnerability["epss"]):
                return False
        
        # Validate URLs array if present
        if "urls" in vulnerability:
            if not self._validate_urls_array(vulnerability["urls"]):
                return False
        
        # Validate fix information if present
        if "fix" in vulnerability:
            if not self._validate_fix_structure(vulnerability["fix"]):
                return False
        
        return True
    
    def _validate_related_vulnerabilities(self, related: List[Dict]) -> bool:
        """
        Validate related vulnerabilities array.
        
        Args:
            related: Related vulnerabilities array
            
        Returns:
            True if related vulnerabilities are valid
        """
        if not isinstance(related, list):
            return False
        
        for related_vuln in related:
            if not isinstance(related_vuln, dict):
                return False
            
            # Validate CVE ID if present
            if "id" in related_vuln:
                if not self._validate_cve_id(related_vuln["id"]):
                    return False
            
            # Validate severity if present
            if "severity" in related_vuln:
                if not self._validate_severity(related_vuln["severity"]):
                    return False
        
        return True
    
    def _validate_match_details(self, match_details: List[Dict]) -> bool:
        """
        Validate match details array.
        
        Args:
            match_details: Match details array
            
        Returns:
            True if match details are valid
        """
        if not isinstance(match_details, list):
            return False
        
        for detail in match_details:
            if not isinstance(detail, dict):
                return False
            
            # Validate matcher type if present
            if "matcher" in detail:
                if not isinstance(detail["matcher"], str):
                    return False
            
            # Validate match type if present
            if "type" in detail:
                if not isinstance(detail["type"], str):
                    return False
        
        return True
    
    def _validate_artifact(self, artifact: Dict[str, Any]) -> bool:
        """
        Validate artifact object structure.
        
        Args:
            artifact: Artifact object to validate
            
        Returns:
            True if artifact is valid
        """
        if not isinstance(artifact, dict):
            return False
        
        # Validate PURL format if present
        if "purl" in artifact:
            if not self._validate_purl_format(artifact["purl"]):
                return False
        
        # Validate locations array if present
        if "locations" in artifact:
            if not self._validate_locations_array(artifact["locations"]):
                return False
        
        # Validate licenses array if present
        if "licenses" in artifact:
            if not self._validate_licenses_array(artifact["licenses"]):
                return False
        
        # Validate CPEs array if present
        if "cpes" in artifact:
            if not self._validate_cpes_array(artifact["cpes"]):
                return False
        
        return True
    
    def _validate_purl_format(self, purl: str) -> bool:
        """
        Validate Package URL format.
        
        Args:
            purl: PURL string to validate
            
        Returns:
            True if PURL format is valid
        """
        if not isinstance(purl, str):
            self.logger.debug("PURL is not a string")
            return False
        
        if not self.purl_pattern.match(purl):
            self.logger.debug(f"Invalid PURL format: {purl}")
            return False
        
        return True
    
    def _validate_cve_id(self, cve_id: str) -> bool:
        """
        Validate CVE ID format.
        
        Args:
            cve_id: CVE ID string to validate
            
        Returns:
            True if CVE ID format is valid
        """
        if not isinstance(cve_id, str):
            return False
        
        if not self.cve_pattern.match(cve_id):
            self.logger.debug(f"Invalid CVE ID format: {cve_id}")
            return False
        
        return True
    
    def _validate_severity(self, severity: str) -> bool:
        """
        Validate severity level.
        
        Args:
            severity: Severity string to validate
            
        Returns:
            True if severity is valid
        """
        if not isinstance(severity, str):
            return False
        
        if severity not in self.valid_severities:
            self.logger.debug(f"Invalid severity level: {severity}")
            return False
        
        return True
    
    def _validate_cvss_structure(self, cvss: List[Dict]) -> bool:
        """
        Validate CVSS array structure.
        
        Args:
            cvss: CVSS array to validate
            
        Returns:
            True if CVSS structure is valid
        """
        if not isinstance(cvss, list):
            return False
        
        for cvss_item in cvss:
            if not isinstance(cvss_item, dict):
                return False
            
            # Validate metrics if present
            if "metrics" in cvss_item:
                if not self._validate_cvss_metrics(cvss_item["metrics"]):
                    return False
        
        return True
    
    def _validate_cvss_metrics(self, metrics: Dict[str, Any]) -> bool:
        """
        Validate CVSS metrics structure.
        
        Args:
            metrics: CVSS metrics dictionary
            
        Returns:
            True if metrics are valid
        """
        if not isinstance(metrics, dict):
            return False
        
        # Validate score ranges if present
        score_fields = ["baseScore", "exploitabilityScore", "impactScore"]
        for field in score_fields:
            if field in metrics:
                if not self._validate_numeric_range(metrics[field], 0.0, 10.0):
                    self.logger.debug(f"Invalid CVSS {field}: {metrics[field]}")
                    return False
        
        return True
    
    def _validate_epss_structure(self, epss: List[Dict]) -> bool:
        """
        Validate EPSS array structure.
        
        Args:
            epss: EPSS array to validate
            
        Returns:
            True if EPSS structure is valid
        """
        if not isinstance(epss, list):
            return False
        
        for epss_item in epss:
            if not isinstance(epss_item, dict):
                return False
            
            # Validate EPSS score range if present
            if "epss" in epss_item:
                if not self._validate_numeric_range(epss_item["epss"], 0.0, 1.0):
                    return False
            
            # Validate percentile range if present
            if "percentile" in epss_item:
                if not self._validate_numeric_range(epss_item["percentile"], 0.0, 1.0):
                    return False
        
        return True
    
    def _validate_urls_array(self, urls: List[str]) -> bool:
        """
        Validate URLs array.
        
        Args:
            urls: URLs array to validate
            
        Returns:
            True if URLs are valid
        """
        if not isinstance(urls, list):
            return False
        
        for url in urls:
            if not isinstance(url, str):
                return False
            
            # Basic URL format check
            if not (url.startswith("http://") or url.startswith("https://") or url.startswith("ftp://")):
                self.logger.debug(f"Invalid URL format: {url}")
                return False
        
        return True
    
    def _validate_fix_structure(self, fix: Dict[str, Any]) -> bool:
        """
        Validate fix information structure.
        
        Args:
            fix: Fix information dictionary
            
        Returns:
            True if fix structure is valid
        """
        if not isinstance(fix, dict):
            return False
        
        # Validate fix state if present
        if "state" in fix:
            valid_states = {"fixed", "not-fixed", "wont-fix", "unknown"}
            if fix["state"] not in valid_states:
                return False
        
        # Validate versions array if present
        if "versions" in fix:
            if not isinstance(fix["versions"], list):
                return False
            
            for version in fix["versions"]:
                if not isinstance(version, str):
                    return False
        
        return True
    
    def _validate_locations_array(self, locations: List[Dict]) -> bool:
        """
        Validate locations array.
        
        Args:
            locations: Locations array to validate
            
        Returns:
            True if locations are valid
        """
        if not isinstance(locations, list):
            return False
        
        for location in locations:
            if not isinstance(location, dict):
                return False
            
            # Validate path if present
            if "path" in location:
                if not isinstance(location["path"], str):
                    return False
        
        return True
    
    def _validate_licenses_array(self, licenses: List[str]) -> bool:
        """
        Validate licenses array.
        
        Args:
            licenses: Licenses array to validate
            
        Returns:
            True if licenses are valid
        """
        if not isinstance(licenses, list):
            return False
        
        for license_name in licenses:
            if not isinstance(license_name, str):
                return False
        
        return True
    
    def _validate_cpes_array(self, cpes: List[str]) -> bool:
        """
        Validate CPEs array.
        
        Args:
            cpes: CPEs array to validate
            
        Returns:
            True if CPEs are valid
        """
        if not isinstance(cpes, list):
            return False
        
        for cpe in cpes:
            if not isinstance(cpe, str):
                return False
            
            # Basic CPE format check
            if not cpe.startswith("cpe:"):
                self.logger.debug(f"Invalid CPE format: {cpe}")
                return False
        
        return True
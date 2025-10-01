"""
Trivy-specific field randomization logic extending base randomization utilities.
"""

import random
from typing import Any, Dict, List

from ..base import BaseRandomizer
from ..logging_config import get_logger


class TrivyRandomizer(BaseRandomizer):
    """Trivy-specific implementation of field randomization extending BaseRandomizer."""
    
    def __init__(self):
        """Initialize Trivy randomizer with Trivy-specific data sources."""
        super().__init__()
        
        # Trivy-specific severity levels
        self.severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        
        self.logger.debug("TrivyRandomizer initialized")
    
    def randomize_root_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize ArtifactName, ImageID, and OwnerEmailAddress fields.
        
        Args:
            data: Original JSON data
            
        Returns:
            Data with randomized root fields
        """
        # Randomize ArtifactName
        if "ArtifactName" in data:
            data["ArtifactName"] = self._generate_artifact_name()
        
        # Randomize ImageID in Metadata
        if "Metadata" in data and isinstance(data["Metadata"], dict):
            if "ImageID" in data["Metadata"]:
                data["Metadata"]["ImageID"] = self._generate_image_id()
        
        # Randomize OwnerEmailAddress
        if "OwnerEmailAddress" in data:
            data["OwnerEmailAddress"] = self.generate_email_address()
        
        return data
    
    def randomize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Randomize vulnerability array entries.
        
        Args:
            vulnerabilities: List of vulnerability objects
            
        Returns:
            List with randomized vulnerability data
        """
        randomized_vulns = []
        
        for vuln in vulnerabilities:
            randomized_vuln = self._randomize_single_vulnerability(vuln)
            randomized_vulns.append(randomized_vuln)
        
        return randomized_vulns
    
    def randomize_vulnerability_count(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Randomize the number of vulnerabilities (0-20 range).
        
        Args:
            vulnerabilities: Original list of vulnerability objects
            
        Returns:
            List with randomized number of vulnerabilities
        """
        if not vulnerabilities:
            return vulnerabilities
        
        # Generate random count between 0 and 20
        target_count = random.randint(0, 20)
        
        if target_count == 0:
            return []
        
        return self.randomize_list_count(vulnerabilities, target_count, target_count)
    
    def _randomize_single_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize a single vulnerability object.
        
        Args:
            vuln: Single vulnerability object
            
        Returns:
            Randomized vulnerability object
        """
        randomized_vuln = vuln.copy()
        
        # Randomize key fields using base class methods
        if "VulnerabilityID" in randomized_vuln:
            randomized_vuln["VulnerabilityID"] = self.generate_cve_id()
        
        if "PkgName" in randomized_vuln:
            randomized_vuln["PkgName"] = self.generate_package_name()
        
        if "InstalledVersion" in randomized_vuln:
            randomized_vuln["InstalledVersion"] = self.generate_version()
        
        if "FixedVersion" in randomized_vuln:
            randomized_vuln["FixedVersion"] = self.generate_version()
        
        # Generate severity first so we can correlate CVSS scores
        severity = None
        if "Severity" in randomized_vuln:
            severity = self._generate_trivy_severity()
            randomized_vuln["Severity"] = severity
        
        # Randomize CVSS scores with correlation to severity
        if "CVSS" in randomized_vuln and isinstance(randomized_vuln["CVSS"], dict):
            self._randomize_cvss_scores(randomized_vuln["CVSS"], severity)
        
        # Randomize dates using base class method
        if "PublishedDate" in randomized_vuln:
            randomized_vuln["PublishedDate"] = self.generate_date("iso")
        
        if "LastModifiedDate" in randomized_vuln:
            randomized_vuln["LastModifiedDate"] = self.generate_date("iso")
        
        return randomized_vuln
    
    def _generate_artifact_name(self) -> str:
        """Generate realistic artifact name."""
        base_names = ["alpine", "ubuntu", "debian", "centos", "nginx", "node", "python", "golang"]
        base = random.choice(base_names)
        version = f"{random.randint(1, 20)}.{random.randint(0, 12)}"
        variant = random.choice(["", "-alpine", "-slim", "-stretch", "-buster"])
        return f"{base}:{version}{variant}"
    
    def _generate_image_id(self) -> str:
        """Generate realistic Docker image ID."""
        return f"sha256:{self.fake.sha256()}"
    
    def _generate_trivy_severity(self) -> str:
        """Select random Trivy severity level with realistic distribution."""
        # Weight distribution to be more realistic (fewer CRITICAL, more MEDIUM/LOW)
        weights = [0.1, 0.2, 0.4, 0.25, 0.05]  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
        return self.generate_weighted_choice(self.severity_levels, weights)
    
    def _generate_cvss_score_for_severity(self, version: str, severity: str = None) -> float:
        """
        Generate realistic CVSS score based on version and optionally correlated with severity.
        
        Args:
            version: CVSS version ("V2" or "V3")
            severity: Optional severity level to correlate score with
            
        Returns:
            Realistic CVSS score as float
        """
        if severity:
            # Correlate CVSS scores with severity levels
            if severity == "CRITICAL":
                base_range = (9.0, 10.0)
            elif severity == "HIGH":
                base_range = (7.0, 8.9)
            elif severity == "MEDIUM":
                base_range = (4.0, 6.9)
            elif severity == "LOW":
                base_range = (0.1, 3.9)
            else:  # UNKNOWN
                base_range = (0.0, 10.0)
            
            score = self.fake.pyfloat(min_value=base_range[0], max_value=base_range[1], right_digits=1)
        else:
            # Generate random score without correlation
            score = self.generate_cvss_score(0.0, 10.0)
        
        return round(score, 1)
    
    def _randomize_cvss_scores(self, cvss_data: Dict[str, Any], severity: str = None) -> None:
        """
        Randomize CVSS scores in place, optionally correlated with severity.
        
        Args:
            cvss_data: CVSS data dictionary to modify
            severity: Optional severity level to correlate scores with
        """
        for source_key, source_data in cvss_data.items():
            if isinstance(source_data, dict):
                if "V2Score" in source_data:
                    source_data["V2Score"] = self._generate_cvss_score_for_severity("V2", severity)
                if "V3Score" in source_data:
                    source_data["V3Score"] = self._generate_cvss_score_for_severity("V3", severity)
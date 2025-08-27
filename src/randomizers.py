"""
Field-specific randomization logic for Trivy JSON data.
"""

import random
from datetime import datetime, timedelta
from typing import Any, Dict, List

from faker import Faker


class VulnerabilityRandomizer:
    """Handles randomization of vulnerability data fields."""
    
    def __init__(self):
        """Initialize randomizer with Faker instance and predefined data."""
        self.fake = Faker()
        
        # Predefined lists for realistic randomization
        self.package_names = [
            "busybox", "apk-tools", "openssl", "curl", "wget", "bash", "coreutils",
            "glibc", "zlib", "libssl", "ca-certificates", "musl", "alpine-baselayout",
            "alpine-keys", "libc-utils", "scanelf", "ssl_client", "tzdata",
            "libcrypto", "libx11", "fontconfig", "freetype", "expat", "libpng",
            "libjpeg", "sqlite", "python3", "nodejs", "nginx", "apache2", "mysql",
            "postgresql", "redis", "git", "vim", "nano", "tar", "gzip", "unzip"
        ]
        
        self.severity_levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    
    def randomize_root_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize ArtifactName and ImageID fields.
        
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
            randomized_vuln = vuln.copy()
            
            # Randomize key fields
            if "VulnerabilityID" in randomized_vuln:
                randomized_vuln["VulnerabilityID"] = self._generate_cve_id()
            
            if "PkgName" in randomized_vuln:
                randomized_vuln["PkgName"] = self._generate_package_name()
            
            if "InstalledVersion" in randomized_vuln:
                randomized_vuln["InstalledVersion"] = self._generate_version()
            
            if "FixedVersion" in randomized_vuln:
                randomized_vuln["FixedVersion"] = self._generate_version()
            
            # Generate severity first so we can correlate CVSS scores
            severity = None
            if "Severity" in randomized_vuln:
                severity = self._generate_severity()
                randomized_vuln["Severity"] = severity
            
            # Randomize CVSS scores with correlation to severity
            if "CVSS" in randomized_vuln and isinstance(randomized_vuln["CVSS"], dict):
                self._randomize_cvss_scores(randomized_vuln["CVSS"], severity)
            
            # Randomize dates
            if "PublishedDate" in randomized_vuln:
                randomized_vuln["PublishedDate"] = self._generate_date()
            
            if "LastModifiedDate" in randomized_vuln:
                randomized_vuln["LastModifiedDate"] = self._generate_date()
            
            randomized_vulns.append(randomized_vuln)
        
        return randomized_vulns
    
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
    
    def _generate_cve_id(self) -> str:
        """Generate realistic CVE identifier following CVE-YYYY-XXXXX format."""
        year = random.randint(2015, 2024)
        number = random.randint(1, 99999)
        return f"CVE-{year}-{number:05d}"
    
    def _generate_package_name(self) -> str:
        """Select random package name from predefined list."""
        return random.choice(self.package_names)
    
    def _generate_version(self) -> str:
        """Generate realistic version string using Faker for semantic versioning patterns."""
        version_types = [
            # Semantic versioning (major.minor.patch)
            lambda: f"{self.fake.random_int(0, 10)}.{self.fake.random_int(0, 20)}.{self.fake.random_int(0, 50)}",
            # Simple major.minor
            lambda: f"{self.fake.random_int(0, 5)}.{self.fake.random_int(0, 15)}",
            # Alpine-style with revision
            lambda: f"{self.fake.random_int(1, 3)}.{self.fake.random_int(0, 10)}.{self.fake.random_int(0, 20)}-r{self.fake.random_int(0, 10)}",
            # Date-based versioning
            lambda: f"{self.fake.random_int(2015, 2024)}{self.fake.random_int(1, 12):02d}{self.fake.random_int(1, 28):02d}",
            # Git-style short hash
            lambda: self.fake.lexify('???????', letters='0123456789abcdef'),
            # Ubuntu-style with build number
            lambda: f"{self.fake.random_int(1, 20)}.{self.fake.random_int(1, 12):02d}.{self.fake.random_int(1, 5)}-{self.fake.random_int(1, 100)}ubuntu{self.fake.random_int(1, 5)}",
        ]
        return random.choice(version_types)()
    
    def _generate_severity(self) -> str:
        """Select random severity level with realistic distribution."""
        # Weight distribution to be more realistic (fewer CRITICAL, more MEDIUM/LOW)
        weights = [0.1, 0.2, 0.4, 0.25, 0.05]  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
        return random.choices(self.severity_levels, weights=weights)[0]
    
    def _generate_cvss_score(self, version: str, severity: str = None) -> float:
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
            score = self.fake.pyfloat(min_value=0.0, max_value=10.0, right_digits=1)
        
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
                    source_data["V2Score"] = self._generate_cvss_score("V2", severity)
                if "V3Score" in source_data:
                    source_data["V3Score"] = self._generate_cvss_score("V3", severity)
    
    def _generate_date(self) -> str:
        """Generate random date in ISO format using Faker for PublishedDate and LastModifiedDate."""
        # Generate date within last 5 years using Faker's date utilities
        random_date = self.fake.date_time_between(start_date='-5y', end_date='now')
        return random_date.strftime("%Y-%m-%dT%H:%M:%SZ")
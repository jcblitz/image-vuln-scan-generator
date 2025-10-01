"""
Grype-specific field randomization logic for matches-based vulnerability schema.
"""

import random
from copy import deepcopy
from typing import Any, Dict, List

from ..base.randomizer import BaseRandomizer
from ..logging_config import get_logger


class GrypeRandomizer(BaseRandomizer):
    """Grype-specific randomization engine extending base randomization utilities."""
    
    def __init__(self):
        """Initialize with Grype-specific data sources."""
        super().__init__()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
        # Grype-specific severity levels
        self.grype_severities = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
        
        # Matcher types used by Grype
        self.matcher_types = [
            "apk-matcher", "java-matcher", "python-matcher", "go-module-matcher",
            "npm-matcher", "ruby-matcher", "dotnet-matcher", "php-matcher",
            "rust-matcher", "binary-matcher", "dpkg-matcher", "rpm-matcher"
        ]
        
        # Distribution types
        self.distro_types = ["alpine", "ubuntu", "debian", "centos", "rhel", "fedora", "arch", "opensuse"]
        
        # Fix states
        self.fix_states = ["fixed", "not-fixed", "wont-fix", "unknown"]
        
        # Package types for PURL generation
        self.package_types = ["apk", "deb", "rpm", "npm", "pypi", "maven", "golang", "cargo", "gem", "nuget"]
        
        # CVSS sources
        self.cvss_sources = ["nvd", "redhat", "ubuntu", "debian", "alpine", "ghsa"]
        
        # Vulnerability description templates
        self.vuln_descriptions = [
            "Buffer overflow vulnerability allows remote code execution",
            "SQL injection vulnerability in authentication module",
            "Cross-site scripting (XSS) vulnerability in web interface",
            "Privilege escalation vulnerability in system service",
            "Denial of service vulnerability in network handler",
            "Information disclosure vulnerability in logging component",
            "Path traversal vulnerability allows file access",
            "Memory corruption vulnerability in parser",
            "Authentication bypass vulnerability in login system",
            "Integer overflow vulnerability in calculation routine"
        ]
        
        self.logger.debug("GrypeRandomizer initialized with Grype-specific data sources")
    
    def randomize_matches(self, matches: List[Dict]) -> List[Dict]:
        """
        Randomize matches array and vulnerability count (1-50).
        
        Args:
            matches: Original matches array
            
        Returns:
            Randomized matches array with count between 1-50
        """
        if not matches:
            self.logger.debug("Empty matches array provided")
            return matches
        
        # Randomize match count between 1-50
        target_count = random.randint(1, 50)
        self.logger.debug(f"Randomizing matches count to {target_count}")
        
        # Use base randomizer to adjust list count
        randomized_matches = self.randomize_list_count(matches, target_count, target_count)
        
        # Randomize each match
        for i, match in enumerate(randomized_matches):
            randomized_matches[i] = self._randomize_single_match(match)
        
        self.logger.debug(f"Randomized {len(randomized_matches)} matches")
        return randomized_matches
    
    def _randomize_single_match(self, match: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize a single match object.
        
        Args:
            match: Original match object
            
        Returns:
            Randomized match object
        """
        randomized_match = deepcopy(match)
        
        # Randomize vulnerability if present
        if "vulnerability" in randomized_match:
            randomized_match["vulnerability"] = self.randomize_vulnerability(randomized_match["vulnerability"])
        
        # Randomize related vulnerabilities if present
        if "relatedVulnerabilities" in randomized_match:
            randomized_match["relatedVulnerabilities"] = self.randomize_related_vulnerabilities(
                randomized_match["relatedVulnerabilities"]
            )
        
        # Randomize match details if present
        if "matchDetails" in randomized_match:
            randomized_match["matchDetails"] = self.randomize_match_details(
                randomized_match["matchDetails"]
            )
        
        # Randomize artifact if present
        if "artifact" in randomized_match:
            randomized_match["artifact"] = self.randomize_artifact(randomized_match["artifact"])
        
        return randomized_match
    
    def randomize_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize vulnerability object fields.
        
        Args:
            vulnerability: Original vulnerability object
            
        Returns:
            Randomized vulnerability object
        """
        randomized_vuln = deepcopy(vulnerability)
        
        # Randomize CVE ID
        if "id" in randomized_vuln:
            randomized_vuln["id"] = self.generate_cve_id()
        
        # Randomize severity
        if "severity" in randomized_vuln:
            randomized_vuln["severity"] = self._generate_grype_severity()
        
        # Randomize data source URL
        if "dataSource" in randomized_vuln:
            randomized_vuln["dataSource"] = self.generate_url()
        
        # Randomize URLs array
        if "urls" in randomized_vuln and isinstance(randomized_vuln["urls"], list):
            url_count = random.randint(1, 3)
            randomized_vuln["urls"] = [self.generate_url() for _ in range(url_count)]
        
        # Randomize CVSS metrics
        if "cvss" in randomized_vuln and isinstance(randomized_vuln["cvss"], list):
            randomized_vuln["cvss"] = self._randomize_cvss_array(randomized_vuln["cvss"])
        
        # Randomize EPSS data
        if "epss" in randomized_vuln and isinstance(randomized_vuln["epss"], list):
            randomized_vuln["epss"] = self._randomize_epss_array(randomized_vuln["epss"])
        
        # Randomize fix information
        if "fix" in randomized_vuln:
            randomized_vuln["fix"] = self._generate_fix_info()
        
        # Randomize risk score
        if "risk" in randomized_vuln:
            randomized_vuln["risk"] = self.generate_cvss_score(0.0, 10.0)
        
        return randomized_vuln
    
    def _generate_grype_severity(self) -> str:
        """
        Select random Grype severity level with realistic distribution.
        
        Returns:
            Severity level string
        """
        # Weight distribution to favor Medium/High over Critical
        weights = [0.1, 0.3, 0.4, 0.15, 0.04, 0.01]  # Critical, High, Medium, Low, Negligible, Unknown
        return self.generate_weighted_choice(self.grype_severities, weights)
    
    def _generate_cvss_metrics(self) -> Dict[str, float]:
        """
        Generate realistic CVSS metrics.
        
        Returns:
            Dictionary with CVSS metric scores
        """
        base_score = self.generate_cvss_score(0.0, 10.0)
        
        # Generate exploitability and impact scores that correlate with base score
        exploitability_score = self.generate_cvss_score(0.0, min(base_score + 2.0, 10.0))
        impact_score = self.generate_cvss_score(0.0, min(base_score + 2.0, 10.0))
        
        return {
            "baseScore": base_score,
            "exploitabilityScore": exploitability_score,
            "impactScore": impact_score
        }
    
    def _randomize_cvss_array(self, cvss_array: List[Dict]) -> List[Dict]:
        """
        Randomize CVSS array with realistic data.
        
        Args:
            cvss_array: Original CVSS array
            
        Returns:
            Randomized CVSS array
        """
        if not cvss_array:
            return cvss_array
        
        randomized_cvss = []
        for cvss_item in cvss_array:
            randomized_item = deepcopy(cvss_item)
            
            # Randomize source
            if "source" in randomized_item:
                randomized_item["source"] = self.select_random_from_list(self.cvss_sources)
            
            # Randomize metrics
            if "metrics" in randomized_item:
                randomized_item["metrics"] = self._generate_cvss_metrics()
            
            # Randomize vector string (simplified)
            if "vector" in randomized_item:
                randomized_item["vector"] = self._generate_cvss_vector()
            
            randomized_cvss.append(randomized_item)
        
        return randomized_cvss
    
    def _generate_cvss_vector(self) -> str:
        """
        Generate simplified CVSS vector string.
        
        Returns:
            CVSS vector string
        """
        # Simplified CVSS v3.1 vector
        av_values = ["N", "A", "L", "P"]  # Attack Vector
        ac_values = ["L", "H"]  # Attack Complexity
        pr_values = ["N", "L", "H"]  # Privileges Required
        ui_values = ["N", "R"]  # User Interaction
        s_values = ["U", "C"]  # Scope
        c_values = ["N", "L", "H"]  # Confidentiality
        i_values = ["N", "L", "H"]  # Integrity
        a_values = ["N", "L", "H"]  # Availability
        
        return (f"CVSS:3.1/AV:{random.choice(av_values)}/AC:{random.choice(ac_values)}/"
                f"PR:{random.choice(pr_values)}/UI:{random.choice(ui_values)}/"
                f"S:{random.choice(s_values)}/C:{random.choice(c_values)}/"
                f"I:{random.choice(i_values)}/A:{random.choice(a_values)}")
    
    def _generate_epss_data(self) -> Dict[str, Any]:
        """
        Generate realistic EPSS data.
        
        Returns:
            Dictionary with EPSS score and percentile
        """
        epss_score = round(random.uniform(0.0, 1.0), 5)
        percentile = round(random.uniform(0.0, 1.0), 5)
        
        return {
            "cve": self.generate_cve_id(),
            "epss": epss_score,
            "percentile": percentile,
            "date": self.generate_date("simple")
        }
    
    def _randomize_epss_array(self, epss_array: List[Dict]) -> List[Dict]:
        """
        Randomize EPSS array.
        
        Args:
            epss_array: Original EPSS array
            
        Returns:
            Randomized EPSS array
        """
        if not epss_array:
            return epss_array
        
        randomized_epss = []
        for epss_item in epss_array:
            randomized_item = deepcopy(epss_item)
            epss_data = self._generate_epss_data()
            
            # Update with new EPSS data
            randomized_item.update(epss_data)
            randomized_epss.append(randomized_item)
        
        return randomized_epss
    
    def _generate_fix_info(self) -> Dict[str, Any]:
        """
        Generate fix information with versions and state.
        
        Returns:
            Dictionary with fix information
        """
        fix_state = self.select_random_from_list(self.fix_states)
        
        fix_info = {
            "state": fix_state
        }
        
        # Add versions if fixed
        if fix_state == "fixed":
            version_count = random.randint(1, 3)
            fix_info["versions"] = [self.generate_version() for _ in range(version_count)]
            
            # Add available fix information
            fix_info["available"] = [{
                "version": self.generate_version(),
                "date": self.generate_date("simple"),
                "kind": "first-observed"
            }]
        
        return fix_info 
   def randomize_related_vulnerabilities(self, related: List[Dict]) -> List[Dict]:
        """
        Randomize related vulnerabilities array (0-5 per match).
        
        Args:
            related: Original related vulnerabilities array
            
        Returns:
            Randomized related vulnerabilities array with 0-5 items
        """
        if not related:
            # Generate 0-5 related vulnerabilities even if none existed
            count = random.randint(0, 5)
            if count == 0:
                return []
            
            # Create new related vulnerabilities
            new_related = []
            for _ in range(count):
                new_related.append(self._generate_related_vulnerability())
            return new_related
        
        # Randomize count between 0-5
        target_count = random.randint(0, 5)
        if target_count == 0:
            return []
        
        # Use base randomizer to adjust list count
        randomized_related = self.randomize_list_count(related, target_count, target_count)
        
        # Randomize each related vulnerability
        for i, related_vuln in enumerate(randomized_related):
            randomized_related[i] = self._randomize_related_vulnerability(related_vuln)
        
        self.logger.debug(f"Randomized to {len(randomized_related)} related vulnerabilities")
        return randomized_related
    
    def _generate_related_vulnerability(self) -> Dict[str, Any]:
        """
        Generate a new related vulnerability object.
        
        Returns:
            New related vulnerability dictionary
        """
        return {
            "id": self.generate_cve_id(),
            "dataSource": self.generate_url(),
            "namespace": f"{self.select_random_from_list(self.distro_types)}:distro",
            "severity": self._generate_grype_severity(),
            "urls": [self.generate_url() for _ in range(random.randint(1, 2))],
            "description": self._generate_vulnerability_description(),
            "cvss": [],
            "epss": []
        }
    
    def _randomize_related_vulnerability(self, related_vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize an existing related vulnerability object.
        
        Args:
            related_vuln: Original related vulnerability
            
        Returns:
            Randomized related vulnerability
        """
        randomized = deepcopy(related_vuln)
        
        # Randomize basic fields
        if "id" in randomized:
            randomized["id"] = self.generate_cve_id()
        
        if "severity" in randomized:
            randomized["severity"] = self._generate_grype_severity()
        
        if "dataSource" in randomized:
            randomized["dataSource"] = self.generate_url()
        
        if "description" in randomized:
            randomized["description"] = self._generate_vulnerability_description()
        
        if "urls" in randomized and isinstance(randomized["urls"], list):
            url_count = random.randint(1, 2)
            randomized["urls"] = [self.generate_url() for _ in range(url_count)]
        
        return randomized
    
    def randomize_match_details(self, match_details: List[Dict]) -> List[Dict]:
        """
        Randomize match details array with matcher types and search criteria.
        
        Args:
            match_details: Original match details array
            
        Returns:
            Randomized match details array
        """
        if not match_details:
            return match_details
        
        randomized_details = []
        for detail in match_details:
            randomized_detail = self._randomize_match_detail(detail)
            randomized_details.append(randomized_detail)
        
        self.logger.debug(f"Randomized {len(randomized_details)} match details")
        return randomized_details
    
    def _randomize_match_detail(self, detail: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize a single match detail object.
        
        Args:
            detail: Original match detail
            
        Returns:
            Randomized match detail
        """
        randomized = deepcopy(detail)
        
        # Randomize matcher type
        if "matcher" in randomized:
            randomized["matcher"] = self._generate_matcher_type()
        
        # Randomize match type
        if "type" in randomized:
            match_types = ["exact-direct-match", "exact-indirect-match", "fuzzy-match"]
            randomized["type"] = self.select_random_from_list(match_types)
        
        # Randomize searchedBy information
        if "searchedBy" in randomized:
            randomized["searchedBy"] = self._randomize_searched_by(randomized["searchedBy"])
        
        # Randomize found information
        if "found" in randomized:
            randomized["found"] = self._randomize_found_info(randomized["found"])
        
        # Randomize fix information
        if "fix" in randomized:
            randomized["fix"] = {
                "suggestedVersion": self.generate_version()
            }
        
        return randomized
    
    def _randomize_searched_by(self, searched_by: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize searchedBy information with distro and package details.
        
        Args:
            searched_by: Original searchedBy object
            
        Returns:
            Randomized searchedBy object
        """
        randomized = deepcopy(searched_by)
        
        # Randomize distro information
        if "distro" in randomized:
            randomized["distro"] = self._generate_distro_info()
        
        # Randomize package information
        if "package" in randomized:
            randomized["package"] = {
                "name": self.generate_package_name(),
                "version": self.generate_version()
            }
        
        # Randomize namespace
        if "namespace" in randomized:
            distro = self.select_random_from_list(self.distro_types)
            randomized["namespace"] = f"{distro}:distro"
        
        return randomized
    
    def _randomize_found_info(self, found: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize found vulnerability information.
        
        Args:
            found: Original found object
            
        Returns:
            Randomized found object
        """
        randomized = deepcopy(found)
        
        # Randomize vulnerability ID
        if "vulnerabilityID" in randomized:
            randomized["vulnerabilityID"] = self.generate_cve_id()
        
        # Randomize version constraint
        if "versionConstraint" in randomized:
            randomized["versionConstraint"] = self._generate_version_constraint()
        
        return randomized
    
    def _generate_matcher_type(self) -> str:
        """
        Select random matcher type.
        
        Returns:
            Matcher type string
        """
        return self.select_random_from_list(self.matcher_types)
    
    def _generate_distro_info(self) -> Dict[str, str]:
        """
        Generate realistic distro information.
        
        Returns:
            Dictionary with distro type and version
        """
        distro_type = self.select_random_from_list(self.distro_types)
        
        # Generate version based on distro type
        if distro_type == "alpine":
            version = f"{random.randint(3, 4)}.{random.randint(10, 19)}"
        elif distro_type == "ubuntu":
            versions = ["18.04", "20.04", "22.04", "24.04"]
            version = self.select_random_from_list(versions)
        elif distro_type == "debian":
            versions = ["9", "10", "11", "12"]
            version = self.select_random_from_list(versions)
        elif distro_type in ["centos", "rhel"]:
            version = f"{random.randint(7, 9)}"
        else:
            version = self.generate_version()
        
        return {
            "type": distro_type,
            "version": version
        }
    
    def _generate_version_constraint(self) -> str:
        """
        Generate realistic version constraint string.
        
        Returns:
            Version constraint string
        """
        operators = ["<", "<=", ">=", ">", "="]
        operator = self.select_random_from_list(operators)
        version = self.generate_version()
        return f"{operator} {version}"
    
    def _generate_vulnerability_description(self) -> str:
        """
        Generate realistic vulnerability description.
        
        Returns:
            Vulnerability description string
        """
        base_description = self.select_random_from_list(self.vuln_descriptions)
        
        # Add some variation
        if random.random() < 0.3:  # 30% chance to add severity context
            severity_context = [
                "This is a critical security issue.",
                "Immediate patching is recommended.",
                "This vulnerability has been actively exploited.",
                "No known workaround is available."
            ]
            base_description += " " + self.select_random_from_list(severity_context)
        
        return base_description    
def randomize_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize artifact information including PURL generation.
        
        Args:
            artifact: Original artifact object
            
        Returns:
            Randomized artifact object
        """
        randomized = deepcopy(artifact)
        
        # Generate new package name and version
        package_name = self.generate_package_name()
        package_version = self.generate_version()
        
        # Randomize basic artifact fields
        if "id" in randomized:
            randomized["id"] = self.generate_hash(32)
        
        if "name" in randomized:
            randomized["name"] = package_name
        
        if "version" in randomized:
            randomized["version"] = package_version
        
        # Randomize artifact type
        if "type" in randomized:
            artifact_types = ["apk", "deb", "rpm", "java-archive", "python", "go-module", "npm", "gem"]
            randomized["type"] = self.select_random_from_list(artifact_types)
        
        # Generate PURL
        if "purl" in randomized:
            pkg_type = self._get_purl_type_from_artifact_type(randomized.get("type", "apk"))
            randomized["purl"] = self._generate_package_url(pkg_type, package_name, package_version)
        
        # Randomize locations
        if "locations" in randomized and isinstance(randomized["locations"], list):
            randomized["locations"] = self._randomize_locations(randomized["locations"])
        
        # Randomize language
        if "language" in randomized:
            languages = ["", "python", "java", "javascript", "go", "ruby", "php", "rust", "c", "cpp"]
            randomized["language"] = self.select_random_from_list(languages)
        
        # Randomize licenses
        if "licenses" in randomized and isinstance(randomized["licenses"], list):
            randomized["licenses"] = self._randomize_licenses()
        
        # Randomize CPEs
        if "cpes" in randomized and isinstance(randomized["cpes"], list):
            randomized["cpes"] = self._randomize_cpes(package_name, package_version)
        
        # Randomize upstreams
        if "upstreams" in randomized and isinstance(randomized["upstreams"], list):
            randomized["upstreams"] = self._randomize_upstreams()
        
        # Randomize metadata type
        if "metadataType" in randomized:
            metadata_types = ["ApkMetadata", "DpkgMetadata", "RpmMetadata", "JavaMetadata", "PythonMetadata"]
            randomized["metadataType"] = self.select_random_from_list(metadata_types)
        
        # Randomize metadata (keep structure but randomize values)
        if "metadata" in randomized and isinstance(randomized["metadata"], dict):
            randomized["metadata"] = self._randomize_metadata(randomized["metadata"])
        
        self.logger.debug(f"Randomized artifact: {package_name}@{package_version}")
        return randomized
    
    def _get_purl_type_from_artifact_type(self, artifact_type: str) -> str:
        """
        Map artifact type to PURL type.
        
        Args:
            artifact_type: Artifact type string
            
        Returns:
            Corresponding PURL type
        """
        type_mapping = {
            "apk": "apk",
            "deb": "deb", 
            "rpm": "rpm",
            "java-archive": "maven",
            "python": "pypi",
            "go-module": "golang",
            "npm": "npm",
            "gem": "gem"
        }
        return type_mapping.get(artifact_type, "generic")
    
    def _generate_package_url(self, pkg_type: str, name: str, version: str) -> str:
        """
        Generate valid Package URL (PURL) format string.
        
        Args:
            pkg_type: Package type (apk, deb, maven, etc.)
            name: Package name
            version: Package version
            
        Returns:
            Valid PURL string
        """
        # Basic PURL format: pkg:type/namespace/name@version?qualifiers#subpath
        
        # Generate namespace based on package type
        namespace = ""
        if pkg_type == "maven":
            namespace = f"org.{self.fake.word()}"
        elif pkg_type == "npm":
            if random.random() < 0.3:  # 30% chance of scoped package
                namespace = f"@{self.fake.word()}"
        elif pkg_type in ["deb", "rpm"]:
            namespace = self.select_random_from_list(self.distro_types)
        
        # Construct PURL
        purl = f"pkg:{pkg_type}/"
        if namespace:
            purl += f"{namespace}/"
        purl += f"{name}@{version}"
        
        # Add qualifiers for some package types
        qualifiers = []
        if pkg_type == "deb":
            arch = self.select_random_from_list(["amd64", "arm64", "i386", "armhf"])
            qualifiers.append(f"arch={arch}")
        elif pkg_type == "rpm":
            arch = self.select_random_from_list(["x86_64", "aarch64", "i686", "noarch"])
            qualifiers.append(f"arch={arch}")
        elif pkg_type == "apk":
            arch = self.select_random_from_list(["x86_64", "aarch64", "armv7", "armhf"])
            qualifiers.append(f"arch={arch}")
        
        if qualifiers:
            purl += "?" + "&".join(qualifiers)
        
        return purl
    
    def _randomize_locations(self, locations: List[Dict]) -> List[Dict]:
        """
        Randomize artifact locations.
        
        Args:
            locations: Original locations array
            
        Returns:
            Randomized locations array
        """
        if not locations:
            return locations
        
        randomized_locations = []
        for location in locations:
            randomized_loc = deepcopy(location)
            
            # Randomize path
            if "path" in randomized_loc:
                paths = [
                    "/lib/apk/db/installed",
                    "/var/lib/dpkg/status", 
                    "/usr/lib/python3.9/site-packages",
                    "/usr/share/java",
                    "/opt/app/node_modules",
                    "/usr/local/bin",
                    "/etc/ssl/certs"
                ]
                randomized_loc["path"] = self.select_random_from_list(paths)
            
            # Randomize layer ID
            if "layerID" in randomized_loc:
                randomized_loc["layerID"] = f"sha256:{self.generate_hash(64)}"
            
            # Randomize access path
            if "accessPath" in randomized_loc:
                randomized_loc["accessPath"] = randomized_loc.get("path", "/")
            
            randomized_locations.append(randomized_loc)
        
        return randomized_locations
    
    def _randomize_licenses(self) -> List[str]:
        """
        Generate randomized license list.
        
        Returns:
            List of license strings
        """
        licenses = [
            "MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause", "ISC", "GPL-2.0",
            "LGPL-2.1", "MPL-2.0", "AGPL-3.0", "Unlicense", "BSD-2-Clause"
        ]
        
        # Return 1-2 licenses
        count = random.randint(1, 2)
        return random.sample(licenses, min(count, len(licenses)))
    
    def _randomize_cpes(self, package_name: str, package_version: str) -> List[str]:
        """
        Generate randomized CPE (Common Platform Enumeration) strings.
        
        Args:
            package_name: Package name for CPE
            package_version: Package version for CPE
            
        Returns:
            List of CPE strings
        """
        # CPE format: cpe:2.3:a:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        vendors = ["apache", "gnu", "python", "nodejs", "oracle", "microsoft", "redhat"]
        vendor = self.select_random_from_list(vendors)
        
        cpe = f"cpe:2.3:a:{vendor}:{package_name}:{package_version}:*:*:*:*:*:*:*"
        return [cpe]
    
    def _randomize_upstreams(self) -> List[Dict[str, str]]:
        """
        Generate randomized upstream information.
        
        Returns:
            List of upstream dictionaries
        """
        upstream_count = random.randint(0, 2)
        if upstream_count == 0:
            return []
        
        upstreams = []
        for _ in range(upstream_count):
            upstreams.append({
                "name": self.generate_package_name()
            })
        
        return upstreams
    
    def _randomize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Randomize metadata while preserving structure.
        
        Args:
            metadata: Original metadata dictionary
            
        Returns:
            Randomized metadata dictionary
        """
        randomized = deepcopy(metadata)
        
        # Common metadata fields to randomize
        if "size" in randomized:
            randomized["size"] = random.randint(1024, 10485760)  # 1KB to 10MB
        
        if "installedSize" in randomized:
            randomized["installedSize"] = random.randint(2048, 20971520)  # 2KB to 20MB
        
        if "architecture" in randomized:
            architectures = ["x86_64", "aarch64", "armv7", "i686", "noarch"]
            randomized["architecture"] = self.select_random_from_list(architectures)
        
        if "maintainer" in randomized:
            randomized["maintainer"] = f"{self.fake.name()} <{self.fake.email()}>"
        
        if "description" in randomized:
            randomized["description"] = self.fake.sentence(nb_words=10)
        
        if "homepage" in randomized:
            randomized["homepage"] = self.generate_url()
        
        # Randomize any version fields in metadata
        for key, value in randomized.items():
            if isinstance(value, str) and ("version" in key.lower() or key.lower().endswith("ver")):
                randomized[key] = self.generate_version()
        
        return randomized
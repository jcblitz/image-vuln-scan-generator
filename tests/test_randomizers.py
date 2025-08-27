"""
Unit tests for the VulnerabilityRandomizer class.
"""

import unittest
from unittest.mock import patch

from src.randomizers import VulnerabilityRandomizer


class TestVulnerabilityRandomizer(unittest.TestCase):
    """Test cases for VulnerabilityRandomizer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.randomizer = VulnerabilityRandomizer()
        
        self.sample_data = {
            "ArtifactName": "original:latest",
            "Metadata": {
                "ImageID": "sha256:original123"
            }
        }
        
        self.sample_vulnerabilities = [
            {
                "VulnerabilityID": "CVE-2023-00001",
                "PkgName": "original-pkg",
                "InstalledVersion": "1.0.0",
                "FixedVersion": "1.0.1",
                "Severity": "HIGH",
                "CVSS": {
                    "nvd": {
                        "V2Score": 5.0,
                        "V3Score": 7.5
                    }
                },
                "PublishedDate": "2023-01-01T00:00:00Z",
                "LastModifiedDate": "2023-01-02T00:00:00Z"
            }
        ]
    
    def test_randomize_root_fields(self):
        """Test root field randomization."""
        result = self.randomizer.randomize_root_fields(self.sample_data.copy())
        
        # Should change values but keep structure
        self.assertNotEqual(result["ArtifactName"], self.sample_data["ArtifactName"])
        self.assertNotEqual(result["Metadata"]["ImageID"], self.sample_data["Metadata"]["ImageID"])
        self.assertIn("ArtifactName", result)
        self.assertIn("ImageID", result["Metadata"])
    
    def test_generate_cve_id(self):
        """Test CVE ID generation."""
        cve_id = self.randomizer._generate_cve_id()
        
        # Should match CVE-YYYY-XXXXX format
        self.assertTrue(cve_id.startswith("CVE-"))
        parts = cve_id.split("-")
        self.assertEqual(len(parts), 3)
        self.assertTrue(parts[1].isdigit())  # Year
        self.assertTrue(parts[2].isdigit())  # Number
        self.assertEqual(len(parts[2]), 5)   # 5-digit number
    
    def test_generate_package_name(self):
        """Test package name generation."""
        pkg_name = self.randomizer._generate_package_name()
        
        self.assertIn(pkg_name, self.randomizer.package_names)
        self.assertIsInstance(pkg_name, str)
        self.assertGreater(len(pkg_name), 0)
    
    def test_generate_severity(self):
        """Test severity generation."""
        severity = self.randomizer._generate_severity()
        
        self.assertIn(severity, self.randomizer.severity_levels)
    
    def test_generate_cvss_score(self):
        """Test CVSS score generation."""
        v2_score = self.randomizer._generate_cvss_score("V2")
        v3_score = self.randomizer._generate_cvss_score("V3")
        
        self.assertGreaterEqual(v2_score, 0.0)
        self.assertLessEqual(v2_score, 10.0)
        self.assertGreaterEqual(v3_score, 0.0)
        self.assertLessEqual(v3_score, 10.0)
    
    def test_randomize_vulnerabilities(self):
        """Test vulnerability randomization."""
        result = self.randomizer.randomize_vulnerabilities(self.sample_vulnerabilities.copy())
        
        self.assertEqual(len(result), len(self.sample_vulnerabilities))
        
        vuln = result[0]
        original = self.sample_vulnerabilities[0]
        
        # Should have different values but same structure
        self.assertNotEqual(vuln["VulnerabilityID"], original["VulnerabilityID"])
        self.assertNotEqual(vuln["PkgName"], original["PkgName"])
        self.assertIn("VulnerabilityID", vuln)
        self.assertIn("PkgName", vuln)


if __name__ == '__main__':
    unittest.main()
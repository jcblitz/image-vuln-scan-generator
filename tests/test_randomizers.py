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
            },
            "OwnerEmailAddress": "original@example.com"
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
        self.assertNotEqual(result["OwnerEmailAddress"], self.sample_data["OwnerEmailAddress"])
        # ImageID should be a valid SHA256 format
        self.assertTrue(result["Metadata"]["ImageID"].startswith("sha256:"))
        self.assertEqual(len(result["Metadata"]["ImageID"]), 71)  # "sha256:" + 64 hex chars
        self.assertIn("ArtifactName", result)
        self.assertIn("ImageID", result["Metadata"])
        self.assertIn("OwnerEmailAddress", result)
    
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
    
    def test_generate_version(self):
        """Test version string generation."""
        version = self.randomizer._generate_version()
        
        self.assertIsInstance(version, str)
        self.assertGreater(len(version), 0)
        # Should contain digits and dots or dashes
        self.assertTrue(any(c.isdigit() for c in version))
    
    def test_generate_date(self):
        """Test date generation in ISO format."""
        date_str = self.randomizer._generate_date()
        
        self.assertIsInstance(date_str, str)
        self.assertTrue(date_str.endswith('Z'))
        self.assertIn('T', date_str)
        # Should be parseable as ISO format
        from datetime import datetime
        try:
            datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        except ValueError:
            self.fail(f"Generated date {date_str} is not valid ISO format")
    
    def test_generate_artifact_name(self):
        """Test artifact name generation."""
        artifact_name = self.randomizer._generate_artifact_name()
        
        self.assertIsInstance(artifact_name, str)
        self.assertIn(':', artifact_name)  # Should have format base:version
        self.assertGreater(len(artifact_name), 0)
    
    def test_generate_image_id(self):
        """Test image ID generation."""
        image_id = self.randomizer._generate_image_id()
        
        self.assertTrue(image_id.startswith("sha256:"))
        self.assertEqual(len(image_id), 71)  # "sha256:" + 64 hex chars
        # Should be valid hex after sha256:
        hex_part = image_id[7:]
        self.assertTrue(all(c in '0123456789abcdef' for c in hex_part))
    
    def test_severity_distribution(self):
        """Test that severity generation follows realistic distribution."""
        severities = [self.randomizer._generate_severity() for _ in range(1000)]
        
        # Count occurrences
        counts = {level: severities.count(level) for level in self.randomizer.severity_levels}
        
        # MEDIUM should be most common, CRITICAL should be least common
        self.assertGreater(counts["MEDIUM"], counts["CRITICAL"])
        self.assertGreater(counts["LOW"], counts["CRITICAL"])
    
    def test_cvss_scores_correlation(self):
        """Test CVSS score generation with different versions."""
        v2_scores = [self.randomizer._generate_cvss_score("V2") for _ in range(100)]
        v3_scores = [self.randomizer._generate_cvss_score("V3") for _ in range(100)]
        
        # All scores should be in valid range
        for score in v2_scores + v3_scores:
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 10.0)
            self.assertIsInstance(score, float)
    
    def test_version_patterns(self):
        """Test that version generation produces various realistic patterns."""
        versions = [self.randomizer._generate_version() for _ in range(100)]
        
        # Should have variety in patterns
        patterns = set()
        for version in versions:
            if '.' in version and '-' in version:
                patterns.add('semantic_with_revision')
            elif '.' in version:
                patterns.add('semantic')
            elif len(version) == 7 and all(c in '0123456789abcdef' for c in version):
                patterns.add('git_hash')
            elif 'ubuntu' in version:
                patterns.add('ubuntu_style')
            else:
                patterns.add('other')
        
        # Should have at least 2 different patterns
        self.assertGreaterEqual(len(patterns), 2)
    
    def test_cvss_score_precision(self):
        """Test CVSS score precision and realistic ranges."""
        scores = [self.randomizer._generate_cvss_score("V3") for _ in range(50)]
        
        # All scores should be rounded to 1 decimal place
        for score in scores:
            self.assertEqual(score, round(score, 1))
        
        # Should have variety in scores
        unique_scores = set(scores)
        self.assertGreater(len(unique_scores), 10)  # Should have good variety
    
    def test_randomize_cvss_scores_in_place(self):
        """Test CVSS score randomization modifies data in place."""
        cvss_data = {
            "nvd": {
                "V2Score": 5.0,
                "V3Score": 7.5,
                "V2Vector": "original",
                "V3Vector": "original"
            }
        }
        
        original_v2 = cvss_data["nvd"]["V2Score"]
        original_v3 = cvss_data["nvd"]["V3Score"]
        
        self.randomizer._randomize_cvss_scores(cvss_data)
        
        # Scores should be changed
        self.assertNotEqual(cvss_data["nvd"]["V2Score"], original_v2)
        self.assertNotEqual(cvss_data["nvd"]["V3Score"], original_v3)
        
        # Vectors should remain unchanged
        self.assertEqual(cvss_data["nvd"]["V2Vector"], "original")
        self.assertEqual(cvss_data["nvd"]["V3Vector"], "original")
    
    def test_cvss_severity_correlation(self):
        """Test that CVSS scores correlate with severity levels."""
        # Test CRITICAL severity
        critical_scores = [self.randomizer._generate_cvss_score("V3", "CRITICAL") for _ in range(50)]
        for score in critical_scores:
            self.assertGreaterEqual(score, 9.0)
            self.assertLessEqual(score, 10.0)
        
        # Test LOW severity
        low_scores = [self.randomizer._generate_cvss_score("V3", "LOW") for _ in range(50)]
        for score in low_scores:
            self.assertGreaterEqual(score, 0.1)
            self.assertLessEqual(score, 3.9)
        
        # Test MEDIUM severity
        medium_scores = [self.randomizer._generate_cvss_score("V3", "MEDIUM") for _ in range(50)]
        for score in medium_scores:
            self.assertGreaterEqual(score, 4.0)
            self.assertLessEqual(score, 6.9)
    
    def test_vulnerability_correlation_integration(self):
        """Test that vulnerability randomization maintains correlation between severity and CVSS."""
        vuln_with_cvss = {
            "VulnerabilityID": "CVE-2023-00001",
            "Severity": "HIGH",
            "CVSS": {
                "nvd": {
                    "V2Score": 5.0,
                    "V3Score": 7.5
                }
            }
        }
        
        result = self.randomizer.randomize_vulnerabilities([vuln_with_cvss])
        randomized_vuln = result[0]
        
        severity = randomized_vuln["Severity"]
        v3_score = randomized_vuln["CVSS"]["nvd"]["V3Score"]
        
        # Verify correlation based on severity
        if severity == "CRITICAL":
            self.assertGreaterEqual(v3_score, 9.0)
        elif severity == "HIGH":
            self.assertGreaterEqual(v3_score, 7.0)
            self.assertLessEqual(v3_score, 8.9)
        elif severity == "MEDIUM":
            self.assertGreaterEqual(v3_score, 4.0)
            self.assertLessEqual(v3_score, 6.9)
        elif severity == "LOW":
            self.assertGreaterEqual(v3_score, 0.1)
            self.assertLessEqual(v3_score, 3.9)
    
    def test_date_generation_faker_integration(self):
        """Test date generation uses Faker utilities properly."""
        dates = [self.randomizer._generate_date() for _ in range(20)]
        
        # All dates should be unique (very high probability)
        self.assertEqual(len(dates), len(set(dates)))
        
        # All dates should be in the past 5 years
        from datetime import datetime
        now = datetime.now()
        five_years_ago = datetime(now.year - 5, now.month, now.day)
        
        for date_str in dates:
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00')).replace(tzinfo=None)
            self.assertGreaterEqual(date_obj, five_years_ago)
            self.assertLessEqual(date_obj, now)
    
    def test_artifact_name_realistic_patterns(self):
        """Test artifact name generation produces realistic container patterns."""
        names = [self.randomizer._generate_artifact_name() for _ in range(50)]
        
        for name in names:
            # Should have base:version format
            self.assertIn(':', name)
            parts = name.split(':')
            self.assertEqual(len(parts), 2)
            
            base, version_tag = parts
            # Base should be a known container name
            base_names = ["alpine", "ubuntu", "debian", "centos", "nginx", "node", "python", "golang"]
            self.assertIn(base, base_names)
            
            # Version should contain digits
            self.assertTrue(any(c.isdigit() for c in version_tag))
    
    def test_image_id_faker_integration(self):
        """Test image ID generation uses Faker for realistic hashes."""
        image_ids = [self.randomizer._generate_image_id() for _ in range(20)]
        
        # All should be unique
        self.assertEqual(len(image_ids), len(set(image_ids)))
        
        for image_id in image_ids:
            self.assertTrue(image_id.startswith("sha256:"))
            hex_part = image_id[7:]
            self.assertEqual(len(hex_part), 64)
            # Should be valid hex
            self.assertTrue(all(c in '0123456789abcdef' for c in hex_part))
    
    def test_generate_email_address(self):
        """Test email address generation."""
        email = self.randomizer._generate_email_address()
        
        self.assertIsInstance(email, str)
        self.assertIn('@', email)
        self.assertGreater(len(email), 0)
        
        # Should have basic email format
        parts = email.split('@')
        self.assertEqual(len(parts), 2)
        self.assertGreater(len(parts[0]), 0)  # Username part
        self.assertGreater(len(parts[1]), 0)  # Domain part
        self.assertIn('.', parts[1])  # Domain should have TLD
    
    def test_generate_email_address_uniqueness(self):
        """Test that generated email addresses are unique."""
        emails = [self.randomizer._generate_email_address() for _ in range(50)]
        
        # Should have high uniqueness (very high probability with Faker)
        unique_emails = set(emails)
        self.assertGreater(len(unique_emails), 40)  # Allow for small chance of duplicates
    
    def test_generate_email_address_realistic_format(self):
        """Test that generated email addresses follow realistic patterns."""
        emails = [self.randomizer._generate_email_address() for _ in range(20)]
        
        for email in emails:
            # Should be valid email format
            self.assertRegex(email, r'^[^@]+@[^@]+\.[^@]+$')
            
            # Should not have consecutive dots or start/end with dots
            self.assertNotIn('..', email)
            self.assertFalse(email.startswith('.'))
            self.assertFalse(email.endswith('.'))
    
    def test_randomize_root_fields_with_owner_email(self):
        """Test root field randomization specifically for OwnerEmailAddress."""
        data_with_email = {
            "ArtifactName": "test:latest",
            "OwnerEmailAddress": "test@example.com",
            "Metadata": {
                "ImageID": "sha256:test123"
            }
        }
        
        result = self.randomizer.randomize_root_fields(data_with_email.copy())
        
        # OwnerEmailAddress should be changed
        self.assertNotEqual(result["OwnerEmailAddress"], data_with_email["OwnerEmailAddress"])
        
        # Should still be a valid email format
        self.assertIn('@', result["OwnerEmailAddress"])
        self.assertRegex(result["OwnerEmailAddress"], r'^[^@]+@[^@]+\.[^@]+$')
    
    def test_randomize_root_fields_without_owner_email(self):
        """Test root field randomization when OwnerEmailAddress is not present."""
        data_without_email = {
            "ArtifactName": "test:latest",
            "Metadata": {
                "ImageID": "sha256:test123"
            }
        }
        
        result = self.randomizer.randomize_root_fields(data_without_email.copy())
        
        # Should not add OwnerEmailAddress if it wasn't there originally
        self.assertNotIn("OwnerEmailAddress", result)
        
        # Other fields should still be randomized (check format rather than exact value)
        self.assertIn(':', result["ArtifactName"])  # Should have artifact:version format
        self.assertTrue(result["Metadata"]["ImageID"].startswith("sha256:"))  # Should be valid SHA format


    def test_randomize_vulnerability_count_empty_list(self):
        """Test vulnerability count randomization with empty list."""
        result = self.randomizer.randomize_vulnerability_count([])
        self.assertEqual(result, [])
    
    def test_randomize_vulnerability_count_zero_target(self):
        """Test vulnerability count randomization when target is 0."""
        with patch('random.randint', return_value=0):
            result = self.randomizer.randomize_vulnerability_count(self.sample_vulnerabilities)
            self.assertEqual(result, [])
    
    def test_randomize_vulnerability_count_subset_selection(self):
        """Test vulnerability count randomization when reducing count."""
        # Create multiple vulnerabilities for testing
        multiple_vulns = [
            {"VulnerabilityID": f"CVE-2023-{i:05d}", "PkgName": f"pkg{i}"}
            for i in range(5)
        ]
        
        # Mock random.randint to return 3 (less than original 5)
        with patch('random.randint', return_value=3):
            result = self.randomizer.randomize_vulnerability_count(multiple_vulns)
            
            self.assertEqual(len(result), 3)
            # All returned vulnerabilities should be from the original list
            for vuln in result:
                self.assertIn(vuln, multiple_vulns)
    
    def test_randomize_vulnerability_count_duplication(self):
        """Test vulnerability count randomization when increasing count."""
        # Mock random.randint to return 15 (more than original 1)
        with patch('random.randint', return_value=15):
            result = self.randomizer.randomize_vulnerability_count(self.sample_vulnerabilities)
            
            self.assertEqual(len(result), 15)
            # Should contain the original vulnerability
            original_vuln = self.sample_vulnerabilities[0]
            found_original = False
            for vuln in result:
                if vuln["VulnerabilityID"] == original_vuln["VulnerabilityID"]:
                    found_original = True
                    break
            self.assertTrue(found_original)
    
    def test_randomize_vulnerability_count_range(self):
        """Test vulnerability count randomization stays within 0-20 range."""
        # Test multiple times to ensure range is respected
        for _ in range(50):
            result = self.randomizer.randomize_vulnerability_count(self.sample_vulnerabilities)
            self.assertGreaterEqual(len(result), 0)
            self.assertLessEqual(len(result), 20)
    
    def test_randomize_vulnerability_count_deep_copy(self):
        """Test that duplicated vulnerabilities are deep copies."""
        # Mock random.randint to return 3 (more than original 1)
        with patch('random.randint', return_value=3):
            result = self.randomizer.randomize_vulnerability_count(self.sample_vulnerabilities)
            
            self.assertEqual(len(result), 3)
            
            # Modify one of the results
            result[0]["VulnerabilityID"] = "MODIFIED"
            
            # Original should be unchanged
            self.assertNotEqual(self.sample_vulnerabilities[0]["VulnerabilityID"], "MODIFIED")
            
            # Other copies should also be unchanged
            for i in range(1, len(result)):
                if result[i]["VulnerabilityID"] == "MODIFIED":
                    self.fail("Deep copy failed - modifications affected other instances")
    
    def test_randomize_vulnerability_count_maintains_structure(self):
        """Test that vulnerability structure is maintained after count randomization."""
        complex_vuln = {
            "VulnerabilityID": "CVE-2023-00001",
            "PkgName": "test-pkg",
            "Severity": "HIGH",
            "CVSS": {
                "nvd": {
                    "V2Score": 5.0,
                    "V3Score": 7.5
                }
            },
            "References": ["http://example.com"],
            "PublishedDate": "2023-01-01T00:00:00Z"
        }
        
        with patch('random.randint', return_value=5):
            result = self.randomizer.randomize_vulnerability_count([complex_vuln])
            
            self.assertEqual(len(result), 5)
            
            # Check that all vulnerabilities maintain the complex structure
            for vuln in result:
                self.assertIn("VulnerabilityID", vuln)
                self.assertIn("PkgName", vuln)
                self.assertIn("Severity", vuln)
                self.assertIn("CVSS", vuln)
                self.assertIn("nvd", vuln["CVSS"])
                self.assertIn("V2Score", vuln["CVSS"]["nvd"])
                self.assertIn("V3Score", vuln["CVSS"]["nvd"])
                self.assertIn("References", vuln)
                self.assertIn("PublishedDate", vuln)
    
    def test_randomize_vulnerability_count_shuffling(self):
        """Test that duplicated vulnerabilities are shuffled in the result."""
        # Create multiple distinct vulnerabilities
        multiple_vulns = [
            {"VulnerabilityID": "CVE-2023-00001", "PkgName": "pkg1"},
            {"VulnerabilityID": "CVE-2023-00002", "PkgName": "pkg2"},
            {"VulnerabilityID": "CVE-2023-00003", "PkgName": "pkg3"}
        ]
        
        # Mock to return 9 (3x original count)
        with patch('random.randint', return_value=9):
            # Run multiple times to check for shuffling
            results = []
            for _ in range(10):
                result = self.randomizer.randomize_vulnerability_count(multiple_vulns)
                # Get the order of vulnerability IDs
                order = [vuln["VulnerabilityID"] for vuln in result]
                results.append(tuple(order))
            
            # Should have different orderings (very high probability)
            unique_orders = set(results)
            self.assertGreater(len(unique_orders), 1, "Results should be shuffled")
    
    def test_randomize_vulnerability_count_exact_match(self):
        """Test vulnerability count randomization when target equals original count."""
        multiple_vulns = [
            {"VulnerabilityID": f"CVE-2023-{i:05d}", "PkgName": f"pkg{i}"}
            for i in range(5)
        ]
        
        # Mock to return same count as original
        with patch('random.randint', return_value=5):
            result = self.randomizer.randomize_vulnerability_count(multiple_vulns)
            
            self.assertEqual(len(result), 5)
            # Should be a subset (which happens to be all) of original
            for vuln in result:
                self.assertIn(vuln, multiple_vulns)
    
    def test_deep_copy_vulnerability_method(self):
        """Test the _deep_copy_vulnerability helper method."""
        complex_vuln = {
            "VulnerabilityID": "CVE-2023-00001",
            "nested": {
                "deep": {
                    "value": [1, 2, 3]
                }
            }
        }
        
        copied_vuln = self.randomizer._deep_copy_vulnerability(complex_vuln)
        
        # Should be equal but not the same object
        self.assertEqual(copied_vuln, complex_vuln)
        self.assertIsNot(copied_vuln, complex_vuln)
        
        # Modifying copy should not affect original
        copied_vuln["VulnerabilityID"] = "MODIFIED"
        copied_vuln["nested"]["deep"]["value"].append(4)
        
        self.assertEqual(complex_vuln["VulnerabilityID"], "CVE-2023-00001")
        self.assertEqual(complex_vuln["nested"]["deep"]["value"], [1, 2, 3])
    
    def test_randomize_vulnerability_count_statistical_distribution(self):
        """Test that vulnerability count randomization produces expected statistical distribution."""
        counts = []
        for _ in range(1000):
            result = self.randomizer.randomize_vulnerability_count(self.sample_vulnerabilities)
            counts.append(len(result))
        
        # Should have variety in counts
        unique_counts = set(counts)
        self.assertGreater(len(unique_counts), 10)  # Should have good variety
        
        # All counts should be in valid range
        self.assertEqual(min(counts), min(counts, key=lambda x: x if x >= 0 else float('inf')))
        self.assertEqual(max(counts), max(counts, key=lambda x: x if x <= 20 else float('-inf')))
        
        # Should include both 0 and 20 in the distribution (with high probability)
        self.assertIn(0, counts)
        self.assertIn(20, counts)


if __name__ == '__main__':
    unittest.main()
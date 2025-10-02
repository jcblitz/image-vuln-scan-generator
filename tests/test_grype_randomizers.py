"""
Unit tests for GrypeRandomizer core functionality.
"""

import json
import os
import unittest
from copy import deepcopy

from src.grype.randomizers import GrypeRandomizer


class TestGrypeRandomizer(unittest.TestCase):
    """Test cases for GrypeRandomizer class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.randomizer = GrypeRandomizer()
        
        # Load sample Grype data for testing
        test_data_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        grype_sample_file = os.path.join(test_data_dir, 'grype-golang-1.12-alpine.json')
        
        with open(grype_sample_file, 'r') as f:
            self.sample_data = json.load(f)
    
    def test_randomizer_initialization(self):
        """Test that GrypeRandomizer initializes with correct data sources."""
        self.assertIsInstance(self.randomizer.grype_severities, list)
        self.assertIn("Critical", self.randomizer.grype_severities)
        self.assertIn("High", self.randomizer.grype_severities)
        self.assertIn("Medium", self.randomizer.grype_severities)
        
        self.assertIsInstance(self.randomizer.matcher_types, list)
        self.assertIn("apk-matcher", self.randomizer.matcher_types)
        
        self.assertIsInstance(self.randomizer.distro_types, list)
        self.assertIn("alpine", self.randomizer.distro_types)
        
        self.assertIsInstance(self.randomizer.fix_states, list)
        self.assertIn("fixed", self.randomizer.fix_states)
    
    def test_randomize_matches_basic_functionality(self):
        """Test basic match randomization functionality."""
        original_matches = self.sample_data.get('matches', [])
        if not original_matches:
            self.skipTest("No matches in sample data")
        
        # Randomize matches
        randomized_matches = self.randomizer.randomize_matches(original_matches)
        
        # Verify result is a list
        self.assertIsInstance(randomized_matches, list)
        
        # Verify count is within expected range (1-50)
        self.assertGreaterEqual(len(randomized_matches), 1)
        self.assertLessEqual(len(randomized_matches), 50)
        
        # Verify each match is a dictionary
        for match in randomized_matches:
            self.assertIsInstance(match, dict)
    
    def test_randomize_matches_count_range(self):
        """Test that match count randomization stays within 1-50 range."""
        original_matches = self.sample_data.get('matches', [])
        if not original_matches:
            # Create a minimal match for testing
            original_matches = [{"vulnerability": {"id": "CVE-2023-1234"}}]
        
        # Test multiple randomizations to verify range
        for _ in range(10):
            randomized_matches = self.randomizer.randomize_matches(original_matches)
            self.assertGreaterEqual(len(randomized_matches), 1)
            self.assertLessEqual(len(randomized_matches), 50)
    
    def test_randomize_matches_empty_input(self):
        """Test randomize_matches with empty input."""
        empty_matches = []
        result = self.randomizer.randomize_matches(empty_matches)
        self.assertEqual(result, [])
    
    def test_randomize_vulnerability_basic_fields(self):
        """Test vulnerability randomization of basic fields."""
        if not self.sample_data.get('matches'):
            self.skipTest("No matches in sample data")
        
        original_vuln = self.sample_data['matches'][0].get('vulnerability', {})
        if not original_vuln:
            self.skipTest("No vulnerability in first match")
        
        # Randomize vulnerability
        randomized_vuln = self.randomizer.randomize_vulnerability(original_vuln)
        
        # Verify structure is preserved
        self.assertIsInstance(randomized_vuln, dict)
        
        # Verify CVE ID format if present
        if 'id' in randomized_vuln:
            cve_id = randomized_vuln['id']
            self.assertRegex(cve_id, r'^CVE-\d{4}-\d{4,}$')
        
        # Verify severity is valid if present
        if 'severity' in randomized_vuln:
            severity = randomized_vuln['severity']
            self.assertIn(severity, self.randomizer.grype_severities)
    
    def test_randomize_vulnerability_cvss_metrics(self):
        """Test CVSS metrics randomization."""
        # Create test vulnerability with CVSS data
        test_vuln = {
            "id": "CVE-2023-1234",
            "severity": "High",
            "cvss": [
                {
                    "source": "nvd@nist.gov",
                    "metrics": {
                        "baseScore": 7.5,
                        "exploitabilityScore": 3.9,
                        "impactScore": 3.6
                    }
                }
            ]
        }
        
        randomized_vuln = self.randomizer.randomize_vulnerability(test_vuln)
        
        # Verify CVSS structure is preserved
        self.assertIn('cvss', randomized_vuln)
        self.assertIsInstance(randomized_vuln['cvss'], list)
        
        if randomized_vuln['cvss']:
            cvss_item = randomized_vuln['cvss'][0]
            self.assertIn('metrics', cvss_item)
            
            metrics = cvss_item['metrics']
            # Verify scores are in valid range (0.0-10.0)
            for score_field in ['baseScore', 'exploitabilityScore', 'impactScore']:
                if score_field in metrics:
                    score = metrics[score_field]
                    self.assertGreaterEqual(score, 0.0)
                    self.assertLessEqual(score, 10.0)
    
    def test_randomize_artifact_purl_generation(self):
        """Test artifact randomization with PURL generation."""
        # Create test artifact
        test_artifact = {
            "id": "test-id",
            "name": "zlib",
            "version": "1.2.11",
            "type": "apk",
            "purl": "pkg:apk/alpine/zlib@1.2.11?arch=x86_64"
        }
        
        randomized_artifact = self.randomizer.randomize_artifact(test_artifact)
        
        # Verify structure is preserved
        self.assertIsInstance(randomized_artifact, dict)
        self.assertIn('purl', randomized_artifact)
        
        # Verify PURL format
        purl = randomized_artifact['purl']
        self.assertTrue(purl.startswith('pkg:'))
        self.assertIn('@', purl)  # Should contain version separator
    
    def test_randomize_related_vulnerabilities_count_range(self):
        """Test that related vulnerabilities count stays within 0-5 range."""
        # Test with existing related vulnerabilities
        test_related = [
            {"id": "CVE-2023-1234", "severity": "Medium"},
            {"id": "CVE-2023-5678", "severity": "Low"}
        ]
        
        # Test multiple randomizations
        for _ in range(10):
            randomized_related = self.randomizer.randomize_related_vulnerabilities(test_related)
            self.assertIsInstance(randomized_related, list)
            self.assertGreaterEqual(len(randomized_related), 0)
            self.assertLessEqual(len(randomized_related), 5)
    
    def test_randomize_related_vulnerabilities_empty_input(self):
        """Test related vulnerabilities randomization with empty input."""
        empty_related = []
        
        # Should still generate 0-5 related vulnerabilities
        randomized_related = self.randomizer.randomize_related_vulnerabilities(empty_related)
        self.assertIsInstance(randomized_related, list)
        self.assertGreaterEqual(len(randomized_related), 0)
        self.assertLessEqual(len(randomized_related), 5)
    
    def test_randomize_match_details_structure(self):
        """Test match details randomization preserves structure."""
        # Create test match details
        test_match_details = [
            {
                "type": "exact-direct-match",
                "matcher": "apk-matcher",
                "searchedBy": {
                    "distro": {"type": "alpine", "version": "3.11"},
                    "package": {"name": "zlib", "version": "1.2.11"}
                },
                "found": {
                    "vulnerabilityID": "CVE-2023-1234",
                    "versionConstraint": "< 1.2.12"
                }
            }
        ]
        
        randomized_details = self.randomizer.randomize_match_details(test_match_details)
        
        # Verify structure is preserved
        self.assertIsInstance(randomized_details, list)
        self.assertEqual(len(randomized_details), 1)
        
        detail = randomized_details[0]
        self.assertIsInstance(detail, dict)
        self.assertIn('matcher', detail)
        self.assertIn('searchedBy', detail)
        self.assertIn('found', detail)
        
        # Verify matcher type is valid
        if 'matcher' in detail:
            self.assertIn(detail['matcher'], self.randomizer.matcher_types)
    
    def test_generate_grype_severity_distribution(self):
        """Test that severity generation has realistic distribution."""
        # Generate many severities to test distribution
        severities = []
        for _ in range(100):
            severity = self.randomizer._generate_grype_severity()
            severities.append(severity)
            self.assertIn(severity, self.randomizer.grype_severities)
        
        # Verify we get variety (not all the same)
        unique_severities = set(severities)
        self.assertGreater(len(unique_severities), 1)
    
    def test_generate_cvss_metrics_realistic_values(self):
        """Test that CVSS metrics generation produces realistic values."""
        metrics = self.randomizer._generate_cvss_metrics()
        
        # Verify structure
        self.assertIsInstance(metrics, dict)
        self.assertIn('baseScore', metrics)
        self.assertIn('exploitabilityScore', metrics)
        self.assertIn('impactScore', metrics)
        
        # Verify ranges
        for score_name, score_value in metrics.items():
            self.assertGreaterEqual(score_value, 0.0)
            self.assertLessEqual(score_value, 10.0)
            self.assertIsInstance(score_value, float)
    
    def test_generate_package_url_format(self):
        """Test PURL generation produces valid format."""
        purl = self.randomizer._generate_package_url("apk", "zlib", "1.2.11")
        
        # Verify basic PURL format
        self.assertTrue(purl.startswith("pkg:apk/"))
        self.assertIn("zlib@1.2.11", purl)
        
        # Test different package types
        maven_purl = self.randomizer._generate_package_url("maven", "commons-lang", "3.12.0")
        self.assertTrue(maven_purl.startswith("pkg:maven/"))
        self.assertIn("commons-lang@3.12.0", maven_purl)


if __name__ == '__main__':
    unittest.main()
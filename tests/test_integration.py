"""
Integration tests for the Trivy Test Data Generator.
Tests complete end-to-end workflows and schema preservation.
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.generator import TrivyDataGenerator
from src.main import main, parse_arguments
from src.validators import TrivyValidator
from src.exceptions import ValidationError, GenerationError


class TestEndToEndIntegration(unittest.TestCase):
    """End-to-end integration tests for complete workflow."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.sample_trivy_data = {
            "SchemaVersion": 2,
            "ArtifactName": "test:latest",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:abc123",
                "DiffIDs": ["sha256:diff123"],
                "RepoTags": ["test:latest"],
                "RepoDigests": ["test@sha256:digest123"],
                "ImageConfig": {
                    "architecture": "amd64",
                    "created": "2023-01-15T10:30:00Z",
                    "os": "linux"
                }
            },
            "Results": [
                {
                    "Target": "test (alpine 3.10.2)",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-12345",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1g-r0",
                            "FixedVersion": "1.1.1h-r0",
                            "Layer": {
                                "Digest": "sha256:layer123",
                                "DiffID": "sha256:diff123"
                            },
                            "SeveritySource": "nvd",
                            "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-12345",
                            "DataSource": {
                                "ID": "alpine",
                                "Name": "Alpine Secdb",
                                "URL": "https://secdb.alpinelinux.org/"
                            },
                            "Title": "openssl: buffer overflow vulnerability",
                            "Description": "A buffer overflow vulnerability exists in OpenSSL.",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-120"],
                            "CVSS": {
                                "nvd": {
                                    "V2Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "V2Score": 7.5,
                                    "V3Score": 9.8
                                }
                            },
                            "References": [
                                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345"
                            ],
                            "PublishedDate": "2023-03-15T14:30:00Z",
                            "LastModifiedDate": "2023-03-16T09:15:00Z"
                        }
                    ]
                }
            ]
        }
        
        # Create input file
        self.input_file = Path(self.temp_dir) / "input.json"
        with open(self.input_file, 'w') as f:
            json.dump(self.sample_trivy_data, f, indent=2)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_complete_workflow_small_batch(self):
        """Test complete workflow with small batch of files."""
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(str(self.input_file), str(output_dir))
        
        # Generate files
        generated_files = generator.generate_files(5)
        
        # Verify correct number of files generated
        self.assertEqual(len(generated_files), 5)
        
        # Verify all files exist and are valid JSON
        validator = TrivyValidator()
        for file_path in generated_files:
            self.assertTrue(Path(file_path).exists())
            
            # Load and validate each file
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Validate schema preservation
            validator.validate_generated_file(data)
            
            # Verify basic structure
            self.assertIn("SchemaVersion", data)
            self.assertIn("ArtifactName", data)
            self.assertIn("Results", data)
            
            # Verify randomization occurred
            self.assertNotEqual(data["ArtifactName"], self.sample_trivy_data["ArtifactName"])
            if "Metadata" in data and "ImageID" in data["Metadata"]:
                self.assertNotEqual(
                    data["Metadata"]["ImageID"], 
                    self.sample_trivy_data["Metadata"]["ImageID"]
                )
    
    def test_complete_workflow_medium_batch(self):
        """Test complete workflow with medium batch of files."""
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(str(self.input_file), str(output_dir))
        
        start_time = time.time()
        generated_files = generator.generate_files(50)
        duration = time.time() - start_time
        
        # Verify performance is reasonable
        self.assertLess(duration, 10.0, f"Generation took {duration:.2f}s, expected <10s")
        
        # Verify correct number of files
        self.assertEqual(len(generated_files), 50)
        
        # Sample validation of a few files
        validator = TrivyValidator()
        sample_files = generated_files[::10]  # Every 10th file
        
        for file_path in sample_files:
            self.assertTrue(Path(file_path).exists())
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            validator.validate_generated_file(data)
    
    def test_cli_integration(self):
        """Test CLI integration with argument parsing and execution."""
        output_dir = Path(self.temp_dir) / "cli_output"
        
        # Mock sys.argv to simulate CLI call
        test_args = [
            "trivy-generator",
            str(self.input_file),
            "--count", "3",
            "--output-dir", str(output_dir),
            "--verbose"
        ]
        
        with patch('sys.argv', test_args):
            args = parse_arguments()
            
            # Verify arguments parsed correctly
            self.assertEqual(args.input_file, str(self.input_file))
            self.assertEqual(args.count, 3)
            self.assertEqual(args.output_dir, str(output_dir))
            self.assertTrue(args.verbose)
        
        # Test main function execution
        with patch('sys.argv', test_args):
            exit_code = main()
            
            # Verify successful execution
            self.assertEqual(exit_code, 0)
            
            # Verify files were created
            self.assertTrue(output_dir.exists())
            generated_files = list(output_dir.glob("*.json"))
            self.assertEqual(len(generated_files), 3)
    
    def test_error_handling_integration(self):
        """Test error handling in complete workflow."""
        # Test with non-existent input file
        with self.assertRaises(Exception):
            generator = TrivyDataGenerator("non_existent.json", self.temp_dir)
        
        # Test with invalid JSON input
        invalid_json_file = Path(self.temp_dir) / "invalid.json"
        with open(invalid_json_file, 'w') as f:
            f.write("{ invalid json }")
        
        generator = TrivyDataGenerator(str(invalid_json_file), self.temp_dir)
        with self.assertRaises((ValidationError, GenerationError)):
            generator.generate_files(1)
        
        # Test with invalid count
        generator = TrivyDataGenerator(str(self.input_file), self.temp_dir)
        with self.assertRaises(GenerationError):
            generator.generate_files(0)
        
        with self.assertRaises(GenerationError):
            generator.generate_files(-1)


class TestSchemaPreservation(unittest.TestCase):
    """Tests for schema preservation across different file variations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.validator = TrivyValidator()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_minimal_trivy_file_preservation(self):
        """Test schema preservation with minimal Trivy file."""
        minimal_data = {
            "SchemaVersion": 2,
            "ArtifactName": "minimal:test",
            "ArtifactType": "container_image",
            "Results": []
        }
        
        input_file = Path(self.temp_dir) / "minimal.json"
        with open(input_file, 'w') as f:
            json.dump(minimal_data, f)
        
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        generated_files = generator.generate_files(3)
        
        for file_path in generated_files:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Validate schema is preserved
            self.validator.validate_generated_file(data)
            
            # Verify structure matches original
            self.assertEqual(data["SchemaVersion"], minimal_data["SchemaVersion"])
            self.assertEqual(data["ArtifactType"], minimal_data["ArtifactType"])
            self.assertIsInstance(data["Results"], list)
            
            # Verify randomization occurred where expected
            self.assertNotEqual(data["ArtifactName"], minimal_data["ArtifactName"])
    
    def test_complex_trivy_file_preservation(self):
        """Test schema preservation with complex Trivy file structure."""
        complex_data = {
            "SchemaVersion": 2,
            "ArtifactName": "complex:test",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:complex123",
                "DiffIDs": ["sha256:diff1", "sha256:diff2"],
                "RepoTags": ["complex:test", "complex:latest"],
                "RepoDigests": ["complex@sha256:digest1"],
                "ImageConfig": {
                    "architecture": "amd64",
                    "created": "2023-01-15T10:30:00Z",
                    "os": "linux",
                    "config": {
                        "Env": ["PATH=/usr/local/sbin:/usr/local/bin"],
                        "Cmd": ["/bin/sh"]
                    }
                }
            },
            "Results": [
                {
                    "Target": "complex (alpine 3.10.2)",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-11111",
                            "PkgName": "package1",
                            "InstalledVersion": "1.0.0",
                            "FixedVersion": "1.0.1",
                            "Severity": "HIGH",
                            "CVSS": {
                                "nvd": {"V3Score": 8.5},
                                "redhat": {"V3Score": 7.8}
                            },
                            "PublishedDate": "2023-01-01T00:00:00Z",
                            "LastModifiedDate": "2023-01-02T00:00:00Z"
                        },
                        {
                            "VulnerabilityID": "CVE-2023-22222",
                            "PkgName": "package2",
                            "InstalledVersion": "2.0.0",
                            "Severity": "MEDIUM",
                            "CVSS": {
                                "nvd": {"V2Score": 5.0, "V3Score": 6.2}
                            },
                            "PublishedDate": "2023-02-01T00:00:00Z",
                            "LastModifiedDate": "2023-02-02T00:00:00Z"
                        }
                    ]
                },
                {
                    "Target": "complex-lib",
                    "Class": "lang-pkgs",
                    "Type": "npm",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-33333",
                            "PkgName": "npm-package",
                            "InstalledVersion": "3.0.0",
                            "Severity": "LOW",
                            "PublishedDate": "2023-03-01T00:00:00Z",
                            "LastModifiedDate": "2023-03-02T00:00:00Z"
                        }
                    ]
                }
            ]
        }
        
        input_file = Path(self.temp_dir) / "complex.json"
        with open(input_file, 'w') as f:
            json.dump(complex_data, f, indent=2)
        
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        generated_files = generator.generate_files(5)
        
        for file_path in generated_files:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Validate schema is preserved
            self.validator.validate_generated_file(data)
            
            # Verify complex structure is maintained
            self.assertEqual(data["SchemaVersion"], complex_data["SchemaVersion"])
            self.assertEqual(data["ArtifactType"], complex_data["ArtifactType"])
            self.assertIn("Metadata", data)
            self.assertIn("ImageConfig", data["Metadata"])
            self.assertEqual(len(data["Results"]), len(complex_data["Results"]))
            
            # Verify nested structures are preserved
            for i, result in enumerate(data["Results"]):
                original_result = complex_data["Results"][i]
                self.assertEqual(result["Target"], original_result["Target"])
                self.assertEqual(result["Class"], original_result["Class"])
                self.assertEqual(result["Type"], original_result["Type"])
                
                # Verify vulnerabilities structure (count may vary due to randomization)
                if "Vulnerabilities" in result:
                    for vuln in result["Vulnerabilities"]:
                        self.assertIn("VulnerabilityID", vuln)
                        self.assertIn("PkgName", vuln)
                        self.assertIn("Severity", vuln)
    
    def test_vulnerability_count_variations(self):
        """Test schema preservation with different vulnerability counts."""
        base_data = {
            "SchemaVersion": 2,
            "ArtifactName": "test:count",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "test",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": []
                }
            ]
        }
        
        # Test with different initial vulnerability counts
        test_counts = [0, 1, 5, 10, 20]
        
        for initial_count in test_counts:
            with self.subTest(initial_count=initial_count):
                # Create vulnerabilities
                vulnerabilities = []
                for i in range(initial_count):
                    vulnerabilities.append({
                        "VulnerabilityID": f"CVE-2023-{i:05d}",
                        "PkgName": f"package{i}",
                        "InstalledVersion": f"{i}.0.0",
                        "Severity": "MEDIUM",
                        "PublishedDate": "2023-01-01T00:00:00Z",
                        "LastModifiedDate": "2023-01-02T00:00:00Z"
                    })
                
                test_data = base_data.copy()
                test_data["Results"][0]["Vulnerabilities"] = vulnerabilities
                
                input_file = Path(self.temp_dir) / f"count_{initial_count}.json"
                with open(input_file, 'w') as f:
                    json.dump(test_data, f)
                
                output_dir = Path(self.temp_dir) / f"output_{initial_count}"
                generator = TrivyDataGenerator(str(input_file), str(output_dir))
                
                generated_files = generator.generate_files(3)
                
                for file_path in generated_files:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                    
                    # Validate schema is preserved
                    self.validator.validate_generated_file(data)
                    
                    # Verify structure
                    self.assertEqual(data["SchemaVersion"], 2)
                    self.assertIn("Results", data)
                    self.assertEqual(len(data["Results"]), 1)
                    
                    # Verify vulnerabilities structure (count may be randomized 0-20)
                    vulnerabilities = data["Results"][0]["Vulnerabilities"]
                    self.assertIsInstance(vulnerabilities, list)
                    self.assertLessEqual(len(vulnerabilities), 20)
                    
                    # If vulnerabilities exist, verify their structure
                    for vuln in vulnerabilities:
                        self.assertIn("VulnerabilityID", vuln)
                        self.assertIn("PkgName", vuln)
                        self.assertIn("Severity", vuln)


class TestVariousFileSizes(unittest.TestCase):
    """Tests with various file sizes and complexity levels."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.validator = TrivyValidator()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_file(self, vuln_count: int, result_count: int = 1) -> Path:
        """Create a test file with specified vulnerability and result counts."""
        data = {
            "SchemaVersion": 2,
            "ArtifactName": f"test:v{vuln_count}",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": f"sha256:test{vuln_count}"
            },
            "Results": []
        }
        
        for r in range(result_count):
            vulnerabilities = []
            for i in range(vuln_count):
                vulnerabilities.append({
                    "VulnerabilityID": f"CVE-2023-{r:02d}{i:03d}",
                    "PkgName": f"package{i}",
                    "InstalledVersion": f"{i % 10}.{i % 5}.{i % 3}",
                    "FixedVersion": f"{(i % 10) + 1}.{i % 5}.{i % 3}",
                    "Severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
                    "CVSS": {
                        "nvd": {
                            "V2Score": round(1.0 + (i % 90) / 10.0, 1),
                            "V3Score": round(1.0 + (i % 90) / 10.0, 1)
                        }
                    },
                    "PublishedDate": f"2023-{(i % 12) + 1:02d}-01T00:00:00Z",
                    "LastModifiedDate": f"2023-{(i % 12) + 1:02d}-02T00:00:00Z"
                })
            
            data["Results"].append({
                "Target": f"target{r}",
                "Class": "os-pkgs",
                "Type": "alpine",
                "Vulnerabilities": vulnerabilities
            })
        
        file_path = Path(self.temp_dir) / f"test_{vuln_count}v_{result_count}r.json"
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return file_path
    
    def test_small_file_processing(self):
        """Test processing of small files (1-5 vulnerabilities)."""
        input_file = self._create_test_file(vuln_count=3)
        output_dir = Path(self.temp_dir) / "small_output"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        start_time = time.time()
        generated_files = generator.generate_files(10)
        duration = time.time() - start_time
        
        # Should be very fast for small files
        self.assertLess(duration, 2.0)
        self.assertEqual(len(generated_files), 10)
        
        # Validate a sample of files
        for file_path in generated_files[:3]:
            with open(file_path, 'r') as f:
                data = json.load(f)
            self.validator.validate_generated_file(data)
    
    def test_medium_file_processing(self):
        """Test processing of medium files (20-50 vulnerabilities)."""
        input_file = self._create_test_file(vuln_count=30)
        output_dir = Path(self.temp_dir) / "medium_output"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        start_time = time.time()
        generated_files = generator.generate_files(20)
        duration = time.time() - start_time
        
        # Should complete reasonably quickly
        self.assertLess(duration, 5.0)
        self.assertEqual(len(generated_files), 20)
        
        # Validate schema preservation
        for file_path in generated_files[::5]:  # Every 5th file
            with open(file_path, 'r') as f:
                data = json.load(f)
            self.validator.validate_generated_file(data)
    
    def test_large_file_processing(self):
        """Test processing of large files (100+ vulnerabilities)."""
        input_file = self._create_test_file(vuln_count=150)
        output_dir = Path(self.temp_dir) / "large_output"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        start_time = time.time()
        generated_files = generator.generate_files(10)
        duration = time.time() - start_time
        
        # Should still complete in reasonable time
        self.assertLess(duration, 10.0)
        self.assertEqual(len(generated_files), 10)
        
        # Validate schema preservation for large files
        sample_file = generated_files[0]
        with open(sample_file, 'r') as f:
            data = json.load(f)
        
        self.validator.validate_generated_file(data)
        
        # Verify structure is maintained for large files
        self.assertIn("Results", data)
        self.assertGreater(len(data["Results"]), 0)
        
        # Check that vulnerabilities were processed
        result = data["Results"][0]
        if "Vulnerabilities" in result:
            vulnerabilities = result["Vulnerabilities"]
            self.assertIsInstance(vulnerabilities, list)
            # Count may be randomized, but structure should be preserved
            for vuln in vulnerabilities[:5]:  # Check first 5
                self.assertIn("VulnerabilityID", vuln)
                self.assertIn("PkgName", vuln)
                self.assertIn("Severity", vuln)
    
    def test_multiple_results_processing(self):
        """Test processing files with multiple Results sections."""
        input_file = self._create_test_file(vuln_count=10, result_count=5)
        output_dir = Path(self.temp_dir) / "multi_results_output"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        generated_files = generator.generate_files(5)
        self.assertEqual(len(generated_files), 5)
        
        # Validate structure with multiple results
        for file_path in generated_files:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            self.validator.validate_generated_file(data)
            
            # Verify all Results sections are preserved
            self.assertEqual(len(data["Results"]), 5)
            
            for result in data["Results"]:
                self.assertIn("Target", result)
                self.assertIn("Class", result)
                self.assertIn("Type", result)
                if "Vulnerabilities" in result:
                    self.assertIsInstance(result["Vulnerabilities"], list)


if __name__ == '__main__':
    unittest.main()
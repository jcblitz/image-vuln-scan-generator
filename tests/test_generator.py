"""
Unit tests for the TrivyDataGenerator class.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.generator import TrivyDataGenerator


class TestTrivyDataGenerator(unittest.TestCase):
    """Test cases for TrivyDataGenerator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_trivy_data = {
            "SchemaVersion": 2,
            "ArtifactName": "test:latest",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:abc123"
            },
            "Results": [
                {
                    "Target": "test",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-12345",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "Severity": "HIGH"
                        }
                    ]
                }
            ]
        }
    
    def test_init(self):
        """Test generator initialization."""
        with tempfile.NamedTemporaryFile() as temp_file:
            generator = TrivyDataGenerator(temp_file.name, "output")
            self.assertEqual(generator.input_file, temp_file.name)
            self.assertEqual(generator.output_dir, Path("output"))
    
    @patch('src.generator.TrivyDataGenerator._load_template')
    @patch('src.generator.Path.mkdir')
    def test_generate_files(self, mock_mkdir, mock_load_template):
        """Test file generation."""
        mock_load_template.return_value = self.sample_trivy_data
        
        with tempfile.TemporaryDirectory() as temp_dir:
            with tempfile.NamedTemporaryFile() as temp_input:
                generator = TrivyDataGenerator(temp_input.name, temp_dir)
                
                with patch.object(generator, '_generate_single_file') as mock_generate:
                    mock_generate.side_effect = [f"{temp_dir}/file_{i}.json" for i in range(3)]
                    
                    result = generator.generate_files(3)
                    
                    self.assertEqual(len(result), 3)
                    self.assertEqual(mock_generate.call_count, 3)
    
    def test_load_template_caching(self):
        """Test template caching functionality."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.sample_trivy_data, f)
            temp_file = f.name
        
        try:
            generator = TrivyDataGenerator(temp_file, "output")
            
            # First load
            template1 = generator._load_template()
            
            # Second load should use cache
            template2 = generator._load_template()
            
            self.assertEqual(template1, template2)
            self.assertIn(temp_file, generator._template_cache)
        finally:
            Path(temp_file).unlink()


if __name__ == '__main__':
    unittest.main()
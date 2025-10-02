"""
Unit tests for GrypeDataGenerator core functionality.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from src.grype.generator import GrypeDataGenerator
from src.exceptions import ValidationError, GenerationError, FileOperationError


class TestGrypeDataGenerator(unittest.TestCase):
    """Test cases for GrypeDataGenerator class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        self.grype_sample_file = os.path.join(self.test_data_dir, 'grype-golang-1.12-alpine.json')
        
        # Create temporary output directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Initialize generator
        self.generator = GrypeDataGenerator(self.grype_sample_file, self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up temporary files
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_generator_initialization(self):
        """Test that GrypeDataGenerator initializes correctly."""
        self.assertIsNotNone(self.generator.randomizer)
        self.assertIsNotNone(self.generator.validator)
        self.assertEqual(self.generator.input_file, self.grype_sample_file)
        self.assertEqual(str(self.generator.output_dir), self.temp_dir)
    
    def test_generate_at_least_two_files_successfully(self):
        """Test that generator can create at least 2 files successfully."""
        # Generate 2 files
        generated_files = self.generator.generate_files(2)
        
        # Verify 2 files were generated
        self.assertEqual(len(generated_files), 2)
        
        # Verify files exist and are valid JSON
        for file_path in generated_files:
            self.assertTrue(os.path.exists(file_path))
            
            # Verify file contains valid JSON
            with open(file_path, 'r') as f:
                data = json.load(f)
                self.assertIsInstance(data, dict)
                self.assertIn('matches', data)
    
    def test_randomize_data_preserves_structure(self):
        """Test that _randomize_data preserves the basic Grype structure."""
        # Load sample data
        with open(self.grype_sample_file, 'r') as f:
            original_data = json.load(f)
        
        # Randomize data
        randomized_data = self.generator._randomize_data(original_data.copy())
        
        # Verify structure is preserved
        self.assertIn('matches', randomized_data)
        self.assertIsInstance(randomized_data['matches'], list)
        
        # Verify matches have expected structure
        if randomized_data['matches']:
            match = randomized_data['matches'][0]
            self.assertIsInstance(match, dict)
    
    def test_validate_input_with_valid_grype_file(self):
        """Test that _validate_input correctly validates a valid Grype file."""
        # Load sample data
        with open(self.grype_sample_file, 'r') as f:
            data = json.load(f)
        
        # Validate input
        is_valid = self.generator._validate_input(data)
        self.assertTrue(is_valid)
    
    def test_validate_input_with_invalid_data(self):
        """Test that _validate_input rejects invalid data."""
        # Test with empty dict
        is_valid = self.generator._validate_input({})
        self.assertFalse(is_valid)
        
        # Test with missing matches field
        invalid_data = {"some_field": "value"}
        is_valid = self.generator._validate_input(invalid_data)
        self.assertFalse(is_valid)
    
    def test_get_output_filename_format(self):
        """Test that _get_output_filename generates correct format."""
        filename = self.generator._get_output_filename(1)
        self.assertEqual(filename, "grype-generated-0001.json")
        
        filename = self.generator._get_output_filename(42)
        self.assertEqual(filename, "grype-generated-0042.json")
        
        filename = self.generator._get_output_filename(1000)
        self.assertEqual(filename, "grype-generated-1000.json")
    
    @patch('src.grype.generator.get_logger')
    def test_logging_integration(self, mock_logger):
        """Test that generator integrates with logging system."""
        # Create generator (should trigger logging)
        generator = GrypeDataGenerator(self.grype_sample_file, self.temp_dir)
        
        # Verify logger was called
        mock_logger.assert_called()
    
    def test_error_handling_invalid_input_file(self):
        """Test error handling for invalid input file."""
        # Test with non-existent file
        with self.assertRaises((FileOperationError, ValidationError)):
            invalid_generator = GrypeDataGenerator('/nonexistent/file.json', self.temp_dir)
    
    def test_error_handling_invalid_output_directory(self):
        """Test error handling for invalid output directory."""
        # Test with invalid output directory (file instead of directory)
        invalid_output = os.path.join(self.temp_dir, 'not_a_directory.txt')
        with open(invalid_output, 'w') as f:
            f.write('test')
        
        generator = GrypeDataGenerator(self.grype_sample_file, invalid_output)
        
        # Should handle the error gracefully
        with self.assertRaises((FileOperationError, GenerationError)):
            generator.generate_files(1)


if __name__ == '__main__':
    unittest.main()
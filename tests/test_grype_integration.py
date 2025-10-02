"""
Integration tests for complete Grype workflow.
"""

import json
import os
import tempfile
import unittest
import shutil

# Import directly to avoid circular import issues
from src.grype.generator import GrypeDataGenerator


class TestGrypeIntegration(unittest.TestCase):
    """Integration test cases for complete Grype workflow."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_data_dir = os.path.join(os.path.dirname(__file__), 'fixtures')
        self.grype_sample_file = os.path.join(self.test_data_dir, 'grype-golang-1.12-alpine.json')
        
        # Create temporary output directory
        self.temp_dir = tempfile.mkdtemp()
        
        # Verify sample file exists
        if not os.path.exists(self.grype_sample_file):
            self.skipTest(f"Sample file not found: {self.grype_sample_file}")
    
    def tearDown(self):
        """Clean up test fixtures."""
        # Clean up temporary files
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_end_to_end_generation_of_two_files(self):
        """Test end-to-end generation of 2 files with sample Grype file."""
        # Create generator
        generator = GrypeDataGenerator(self.grype_sample_file, self.temp_dir)
        
        # Generate 2 files
        generated_files = generator.generate_files(2)
        
        # Verify 2 files were generated
        self.assertEqual(len(generated_files), 2, "Should generate exactly 2 files")
        
        # Verify files exist
        for file_path in generated_files:
            self.assertTrue(os.path.exists(file_path), f"Generated file should exist: {file_path}")
            
            # Verify file is not empty
            self.assertGreater(os.path.getsize(file_path), 0, f"Generated file should not be empty: {file_path}")
    
    def test_generated_files_are_valid_json(self):
        """Test that generated files contain valid JSON."""
        # Create generator
        generator = GrypeDataGenerator(self.grype_sample_file, self.temp_dir)
        
        # Generate 2 files
        generated_files = generator.generate_files(2)
        
        # Verify each file contains valid JSON
        for file_path in generated_files:
            with open(file_path, 'r') as f:
                try:
                    data = json.load(f)
                    self.assertIsInstance(data, dict, f"Generated file should contain JSON object: {file_path}")
                except json.JSONDecodeError as e:
                    self.fail(f"Generated file contains invalid JSON: {file_path}, Error: {e}")
    
    def test_generated_files_maintain_basic_structure(self):
        """Test that generated files maintain basic Grype structure."""
        # Create generator
        generator = GrypeDataGenerator(self.grype_sample_file, self.temp_dir)
        
        # Generate 2 files
        generated_files = generator.generate_files(2)
        
        # Load original file for comparison
        with open(self.grype_sample_file, 'r') as f:
            original_data = json.load(f)
        
        # Verify each generated file maintains structure
        for file_path in generated_files:
            with open(file_path, 'r') as f:
                generated_data = json.load(f)
            
            # Check that required top-level fields are present
            self.assertIn('matches', generated_data, f"Generated file should have 'matches' field: {file_path}")
            self.assertIsInstance(generated_data['matches'], list, f"'matches' should be a list: {file_path}")
            
            # If original had matches, generated should too (though count may differ)
            if original_data.get('matches'):
                # Generated matches count should be between 1-50 (as per randomization logic)
                matches_count = len(generated_data['matches'])
                self.assertGreaterEqual(matches_count, 1, f"Should have at least 1 match: {file_path}")
                self.assertLessEqual(matches_count, 50, f"Should have at most 50 matches: {file_path}")
                
                # Check structure of first match if present
                if generated_data['matches']:
                    first_match = generated_data['matches'][0]
                    self.assertIsInstance(first_match, dict, f"Match should be a dictionary: {file_path}")
    
    def test_generated_files_are_different(self):
        """Test that generated files are different from each other."""
        # Create generator
        generator = GrypeDataGenerator(self.grype_sample_file, self.temp_dir)
        
        # Generate 2 files
        generated_files = generator.generate_files(2)
        
        # Load both files
        with open(generated_files[0], 'r') as f:
            data1 = json.load(f)
        
        with open(generated_files[1], 'r') as f:
            data2 = json.load(f)
        
        # Files should be different (randomization should ensure this)
        self.assertNotEqual(data1, data2, "Generated files should be different due to randomization")
    
    def test_generator_handles_empty_output_directory(self):
        """Test that generator can handle empty output directory."""
        # Create generator with empty directory
        generator = GrypeDataGenerator(self.grype_sample_file, self.temp_dir)
        
        # Generate files
        generated_files = generator.generate_files(1)
        
        # Should succeed
        self.assertEqual(len(generated_files), 1)
        self.assertTrue(os.path.exists(generated_files[0]))
    
    def test_generator_creates_output_directory_if_needed(self):
        """Test that generator creates output directory if it doesn't exist."""
        # Use a non-existent subdirectory
        non_existent_dir = os.path.join(self.temp_dir, 'subdir', 'nested')
        
        # Create generator
        generator = GrypeDataGenerator(self.grype_sample_file, non_existent_dir)
        
        # Generate files
        generated_files = generator.generate_files(1)
        
        # Should succeed and create directory
        self.assertEqual(len(generated_files), 1)
        self.assertTrue(os.path.exists(generated_files[0]))
        self.assertTrue(os.path.exists(non_existent_dir))


if __name__ == '__main__':
    unittest.main()
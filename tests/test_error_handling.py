"""
Unit tests for error handling and logging functionality.
"""

import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from src.exceptions import (
    TrivyGeneratorError, ValidationError, GenerationError, 
    FileOperationError, ConfigurationError
)
from src.generator import TrivyDataGenerator
from src.logging_config import setup_logging, get_logger, log_exception, log_performance
from src.main import validate_inputs, main
from src.validators import TrivyValidator


class TestCustomExceptions(unittest.TestCase):
    """Test cases for custom exception classes."""
    
    def test_trivy_generator_error_base(self):
        """Test base TrivyGeneratorError exception."""
        error = TrivyGeneratorError("Test message", "Test details")
        
        self.assertEqual(error.message, "Test message")
        self.assertEqual(error.details, "Test details")
        self.assertEqual(str(error), "Test message (Details: Test details)")
        
        # Test without details
        error_no_details = TrivyGeneratorError("Test message")
        self.assertEqual(str(error_no_details), "Test message")
    
    def test_validation_error(self):
        """Test ValidationError exception."""
        error = ValidationError("Invalid file", "/path/to/file", "Missing fields")
        
        self.assertEqual(error.message, "Invalid file")
        self.assertEqual(error.file_path, "/path/to/file")
        self.assertEqual(error.details, "Missing fields")
        self.assertIn("File: /path/to/file", str(error))
        self.assertIn("Details: Missing fields", str(error))
    
    def test_generation_error(self):
        """Test GenerationError exception."""
        error = GenerationError("Generation failed", "file creation", "Disk full")
        
        self.assertEqual(error.message, "Generation failed")
        self.assertEqual(error.operation, "file creation")
        self.assertEqual(error.details, "Disk full")
        self.assertIn("Operation: file creation", str(error))
        self.assertIn("Details: Disk full", str(error))
    
    def test_file_operation_error(self):
        """Test FileOperationError exception."""
        error = FileOperationError("File error", "/path/to/file", "read", "Permission denied")
        
        self.assertEqual(error.message, "File error")
        self.assertEqual(error.file_path, "/path/to/file")
        self.assertEqual(error.operation, "read")
        self.assertEqual(error.details, "Permission denied")
        self.assertIn("File: /path/to/file", str(error))
        self.assertIn("Operation: read", str(error))
        self.assertIn("Details: Permission denied", str(error))
    
    def test_configuration_error(self):
        """Test ConfigurationError exception."""
        error = ConfigurationError("Invalid config", "count", "Must be positive")
        
        self.assertEqual(error.message, "Invalid config")
        self.assertEqual(error.parameter, "count")
        self.assertEqual(error.details, "Must be positive")
        self.assertIn("Parameter: count", str(error))
        self.assertIn("Details: Must be positive", str(error))


class TestLoggingConfiguration(unittest.TestCase):
    """Test cases for logging configuration."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Clear any existing loggers
        logging.getLogger("trivy_generator").handlers.clear()
    
    def test_setup_logging_console_only(self):
        """Test logging setup with console output only."""
        logger = setup_logging(level="INFO", enable_console=True)
        
        self.assertEqual(logger.level, logging.INFO)
        self.assertEqual(len(logger.handlers), 1)
        self.assertIsInstance(logger.handlers[0], logging.StreamHandler)
    
    def test_setup_logging_with_file(self):
        """Test logging setup with file output."""
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_path = temp_file.name
        
        try:
            logger = setup_logging(level="DEBUG", log_file=temp_path, enable_console=True)
            
            self.assertEqual(logger.level, logging.DEBUG)
            self.assertEqual(len(logger.handlers), 2)  # Console + file
            
            # Test logging to file
            logger.info("Test message")
            
            with open(temp_path, 'r') as f:
                log_content = f.read()
                self.assertIn("Test message", log_content)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_get_logger(self):
        """Test get_logger function."""
        logger = get_logger("test_logger")
        self.assertEqual(logger.name, "test_logger")
    
    def test_log_exception(self):
        """Test log_exception function."""
        logger = Mock()
        exception = ValueError("Test error")
        
        log_exception(logger, exception, "test context")
        
        logger.error.assert_called_once()
        logger.debug.assert_called_once()
        
        # Check error message contains exception info
        error_call = logger.error.call_args[0][0]
        self.assertIn("ValueError", error_call)
        self.assertIn("Test error", error_call)
        self.assertIn("test context", error_call)
    
    def test_log_performance(self):
        """Test log_performance function."""
        logger = Mock()
        
        # Test with count
        log_performance(logger, "file generation", 5.5, 100)
        logger.info.assert_called_once()
        
        info_call = logger.info.call_args[0][0]
        self.assertIn("file generation", info_call)
        self.assertIn("5.50s", info_call)
        self.assertIn("100 items", info_call)
        self.assertIn("items/sec", info_call)
        
        # Test without count
        logger.reset_mock()
        log_performance(logger, "operation", 2.0)
        logger.info.assert_called_once()
        
        info_call = logger.info.call_args[0][0]
        self.assertIn("operation", info_call)
        self.assertIn("2.00s", info_call)
        self.assertNotIn("items", info_call)


class TestValidatorErrorHandling(unittest.TestCase):
    """Test cases for validator error handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator = TrivyValidator()
    
    def test_validate_input_file_not_found(self):
        """Test validation with non-existent file."""
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_input_file("/nonexistent/file.json")
        
        error = context.exception
        self.assertIn("does not exist", error.message)
        self.assertEqual(error.file_path, "/nonexistent/file.json")
    
    def test_validate_input_file_not_file(self):
        """Test validation with directory instead of file."""
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValidationError) as context:
                self.validator.validate_input_file(temp_dir)
            
            error = context.exception
            self.assertIn("not a file", error.message)
            self.assertEqual(error.file_path, temp_dir)
    
    def test_validate_input_file_invalid_json(self):
        """Test validation with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json content {")
            temp_path = f.name
        
        try:
            with self.assertRaises(ValidationError) as context:
                self.validator.validate_input_file(temp_path)
            
            error = context.exception
            self.assertIn("invalid JSON", error.message)
            self.assertEqual(error.file_path, temp_path)
        finally:
            Path(temp_path).unlink()
    
    def test_validate_input_file_invalid_structure(self):
        """Test validation with valid JSON but invalid Trivy structure."""
        invalid_data = {"invalid": "structure"}
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(invalid_data, f)
            temp_path = f.name
        
        try:
            with self.assertRaises(ValidationError) as context:
                self.validator.validate_input_file(temp_path)
            
            error = context.exception
            self.assertIn("valid Trivy JSON structure", error.message)
            self.assertEqual(error.file_path, temp_path)
        finally:
            Path(temp_path).unlink()
    
    def test_validate_generated_file_invalid_structure(self):
        """Test validation of generated data with invalid structure."""
        invalid_data = {"invalid": "structure"}
        
        with self.assertRaises(ValidationError) as context:
            self.validator.validate_generated_file(invalid_data)
        
        error = context.exception
        self.assertIn("valid Trivy JSON structure", error.message)
    
    def test_validate_generated_file_type_error(self):
        """Test validation with type error in generated data."""
        # Mock _check_trivy_structure to raise TypeError
        with patch.object(self.validator, '_check_trivy_structure', side_effect=TypeError("Type error")):
            with self.assertRaises(ValidationError) as context:
                self.validator.validate_generated_file({})
            
            error = context.exception
            self.assertIn("invalid structure", error.message)


class TestGeneratorErrorHandling(unittest.TestCase):
    """Test cases for generator error handling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.sample_data = {
            "SchemaVersion": 2,
            "ArtifactName": "test:latest",
            "ArtifactType": "container_image",
            "Results": []
        }
    
    def test_generator_init_nonexistent_file(self):
        """Test generator initialization with non-existent input file."""
        with self.assertRaises(FileOperationError) as context:
            TrivyDataGenerator("/nonexistent/file.json", "output")
        
        error = context.exception
        self.assertIn("does not exist", error.message)
        self.assertEqual(error.file_path, "/nonexistent/file.json")
        self.assertEqual(error.operation, "initialization")
    
    def test_generate_files_invalid_count(self):
        """Test file generation with invalid count."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.sample_data, f)
            temp_path = f.name
        
        try:
            generator = TrivyDataGenerator(temp_path, "output")
            
            with self.assertRaises(GenerationError) as context:
                generator.generate_files(0)
            
            error = context.exception
            self.assertIn("must be positive", error.message)
            self.assertEqual(error.operation, "file generation")
        finally:
            Path(temp_path).unlink()
    
    def test_generate_files_output_directory_creation_failure(self):
        """Test file generation when output directory creation fails."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.sample_data, f)
            temp_path = f.name
        
        try:
            generator = TrivyDataGenerator(temp_path, "/invalid/path/that/cannot/be/created")
            
            # Mock mkdir to raise OSError
            with patch.object(Path, 'mkdir', side_effect=OSError("Permission denied")):
                with self.assertRaises(FileOperationError) as context:
                    generator.generate_files(1)
                
                error = context.exception
                self.assertIn("create output directory", error.message)
                self.assertEqual(error.operation, "directory creation")
        finally:
            Path(temp_path).unlink()
    
    def test_load_template_json_decode_error(self):
        """Test template loading with JSON decode error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("invalid json {")
            temp_path = f.name
        
        try:
            generator = TrivyDataGenerator.__new__(TrivyDataGenerator)
            generator.input_file = temp_path
            generator._template_cache = {}
            generator.logger = get_logger("test")
            
            with self.assertRaises(ValidationError) as context:
                generator._load_template()
            
            error = context.exception
            self.assertIn("Invalid JSON", error.message)
            self.assertEqual(error.file_path, temp_path)
        finally:
            Path(temp_path).unlink()
    
    def test_load_template_io_error(self):
        """Test template loading with IO error."""
        generator = TrivyDataGenerator.__new__(TrivyDataGenerator)
        generator.input_file = "/nonexistent/file.json"
        generator._template_cache = {}
        generator.logger = get_logger("test")
        
        with self.assertRaises(FileOperationError) as context:
            generator._load_template()
        
        error = context.exception
        self.assertIn("not found", error.message)
        self.assertEqual(error.file_path, "/nonexistent/file.json")
        self.assertEqual(error.operation, "template loading")
    
    def test_generate_single_file_validation_error(self):
        """Test single file generation with validation error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.sample_data, f)
            temp_path = f.name
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                generator = TrivyDataGenerator(temp_path, temp_dir)
                
                # Mock validator to raise ValidationError
                with patch.object(generator.validator, 'validate_generated_file', 
                                side_effect=ValidationError("Validation failed")):
                    with self.assertRaises(GenerationError) as context:
                        generator._generate_single_file(self.sample_data, 0)
                    
                    error = context.exception
                    self.assertIn("failed schema validation", error.message)
                    self.assertEqual(error.operation, "schema validation")
        finally:
            Path(temp_path).unlink()
    
    def test_generate_single_file_write_error(self):
        """Test single file generation with file write error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.sample_data, f)
            temp_path = f.name
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                generator = TrivyDataGenerator(temp_path, temp_dir)
                
                # Mock open to raise IOError
                with patch('builtins.open', side_effect=IOError("Disk full")):
                    with self.assertRaises(FileOperationError) as context:
                        generator._generate_single_file(self.sample_data, 0)
                    
                    error = context.exception
                    self.assertIn("write generated file", error.message)
                    self.assertEqual(error.operation, "file writing")
        finally:
            Path(temp_path).unlink()


class TestMainErrorHandling(unittest.TestCase):
    """Test cases for main CLI error handling."""
    
    def test_validate_inputs_nonexistent_file(self):
        """Test input validation with non-existent file."""
        args = Mock()
        args.input_file = "/nonexistent/file.json"
        args.count = 10
        
        logger = get_logger("test")
        
        with self.assertRaises(ConfigurationError) as context:
            validate_inputs(args, logger)
        
        error = context.exception
        self.assertIn("does not exist", error.message)
        self.assertEqual(error.parameter, "input_file")
    
    def test_validate_inputs_invalid_count(self):
        """Test input validation with invalid count."""
        with tempfile.NamedTemporaryFile() as temp_file:
            args = Mock()
            args.input_file = temp_file.name
            args.count = -5
            
            logger = get_logger("test")
            
            with self.assertRaises(ConfigurationError) as context:
                validate_inputs(args, logger)
            
            error = context.exception
            self.assertIn("positive integer", error.message)
            self.assertEqual(error.parameter, "count")
    
    def test_validate_inputs_large_count_warning(self):
        """Test input validation with large count generates warning."""
        with tempfile.NamedTemporaryFile() as temp_file:
            args = Mock()
            args.input_file = temp_file.name
            args.count = 15000
            
            logger = Mock()
            
            # Should not raise exception but should log warning
            validate_inputs(args, logger)
            logger.warning.assert_called_once()
            warning_call = logger.warning.call_args[0][0]
            self.assertIn("Large file count", warning_call)
    
    @patch('src.main.parse_arguments')
    @patch('src.main.setup_logging')
    def test_main_configuration_error(self, mock_setup_logging, mock_parse_args):
        """Test main function with configuration error."""
        mock_logger = Mock()
        mock_setup_logging.return_value = mock_logger
        
        args = Mock()
        args.input_file = "/nonexistent/file.json"
        args.count = 10
        args.output_dir = "output"
        args.verbose = False
        args.debug = False
        args.log_file = None
        mock_parse_args.return_value = args
        
        result = main()
        
        self.assertEqual(result, 1)
        mock_logger.error.assert_called()
        error_call = mock_logger.error.call_args[0][0]
        self.assertIn("Configuration error", error_call)
    
    @patch('src.main.parse_arguments')
    @patch('src.main.setup_logging')
    @patch('src.main.validate_inputs')
    @patch('src.main.TrivyValidator')
    def test_main_validation_error(self, mock_validator_class, mock_validate_inputs, 
                                 mock_setup_logging, mock_parse_args):
        """Test main function with validation error."""
        mock_logger = Mock()
        mock_setup_logging.return_value = mock_logger
        
        args = Mock()
        args.verbose = False
        args.debug = False
        args.log_file = None
        mock_parse_args.return_value = args
        
        mock_validator = Mock()
        mock_validator.validate_input_file.side_effect = ValidationError("Invalid file")
        mock_validator_class.return_value = mock_validator
        
        result = main()
        
        self.assertEqual(result, 1)
        mock_logger.error.assert_called()
        error_call = mock_logger.error.call_args[0][0]
        self.assertIn("Validation error", error_call)
    
    @patch('src.main.parse_arguments')
    @patch('src.main.setup_logging')
    @patch('src.main.validate_inputs')
    @patch('src.main.TrivyValidator')
    @patch('src.main.TrivyDataGenerator')
    def test_main_generation_error(self, mock_generator_class, mock_validator_class, 
                                 mock_validate_inputs, mock_setup_logging, mock_parse_args):
        """Test main function with generation error."""
        mock_logger = Mock()
        mock_setup_logging.return_value = mock_logger
        
        args = Mock()
        args.count = 10
        args.verbose = False
        args.debug = False
        args.log_file = None
        mock_parse_args.return_value = args
        
        mock_validator = Mock()
        mock_validator_class.return_value = mock_validator
        
        mock_generator = Mock()
        mock_generator.generate_files.side_effect = GenerationError("Generation failed")
        mock_generator_class.return_value = mock_generator
        
        result = main()
        
        self.assertEqual(result, 1)
        mock_logger.error.assert_called()
        error_call = mock_logger.error.call_args[0][0]
        self.assertIn("Generation error", error_call)
    
    @patch('src.main.parse_arguments')
    @patch('src.main.setup_logging')
    def test_main_keyboard_interrupt(self, mock_setup_logging, mock_parse_args):
        """Test main function with keyboard interrupt."""
        mock_logger = Mock()
        mock_setup_logging.return_value = mock_logger
        
        mock_parse_args.side_effect = KeyboardInterrupt()
        
        result = main()
        
        self.assertEqual(result, 1)
        # Logger won't be called since KeyboardInterrupt happens before logging setup
        mock_setup_logging.assert_not_called()
    
    @patch('src.main.parse_arguments')
    @patch('src.main.setup_logging')
    def test_main_unexpected_error(self, mock_setup_logging, mock_parse_args):
        """Test main function with unexpected error."""
        mock_logger = Mock()
        mock_setup_logging.return_value = mock_logger
        
        mock_parse_args.side_effect = RuntimeError("Unexpected error")
        
        result = main()
        
        self.assertEqual(result, 1)
        # Logger won't be called since RuntimeError happens before logging setup
        mock_setup_logging.assert_not_called()
    
    @patch('src.main.parse_arguments')
    @patch('src.main.setup_logging')
    @patch('src.main.validate_inputs')
    def test_main_unexpected_error_after_logging(self, mock_validate_inputs, mock_setup_logging, mock_parse_args):
        """Test main function with unexpected error after logging is set up."""
        mock_logger = Mock()
        mock_setup_logging.return_value = mock_logger
        
        args = Mock()
        args.verbose = False
        args.debug = False
        args.log_file = None
        mock_parse_args.return_value = args
        
        # Make validate_inputs raise an unexpected error
        mock_validate_inputs.side_effect = RuntimeError("Unexpected error")
        
        result = main()
        
        self.assertEqual(result, 1)
        # Should call log_exception for unexpected errors
        mock_logger.error.assert_called()
        mock_logger.debug.assert_called()


class TestErrorPropagation(unittest.TestCase):
    """Test cases for proper error propagation through the system."""
    
    def test_error_propagation_chain(self):
        """Test that errors propagate correctly through the call chain."""
        # Create a scenario where validator raises ValidationError
        # and it gets wrapped in GenerationError by generator
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"invalid": "structure"}, f)
            temp_path = f.name
        
        try:
            # This should raise ValidationError from validator
            # which should be caught and wrapped in GenerationError by generator
            generator = TrivyDataGenerator(temp_path, "output")
            
            with self.assertRaises(GenerationError) as context:
                generator.generate_files(1)
            
            # The GenerationError should contain details about the original ValidationError
            error = context.exception
            self.assertIn("single file generation", error.operation)
            self.assertIn("schema validation", str(error.details))
                
        finally:
            Path(temp_path).unlink()
    
    def test_exception_context_preservation(self):
        """Test that exception context is preserved through error handling."""
        original_error = ValueError("Original error")
        
        try:
            raise GenerationError(
                "Generation failed",
                operation="test operation",
                details=str(original_error)
            )
        except GenerationError as e:
            self.assertIn("Original error", e.details)
            self.assertEqual(e.operation, "test operation")


if __name__ == '__main__':
    unittest.main()
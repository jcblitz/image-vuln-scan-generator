"""
Abstract base generator class with template method pattern for vulnerability test data generation.
"""

import json
import os
import time
from abc import ABC, abstractmethod
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

from ..exceptions import GenerationError, FileOperationError, ValidationError
from ..logging_config import get_logger, log_performance, log_exception


class BaseGenerator(ABC):
    """Abstract base class defining common generation workflow using template method pattern."""
    
    def __init__(self, input_file: str, output_dir: str):
        """
        Initialize generator with input file and output directory.
        
        Args:
            input_file: Path to the input JSON file
            output_dir: Directory where generated files will be saved
            
        Raises:
            FileOperationError: If input file or output directory issues are detected
        """
        self.input_file = input_file
        self.output_dir = Path(output_dir)
        self._template_cache: Dict[str, Any] = {}
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
        self.logger.info(f"Initializing generator with input: {input_file}, output: {output_dir}")
        
        # Validate input file exists
        if not Path(input_file).exists():
            raise FileOperationError(
                "Input file does not exist",
                file_path=input_file,
                operation="initialization"
            )
    
    def generate_files(self, count: int) -> List[str]:
        """
        Template method for file generation workflow.
        
        Args:
            count: Number of files to generate
            
        Returns:
            List of generated file paths
            
        Raises:
            GenerationError: If file generation fails
            FileOperationError: If file operations fail
        """
        if count <= 0:
            raise GenerationError(
                "File count must be positive",
                operation="file generation",
                details=f"Requested count: {count}"
            )
        
        start_time = time.time()
        self.logger.info(f"Starting generation of {count} files")
        
        try:
            # Ensure output directory exists
            self.output_dir.mkdir(parents=True, exist_ok=True)
            self.logger.debug(f"Created output directory: {self.output_dir}")
        except OSError as e:
            self.logger.error(f"Failed to create output directory: {e}")
            raise FileOperationError(
                "Failed to create output directory",
                file_path=str(self.output_dir),
                operation="directory creation",
                details=str(e)
            )
        
        try:
            # Load template once for performance
            template = self._load_template()
            
            generated_files = []
            
            for i in range(count):
                try:
                    file_path = self._generate_single_file(template, i)
                    generated_files.append(file_path)
                    
                    if (i + 1) % 100 == 0:  # Log progress every 100 files
                        self.logger.info(f"Generated {i + 1}/{count} files")
                        
                except Exception as e:
                    log_exception(self.logger, e, f"generating file {i}")
                    raise GenerationError(
                        f"Failed to generate file {i}",
                        operation="single file generation",
                        details=str(e)
                    )
            
            duration = time.time() - start_time
            log_performance(self.logger, "file generation", duration, count)
            self.logger.info(f"Successfully generated {len(generated_files)} files")
            
            return generated_files
            
        except Exception as e:
            duration = time.time() - start_time
            self.logger.error(f"File generation failed after {duration:.2f}s")
            if not isinstance(e, (GenerationError, FileOperationError, ValidationError)):
                log_exception(self.logger, e, "file generation")
                raise GenerationError(
                    "Unexpected error during file generation",
                    operation="batch file generation",
                    details=str(e)
                )
            raise
    
    def _load_template(self) -> Dict[str, Any]:
        """
        Load and parse input JSON template.
        
        Returns:
            Parsed JSON template as dictionary
            
        Raises:
            FileOperationError: If file operations fail
            ValidationError: If JSON is invalid
        """
        if self.input_file in self._template_cache:
            self.logger.debug(f"Using cached template for {self.input_file}")
            return self._template_cache[self.input_file]
        
        self.logger.debug(f"Loading template from {self.input_file}")
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                template = json.load(f)
            
            # Validate input using format-specific validation
            if not self._validate_input(template):
                raise ValidationError(
                    "Input file failed format-specific validation",
                    file_path=self.input_file,
                    details="Schema validation failed"
                )
            
            self._template_cache[self.input_file] = template
            self.logger.info(f"Successfully loaded template from {self.input_file}")
            return template
            
        except FileNotFoundError as e:
            self.logger.error(f"Input file not found: {self.input_file}")
            raise FileOperationError(
                "Input file not found",
                file_path=self.input_file,
                operation="template loading",
                details=str(e)
            )
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in input file {self.input_file}: {e}")
            raise ValidationError(
                "Invalid JSON in input file",
                file_path=self.input_file,
                details=f"JSON parsing failed: {e}"
            )
        except IOError as e:
            self.logger.error(f"IO error reading input file {self.input_file}: {e}")
            raise FileOperationError(
                "Failed to read input file",
                file_path=self.input_file,
                operation="template loading",
                details=str(e)
            )
    
    def _generate_single_file(self, template: Dict[str, Any], index: int) -> str:
        """
        Generate a single randomized file from template.
        
        Args:
            template: Original JSON template
            index: File index for unique naming
            
        Returns:
            Path to the generated file
            
        Raises:
            GenerationError: If generation fails
            ValidationError: If validation fails
            FileOperationError: If file writing fails
        """
        self.logger.debug(f"Generating file {index}")
        
        try:
            # Create deep copy of template
            randomized_data = deepcopy(template)
            
            # Apply format-specific randomization
            randomized_data = self._randomize_data(randomized_data)
            
            # Validate generated data maintains schema
            try:
                if not self._validate_output(randomized_data):
                    raise ValidationError(
                        f"Generated file {index} failed schema validation",
                        details="Output validation failed"
                    )
            except ValidationError as e:
                self.logger.error(f"Generated file {index} failed schema validation: {e}")
                raise GenerationError(
                    f"Generated file {index} failed schema validation",
                    operation="schema validation",
                    details=str(e)
                )
            
            # Generate unique filename
            output_filename = self._get_output_filename(index)
            output_path = self.output_dir / output_filename
            
            # Write to file
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(randomized_data, f, indent=2, ensure_ascii=False)
                
                self.logger.debug(f"Successfully wrote file: {output_path}")
                return str(output_path)
                
            except IOError as e:
                self.logger.error(f"Failed to write file {output_path}: {e}")
                raise FileOperationError(
                    f"Failed to write generated file",
                    file_path=str(output_path),
                    operation="file writing",
                    details=str(e)
                )
            except json.JSONEncodeError as e:
                self.logger.error(f"Failed to serialize JSON for file {output_path}: {e}")
                raise GenerationError(
                    f"Failed to serialize generated data to JSON",
                    operation="JSON serialization",
                    details=str(e)
                )
                
        except Exception as e:
            if not isinstance(e, (GenerationError, ValidationError, FileOperationError)):
                log_exception(self.logger, e, f"generating single file {index}")
                raise GenerationError(
                    f"Unexpected error generating file {index}",
                    operation="single file generation",
                    details=str(e)
                )
            raise
    
    @abstractmethod
    def _randomize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Format-specific data randomization - implemented by subclasses.
        
        Args:
            data: Original data dictionary
            
        Returns:
            Randomized data dictionary
        """
        pass
    
    @abstractmethod
    def _validate_input(self, data: Dict[str, Any]) -> bool:
        """
        Format-specific input validation - implemented by subclasses.
        
        Args:
            data: Input data to validate
            
        Returns:
            True if valid, False otherwise
        """
        pass
    
    def _validate_output(self, data: Dict[str, Any]) -> bool:
        """
        Format-specific output validation - can be overridden by subclasses.
        Default implementation delegates to input validation.
        
        Args:
            data: Output data to validate
            
        Returns:
            True if valid, False otherwise
        """
        return self._validate_input(data)
    
    @abstractmethod
    def _get_output_filename(self, index: int) -> str:
        """
        Format-specific output filename generation - implemented by subclasses.
        
        Args:
            index: File index for unique naming
            
        Returns:
            Generated filename
        """
        pass
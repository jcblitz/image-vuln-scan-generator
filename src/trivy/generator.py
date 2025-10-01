"""
Trivy-specific implementation of the base generator.
"""

from pathlib import Path
from typing import Any, Dict

from ..base import BaseGenerator
from ..exceptions import GenerationError, ValidationError
from ..logging_config import get_logger
from ..performance import PerformanceMonitor, BatchFileWriter, MemoryEfficientProcessor
from .randomizers import TrivyRandomizer
from .validators import TrivyValidator


class TrivyDataGenerator(BaseGenerator):
    """Trivy-specific implementation of base generator."""
    
    def __init__(self, input_file: str, output_dir: str, enable_performance_optimizations: bool = True):
        """
        Initialize Trivy generator with input file and output directory.
        
        Args:
            input_file: Path to the input Trivy JSON file
            output_dir: Directory where generated files will be saved
            enable_performance_optimizations: Whether to enable performance optimizations
            
        Raises:
            FileOperationError: If input file or output directory issues are detected
        """
        super().__init__(input_file, output_dir)
        
        self.randomizer = TrivyRandomizer()
        self.validator = TrivyValidator()
        
        # Performance optimization components
        self.enable_optimizations = enable_performance_optimizations
        self.performance_monitor = PerformanceMonitor() if enable_performance_optimizations else None
        self.memory_processor = MemoryEfficientProcessor() if enable_performance_optimizations else None
        
        self.logger.info(f"Performance optimizations: {'enabled' if enable_performance_optimizations else 'disabled'}")
    
    def _randomize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Implement Trivy-specific data randomization.
        
        Args:
            data: Original data dictionary
            
        Returns:
            Randomized data dictionary
        """
        self.logger.debug("Applying Trivy-specific randomization")
        
        try:
            # Apply root field randomization
            data = self.randomizer.randomize_root_fields(data)
            
            # Randomize vulnerabilities in Results array
            if "Results" in data:
                for result_index, result in enumerate(data["Results"]):
                    if "Vulnerabilities" in result and result["Vulnerabilities"]:
                        self.logger.debug(f"Randomizing vulnerabilities in result {result_index}")
                        
                        # First randomize the count of vulnerabilities
                        original_count = len(result["Vulnerabilities"])
                        result["Vulnerabilities"] = self.randomizer.randomize_vulnerability_count(
                            result["Vulnerabilities"]
                        )
                        new_count = len(result["Vulnerabilities"])
                        
                        self.logger.debug(f"Vulnerability count changed from {original_count} to {new_count}")
                        
                        # Then randomize the content of the remaining vulnerabilities
                        if result["Vulnerabilities"]:  # Only if we still have vulnerabilities after count randomization
                            # Use chunked processing for large vulnerability lists if optimizations enabled
                            if (self.enable_optimizations and self.memory_processor and 
                                len(result["Vulnerabilities"]) > 100):
                                result["Vulnerabilities"] = self.memory_processor.process_vulnerabilities_chunked(
                                    result["Vulnerabilities"],
                                    lambda vuln: self.randomizer._randomize_single_vulnerability(vuln)
                                )
                            else:
                                result["Vulnerabilities"] = self.randomizer.randomize_vulnerabilities(
                                    result["Vulnerabilities"]
                                )
            
            return data
            
        except Exception as e:
            self.logger.error(f"Error during Trivy randomization: {e}")
            raise GenerationError(
                "Failed to randomize Trivy data",
                operation="trivy randomization",
                details=str(e)
            )
    
    def _validate_input(self, data: Dict[str, Any]) -> bool:
        """
        Implement Trivy-specific input validation.
        
        Args:
            data: Input data to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            return self.validator._validate_schema(data)
        except Exception as e:
            self.logger.error(f"Error during Trivy input validation: {e}")
            return False
    
    def _get_output_filename(self, index: int) -> str:
        """
        Generate Trivy-specific output filename.
        
        Args:
            index: File index for unique naming
            
        Returns:
            Generated filename
        """
        input_name = Path(self.input_file).stem
        return f"{input_name}_randomized_{index:04d}.json"
    
    # Enhanced methods for backward compatibility with performance optimizations
    def generate_files_optimized(self, count: int) -> list[str]:
        """
        Generate files with performance optimizations enabled.
        This method provides backward compatibility with the original optimized implementation.
        
        Args:
            count: Number of files to generate
            
        Returns:
            List of generated file paths
        """
        if not self.enable_optimizations or not self.performance_monitor:
            # Fall back to standard generation
            return self.generate_files(count)
        
        with self.performance_monitor.monitor_operation(f"generate_{count}_files") as metrics:
            return self._generate_files_with_batch_writer(count, metrics)
    
    def _generate_files_with_batch_writer(self, count: int, metrics) -> list[str]:
        """Generate files using batch writer for improved I/O performance."""
        self.logger.info(f"Starting optimized generation of {count} files with batch writer")
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load template once for performance
        template = self._load_template()
        
        # Determine batch size based on file count
        batch_size = min(50, max(10, count // 20))  # Adaptive batch size
        self.logger.debug(f"Using batch size: {batch_size}")
        
        generated_files = []
        
        # Use batch file writer for improved I/O performance
        with BatchFileWriter(self.output_dir, batch_size) as batch_writer:
            for i in range(count):
                try:
                    filename, data = self._generate_single_file_data(template, i)
                    batch_writer.add_file(filename, data)
                    generated_files.append(str(self.output_dir / filename))
                    
                    if (i + 1) % 100 == 0:  # Log progress every 100 files
                        self.logger.info(f"Generated {i + 1}/{count} files")
                        
                except Exception as e:
                    self.logger.error(f"Error generating file {i}: {e}")
                    raise GenerationError(
                        f"Failed to generate file {i}",
                        operation="single file generation",
                        details=str(e)
                    )
            
            # Get final stats from batch writer
            files_written, bytes_written = batch_writer.get_stats()
            metrics.items_processed = count
            metrics.files_written = files_written
            metrics.bytes_written = bytes_written
        
        self.logger.info(f"Successfully generated {len(generated_files)} files")
        return generated_files
    
    def _generate_single_file_data(self, template: Dict[str, Any], index: int) -> tuple[str, Dict[str, Any]]:
        """
        Generate randomized data for a single file (optimized version for backward compatibility).
        
        Args:
            template: Original JSON template
            index: File index for unique naming
            
        Returns:
            Tuple of (filename, randomized_data)
        """
        self.logger.debug(f"Generating file data {index}")
        
        # Use memory-efficient deep copy for large datasets if optimizations enabled
        if self.enable_optimizations and self.memory_processor:
            from copy import deepcopy
            randomized_data = self.memory_processor.create_deep_copy_chunked(template)
        else:
            from copy import deepcopy
            randomized_data = deepcopy(template)
        
        # Apply randomization
        randomized_data = self._randomize_data(randomized_data)
        
        # Validate generated data maintains schema
        if not self._validate_input(randomized_data):
            raise ValidationError(
                f"Generated file {index} failed schema validation",
                details="Schema validation failed"
            )
        
        # Generate unique filename
        filename = self._get_output_filename(index)
        
        return filename, randomized_data
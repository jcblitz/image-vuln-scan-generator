"""
Grype-specific implementation of base generator for vulnerability test data generation.
"""

from typing import Any, Dict

from ..base.generator import BaseGenerator
from .randomizers import GrypeRandomizer
from .validators import GrypeValidator
from ..logging_config import get_logger


class GrypeDataGenerator(BaseGenerator):
    """Grype-specific implementation of base generator."""
    
    def __init__(self, input_file: str, output_dir: str):
        """
        Initialize Grype generator with randomizer and validator.
        
        Args:
            input_file: Path to the input Grype JSON file
            output_dir: Directory where generated files will be saved
        """
        super().__init__(input_file, output_dir)
        self.randomizer = GrypeRandomizer()
        self.validator = GrypeValidator()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
        self.logger.info("GrypeDataGenerator initialized")
    
    def _randomize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Implement Grype-specific randomization.
        
        Args:
            data: Original Grype JSON data
            
        Returns:
            Randomized Grype JSON data
        """
        self.logger.debug("Starting Grype-specific data randomization")
        
        # Randomize matches array if present
        if "matches" in data and isinstance(data["matches"], list):
            self.logger.debug(f"Randomizing {len(data['matches'])} matches")
            data["matches"] = self.randomizer.randomize_matches(data["matches"])
            self.logger.debug(f"Randomized to {len(data['matches'])} matches")
        
        self.logger.debug("Grype data randomization completed")
        return data
    
    def _validate_input(self, data: Dict[str, Any]) -> bool:
        """
        Implement Grype-specific input validation.
        
        Args:
            data: Input data to validate
            
        Returns:
            True if valid Grype format
        """
        self.logger.debug("Validating Grype input data")
        return self.validator._validate_schema(data)
    
    def _get_output_filename(self, index: int) -> str:
        """
        Generate Grype-specific output filename.
        
        Args:
            index: File index for unique naming
            
        Returns:
            Generated filename with grype prefix
        """
        return f"grype-generated-{index:04d}.json"
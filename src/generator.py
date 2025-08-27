"""
Core generation logic for the Trivy Test Data Generator.
"""

import json
import os
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List

from .randomizers import VulnerabilityRandomizer
from .validators import TrivyValidator


class TrivyDataGenerator:
    """Main generator class for creating randomized Trivy JSON files."""
    
    def __init__(self, input_file: str, output_dir: str):
        """
        Initialize generator with input file and output directory.
        
        Args:
            input_file: Path to the input Trivy JSON file
            output_dir: Directory where generated files will be saved
        """
        self.input_file = input_file
        self.output_dir = Path(output_dir)
        self.randomizer = VulnerabilityRandomizer()
        self.validator = TrivyValidator()
        self._template_cache: Dict[str, Any] = {}
    
    def generate_files(self, count: int) -> List[str]:
        """
        Generate specified number of randomized files.
        
        Args:
            count: Number of files to generate
            
        Returns:
            List of generated file paths
        """
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Load template once for performance
        template = self._load_template()
        
        generated_files = []
        
        for i in range(count):
            file_path = self._generate_single_file(template, i)
            generated_files.append(file_path)
        
        return generated_files
    
    def _load_template(self) -> Dict[str, Any]:
        """
        Load and parse input JSON template.
        
        Returns:
            Parsed JSON template as dictionary
            
        Raises:
            FileNotFoundError: If input file doesn't exist
            json.JSONDecodeError: If input file is not valid JSON
        """
        if self.input_file in self._template_cache:
            return self._template_cache[self.input_file]
        
        try:
            with open(self.input_file, 'r', encoding='utf-8') as f:
                template = json.load(f)
            
            self._template_cache[self.input_file] = template
            return template
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Input file '{self.input_file}' not found")
        except json.JSONDecodeError as e:
            raise json.JSONDecodeError(f"Invalid JSON in input file: {e}")
    
    def _generate_single_file(self, template: Dict[str, Any], index: int) -> str:
        """
        Generate a single randomized file from template.
        
        Args:
            template: Original JSON template
            index: File index for unique naming
            
        Returns:
            Path to the generated file
        """
        # Create deep copy to avoid modifying original template
        randomized_data = deepcopy(template)
        
        # Apply randomization
        randomized_data = self.randomizer.randomize_root_fields(randomized_data)
        
        # Randomize vulnerabilities in Results array
        if "Results" in randomized_data:
            for result in randomized_data["Results"]:
                if "Vulnerabilities" in result and result["Vulnerabilities"]:
                    # First randomize the count of vulnerabilities
                    result["Vulnerabilities"] = self.randomizer.randomize_vulnerability_count(
                        result["Vulnerabilities"]
                    )
                    # Then randomize the content of the remaining vulnerabilities
                    if result["Vulnerabilities"]:  # Only if we still have vulnerabilities after count randomization
                        result["Vulnerabilities"] = self.randomizer.randomize_vulnerabilities(
                            result["Vulnerabilities"]
                        )
        
        # Validate generated data maintains schema
        if not self.validator.validate_generated_file(randomized_data):
            raise ValueError(f"Generated file {index} failed schema validation")
        
        # Generate unique filename
        input_name = Path(self.input_file).stem
        output_filename = f"{input_name}_randomized_{index:04d}.json"
        output_path = self.output_dir / output_filename
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(randomized_data, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
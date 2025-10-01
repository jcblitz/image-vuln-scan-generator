"""
Abstract base validation interface with template method pattern for vulnerability data validation.
"""

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List

from ..exceptions import ValidationError
from ..logging_config import get_logger


class BaseValidator(ABC):
    """Abstract base class providing template method pattern for validation operations."""
    
    def __init__(self):
        """Initialize validator."""
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        self.logger.debug(f"{self.__class__.__name__} initialized")
    
    def validate_input_file(self, file_path: str) -> bool:
        """
        Template method for input file validation.
        
        Args:
            file_path: Path to the input file
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If validation fails
        """
        self.logger.debug(f"Validating input file: {file_path}")
        
        try:
            # Check file existence and accessibility
            path = Path(file_path)
            if not path.exists():
                raise ValidationError(
                    f"Input file does not exist",
                    file_path=file_path,
                    details="File path not found on filesystem"
                )
            
            if not path.is_file():
                raise ValidationError(
                    f"Input path is not a file",
                    file_path=file_path,
                    details="Path exists but is not a regular file"
                )
            
            # Load and parse JSON
            data = self._load_json(file_path)
            
            # Perform format-specific schema validation
            if not self._validate_schema(data):
                raise ValidationError(
                    "File does not have valid schema structure",
                    file_path=file_path,
                    details="Schema validation failed"
                )
            
            self.logger.info(f"Successfully validated input file: {file_path}")
            return True
            
        except ValidationError:
            # Re-raise ValidationError as-is
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error validating file {file_path}: {e}")
            raise ValidationError(
                "Unexpected error during validation",
                file_path=file_path,
                details=f"Unexpected error: {e}"
            )
    
    def validate_generated_file(self, data: Dict[str, Any]) -> bool:
        """
        Template method for generated file validation.
        
        Args:
            data: Generated JSON data as dictionary
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If validation fails
        """
        self.logger.debug("Validating generated file data")
        
        try:
            if not self._validate_schema(data):
                raise ValidationError(
                    "Generated data does not have valid schema structure",
                    details="Schema validation failed for generated data"
                )
            
            self.logger.debug("Generated file data validation successful")
            return True
            
        except ValidationError:
            # Re-raise ValidationError as-is
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error validating generated data: {e}")
            raise ValidationError(
                "Unexpected error during generated data validation",
                details=f"Unexpected error: {e}"
            )
    
    def _load_json(self, file_path: str) -> Dict[str, Any]:
        """
        Load and parse JSON file with common error handling.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Parsed JSON data as dictionary
            
        Raises:
            ValidationError: If JSON loading fails
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
            
        except json.JSONDecodeError as e:
            self.logger.error(f"JSON decode error in file {file_path}: {e}")
            raise ValidationError(
                "File contains invalid JSON",
                file_path=file_path,
                details=f"JSON parsing failed: {e}"
            )
        except IOError as e:
            self.logger.error(f"IO error reading file {file_path}: {e}")
            raise ValidationError(
                "Failed to read input file",
                file_path=file_path,
                details=f"IO error: {e}"
            )
    
    @abstractmethod
    def _validate_schema(self, data: Dict[str, Any]) -> bool:
        """
        Format-specific schema validation - implemented by subclasses.
        
        Args:
            data: JSON data to validate
            
        Returns:
            True if schema is valid, False otherwise
        """
        pass
    
    @abstractmethod
    def _get_required_fields(self) -> List[str]:
        """
        Get list of required top-level fields - implemented by subclasses.
        
        Returns:
            List of required field names
        """
        pass
    
    def _check_required_fields(self, data: Dict[str, Any], required_fields: List[str]) -> bool:
        """
        Check presence of required fields in data.
        
        Args:
            data: Data dictionary to check
            required_fields: List of required field names
            
        Returns:
            True if all required fields are present
        """
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            self.logger.debug(f"Missing required fields: {missing_fields}")
            return False
        return True
    
    def _validate_field_type(self, data: Dict[str, Any], field_name: str, expected_type: type) -> bool:
        """
        Validate that a field has the expected type.
        
        Args:
            data: Data dictionary containing the field
            field_name: Name of the field to validate
            expected_type: Expected Python type
            
        Returns:
            True if field has correct type or is missing, False if wrong type
        """
        if field_name not in data:
            return True  # Missing fields are handled by required field checks
        
        field_value = data[field_name]
        if not isinstance(field_value, expected_type):
            self.logger.debug(f"Field '{field_name}' has wrong type: expected {expected_type.__name__}, got {type(field_value).__name__}")
            return False
        
        return True
    
    def _validate_list_items(self, items: List[Any], item_validator) -> bool:
        """
        Validate all items in a list using provided validator function.
        
        Args:
            items: List of items to validate
            item_validator: Function that takes an item and returns bool
            
        Returns:
            True if all items are valid
        """
        for i, item in enumerate(items):
            if not item_validator(item):
                self.logger.debug(f"List item {i} failed validation")
                return False
        return True
    
    def _validate_string_format(self, value: str, pattern: str = None, min_length: int = None, max_length: int = None) -> bool:
        """
        Validate string format with optional pattern and length constraints.
        
        Args:
            value: String value to validate
            pattern: Optional regex pattern to match
            min_length: Optional minimum length
            max_length: Optional maximum length
            
        Returns:
            True if string format is valid
        """
        if not isinstance(value, str):
            return False
        
        if min_length is not None and len(value) < min_length:
            self.logger.debug(f"String too short: {len(value)} < {min_length}")
            return False
        
        if max_length is not None and len(value) > max_length:
            self.logger.debug(f"String too long: {len(value)} > {max_length}")
            return False
        
        if pattern is not None:
            import re
            if not re.match(pattern, value):
                self.logger.debug(f"String does not match pattern: {pattern}")
                return False
        
        return True
    
    def _validate_numeric_range(self, value: float, min_value: float = None, max_value: float = None) -> bool:
        """
        Validate numeric value is within specified range.
        
        Args:
            value: Numeric value to validate
            min_value: Optional minimum value
            max_value: Optional maximum value
            
        Returns:
            True if value is within range
        """
        if not isinstance(value, (int, float)):
            return False
        
        if min_value is not None and value < min_value:
            self.logger.debug(f"Value too small: {value} < {min_value}")
            return False
        
        if max_value is not None and value > max_value:
            self.logger.debug(f"Value too large: {value} > {max_value}")
            return False
        
        return True
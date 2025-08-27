"""
Custom exception classes for the Trivy Test Data Generator.
"""


class TrivyGeneratorError(Exception):
    """Base exception for all Trivy generator errors."""
    
    def __init__(self, message: str, details: str = None):
        """
        Initialize the exception.
        
        Args:
            message: Human-readable error message
            details: Optional additional details for debugging
        """
        super().__init__(message)
        self.message = message
        self.details = details
    
    def __str__(self) -> str:
        """Return string representation of the error."""
        if self.details:
            return f"{self.message} (Details: {self.details})"
        return self.message


class ValidationError(TrivyGeneratorError):
    """Exception raised when input validation fails."""
    
    def __init__(self, message: str, file_path: str = None, details: str = None):
        """
        Initialize validation error.
        
        Args:
            message: Human-readable error message
            file_path: Optional path to the file that failed validation
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.file_path = file_path
    
    def __str__(self) -> str:
        """Return string representation of the validation error."""
        base_msg = self.message
        if self.file_path:
            base_msg = f"{base_msg} (File: {self.file_path})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg


class GenerationError(TrivyGeneratorError):
    """Exception raised when file generation fails."""
    
    def __init__(self, message: str, operation: str = None, details: str = None):
        """
        Initialize generation error.
        
        Args:
            message: Human-readable error message
            operation: Optional description of the operation that failed
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.operation = operation
    
    def __str__(self) -> str:
        """Return string representation of the generation error."""
        base_msg = self.message
        if self.operation:
            base_msg = f"{base_msg} (Operation: {self.operation})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg


class FileOperationError(TrivyGeneratorError):
    """Exception raised when file operations fail."""
    
    def __init__(self, message: str, file_path: str = None, operation: str = None, details: str = None):
        """
        Initialize file operation error.
        
        Args:
            message: Human-readable error message
            file_path: Optional path to the file involved in the operation
            operation: Optional description of the file operation that failed
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.file_path = file_path
        self.operation = operation
    
    def __str__(self) -> str:
        """Return string representation of the file operation error."""
        base_msg = self.message
        if self.file_path:
            base_msg = f"{base_msg} (File: {self.file_path})"
        if self.operation:
            base_msg = f"{base_msg} (Operation: {self.operation})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg


class ConfigurationError(TrivyGeneratorError):
    """Exception raised when configuration is invalid."""
    
    def __init__(self, message: str, parameter: str = None, details: str = None):
        """
        Initialize configuration error.
        
        Args:
            message: Human-readable error message
            parameter: Optional name of the configuration parameter that's invalid
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.parameter = parameter
    
    def __str__(self) -> str:
        """Return string representation of the configuration error."""
        base_msg = self.message
        if self.parameter:
            base_msg = f"{base_msg} (Parameter: {self.parameter})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg
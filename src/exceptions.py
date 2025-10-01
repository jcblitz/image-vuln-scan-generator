"""
Custom exception classes for the Vulnerability Test Data Generator.
Supports both Trivy and Grype formats with shared base exceptions.
"""


class VulnerabilityGeneratorError(Exception):
    """Base exception for all vulnerability generator errors."""
    
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


class ValidationError(VulnerabilityGeneratorError):
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


class GenerationError(VulnerabilityGeneratorError):
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


class FileOperationError(VulnerabilityGeneratorError):
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


class ConfigurationError(VulnerabilityGeneratorError):
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


# Format-specific base exceptions
class TrivyGeneratorError(VulnerabilityGeneratorError):
    """Base exception for Trivy-specific generator errors."""
    pass


class GrypeGeneratorError(VulnerabilityGeneratorError):
    """Base exception for Grype-specific generator errors."""
    pass


# Grype-specific exceptions
class PURLFormatError(GrypeGeneratorError):
    """Exception raised when Package URL (PURL) format is invalid."""
    
    def __init__(self, message: str, purl: str = None, details: str = None):
        """
        Initialize PURL format error.
        
        Args:
            message: Human-readable error message
            purl: Optional PURL string that caused the error
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.purl = purl
    
    def __str__(self) -> str:
        """Return string representation of the PURL format error."""
        base_msg = self.message
        if self.purl:
            base_msg = f"{base_msg} (PURL: {self.purl})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg


class GrypeSchemaError(GrypeGeneratorError):
    """Exception raised when Grype schema validation fails."""
    
    def __init__(self, message: str, field: str = None, expected_type: str = None, details: str = None):
        """
        Initialize Grype schema error.
        
        Args:
            message: Human-readable error message
            field: Optional field name that failed validation
            expected_type: Optional expected type for the field
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.field = field
        self.expected_type = expected_type
    
    def __str__(self) -> str:
        """Return string representation of the schema error."""
        base_msg = self.message
        if self.field:
            base_msg = f"{base_msg} (Field: {self.field})"
        if self.expected_type:
            base_msg = f"{base_msg} (Expected: {self.expected_type})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg


class MatchDetailsError(GrypeGeneratorError):
    """Exception raised when match details processing fails."""
    
    def __init__(self, message: str, matcher_type: str = None, details: str = None):
        """
        Initialize match details error.
        
        Args:
            message: Human-readable error message
            matcher_type: Optional matcher type that caused the error
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.matcher_type = matcher_type
    
    def __str__(self) -> str:
        """Return string representation of the match details error."""
        base_msg = self.message
        if self.matcher_type:
            base_msg = f"{base_msg} (Matcher: {self.matcher_type})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg


class CVSSValidationError(VulnerabilityGeneratorError):
    """Exception raised when CVSS data validation fails."""
    
    def __init__(self, message: str, cvss_version: str = None, score: float = None, details: str = None):
        """
        Initialize CVSS validation error.
        
        Args:
            message: Human-readable error message
            cvss_version: Optional CVSS version (e.g., "3.1")
            score: Optional score value that failed validation
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.cvss_version = cvss_version
        self.score = score
    
    def __str__(self) -> str:
        """Return string representation of the CVSS validation error."""
        base_msg = self.message
        if self.cvss_version:
            base_msg = f"{base_msg} (CVSS Version: {self.cvss_version})"
        if self.score is not None:
            base_msg = f"{base_msg} (Score: {self.score})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg


class FormatDetectionError(VulnerabilityGeneratorError):
    """Exception raised when format detection fails."""
    
    def __init__(self, message: str, file_path: str = None, detected_format: str = None, details: str = None):
        """
        Initialize format detection error.
        
        Args:
            message: Human-readable error message
            file_path: Optional path to the file being analyzed
            detected_format: Optional format that was detected (if any)
            details: Optional additional details for debugging
        """
        super().__init__(message, details)
        self.file_path = file_path
        self.detected_format = detected_format
    
    def __str__(self) -> str:
        """Return string representation of the format detection error."""
        base_msg = self.message
        if self.file_path:
            base_msg = f"{base_msg} (File: {self.file_path})"
        if self.detected_format:
            base_msg = f"{base_msg} (Detected: {self.detected_format})"
        if self.details:
            base_msg = f"{base_msg} (Details: {self.details})"
        return base_msg
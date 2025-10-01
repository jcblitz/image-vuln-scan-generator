"""
Logging configuration for the Vulnerability Test Data Generator.
Supports both Trivy and Grype formats with progress tracking.
"""

import logging
import sys
import time
from pathlib import Path
from typing import Optional, Callable


def setup_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    enable_console: bool = True,
    format_string: Optional[str] = None
) -> logging.Logger:
    """
    Set up logging configuration for the application.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file. If None, only console logging is used.
        enable_console: Whether to enable console logging
        format_string: Optional custom format string for log messages
        
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger("vulnerability_generator")
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear any existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Default format string
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    formatter = logging.Formatter(format_string)
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(getattr(logging, level.upper()))
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        try:
            # Ensure log directory exists
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(getattr(logging, level.upper()))
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            
            logger.info(f"Logging to file: {log_file}")
        except (OSError, IOError) as e:
            logger.warning(f"Failed to set up file logging: {e}")
    
    # Prevent propagation to root logger to avoid duplicate messages
    logger.propagate = False
    
    return logger


def get_logger(name: str = "vulnerability_generator") -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_exception(logger: logging.Logger, exception: Exception, context: str = None) -> None:
    """
    Log an exception with context information.
    
    Args:
        logger: Logger instance to use
        exception: Exception to log
        context: Optional context description
    """
    if context:
        logger.error(f"Exception in {context}: {type(exception).__name__}: {exception}")
    else:
        logger.error(f"Exception: {type(exception).__name__}: {exception}")
    
    # Log stack trace at debug level
    logger.debug("Stack trace:", exc_info=True)


def log_performance(logger: logging.Logger, operation: str, duration: float, count: int = None) -> None:
    """
    Log performance metrics for operations.
    
    Args:
        logger: Logger instance to use
        operation: Description of the operation
        duration: Duration in seconds
        count: Optional count of items processed
    """
    if count is not None:
        rate = count / duration if duration > 0 else 0
        logger.info(f"Performance - {operation}: {duration:.2f}s for {count} items ({rate:.1f} items/sec)")
    else:
        logger.info(f"Performance - {operation}: {duration:.2f}s")


def configure_debug_logging() -> logging.Logger:
    """
    Configure debug-level logging for development and troubleshooting.
    
    Returns:
        Logger configured for debug output
    """
    debug_format = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
    return setup_logging(
        level="DEBUG",
        format_string=debug_format,
        enable_console=True
    )


def configure_production_logging(log_file: str = "vulnerability_generator.log") -> logging.Logger:
    """
    Configure production-level logging with file output.
    
    Args:
        log_file: Path to log file
        
    Returns:
        Logger configured for production use
    """
    return setup_logging(
        level="INFO",
        log_file=log_file,
        enable_console=True
    )


class ProgressTracker:
    """
    Progress tracking utility for batch operations with logging integration.
    """
    
    def __init__(self, logger: logging.Logger, total: int, operation: str = "Processing"):
        """
        Initialize progress tracker.
        
        Args:
            logger: Logger instance to use for progress updates
            total: Total number of items to process
            operation: Description of the operation being tracked
        """
        self.logger = logger
        self.total = total
        self.operation = operation
        self.current = 0
        self.start_time = time.time()
        self.last_update_time = self.start_time
        self.update_interval = 1.0  # Update every second
        
        # Log intervals for progress updates
        self.progress_thresholds = [10, 25, 50, 75, 90, 95]  # Percentage thresholds
        self.reported_thresholds = set()
        
        self.logger.info(f"Starting {self.operation}: 0/{self.total} items")
    
    def update(self, increment: int = 1) -> None:
        """
        Update progress counter and log if necessary.
        
        Args:
            increment: Number of items to increment by
        """
        self.current += increment
        current_time = time.time()
        
        # Check if we should log based on time interval
        time_since_update = current_time - self.last_update_time
        should_update_time = time_since_update >= self.update_interval
        
        # Check if we should log based on percentage thresholds
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        should_update_threshold = any(
            threshold <= percentage and threshold not in self.reported_thresholds
            for threshold in self.progress_thresholds
        )
        
        # Log progress if conditions are met
        if should_update_time or should_update_threshold or self.current >= self.total:
            self._log_progress(current_time)
            self.last_update_time = current_time
            
            # Mark thresholds as reported
            for threshold in self.progress_thresholds:
                if threshold <= percentage:
                    self.reported_thresholds.add(threshold)
    
    def _log_progress(self, current_time: float) -> None:
        """
        Log current progress with timing information.
        
        Args:
            current_time: Current timestamp
        """
        elapsed = current_time - self.start_time
        percentage = (self.current / self.total) * 100 if self.total > 0 else 0
        
        if self.current > 0 and elapsed > 0:
            rate = self.current / elapsed
            eta = (self.total - self.current) / rate if rate > 0 else 0
            
            self.logger.info(
                f"{self.operation}: {self.current}/{self.total} ({percentage:.1f}%) "
                f"- {rate:.1f} items/sec - ETA: {eta:.1f}s"
            )
        else:
            self.logger.info(f"{self.operation}: {self.current}/{self.total} ({percentage:.1f}%)")
    
    def complete(self) -> None:
        """
        Mark operation as complete and log final statistics.
        """
        end_time = time.time()
        total_duration = end_time - self.start_time
        
        if total_duration > 0:
            rate = self.current / total_duration
            self.logger.info(
                f"Completed {self.operation}: {self.current} items in {total_duration:.2f}s "
                f"({rate:.1f} items/sec)"
            )
        else:
            self.logger.info(f"Completed {self.operation}: {self.current} items")


def create_progress_tracker(logger: logging.Logger, total: int, operation: str = "Processing") -> ProgressTracker:
    """
    Create a progress tracker instance.
    
    Args:
        logger: Logger instance to use
        total: Total number of items to process
        operation: Description of the operation
        
    Returns:
        ProgressTracker instance
    """
    return ProgressTracker(logger, total, operation)


def log_generation_start(logger: logging.Logger, format_type: str, input_file: str, count: int, output_dir: str) -> None:
    """
    Log the start of a generation operation with context information.
    
    Args:
        logger: Logger instance to use
        format_type: Format being processed (Trivy, Grype, etc.)
        input_file: Path to input file
        count: Number of files to generate
        output_dir: Output directory path
    """
    logger.info(f"Starting {format_type} data generation")
    logger.info(f"Input file: {input_file}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Files to generate: {count}")


def log_generation_complete(logger: logging.Logger, format_type: str, count: int, duration: float, output_files: list) -> None:
    """
    Log the completion of a generation operation with results.
    
    Args:
        logger: Logger instance to use
        format_type: Format that was processed
        count: Number of files generated
        duration: Total duration in seconds
        output_files: List of generated file paths
    """
    rate = count / duration if duration > 0 else 0
    logger.info(f"Completed {format_type} data generation")
    logger.info(f"Generated {count} files in {duration:.2f}s ({rate:.1f} files/sec)")
    
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug("Generated files:")
        for file_path in output_files:
            logger.debug(f"  - {file_path}")


def log_validation_results(logger: logging.Logger, format_type: str, valid_count: int, total_count: int, errors: list = None) -> None:
    """
    Log validation results for generated files.
    
    Args:
        logger: Logger instance to use
        format_type: Format that was validated
        valid_count: Number of valid files
        total_count: Total number of files checked
        errors: Optional list of validation errors
    """
    success_rate = (valid_count / total_count) * 100 if total_count > 0 else 0
    logger.info(f"{format_type} validation: {valid_count}/{total_count} files valid ({success_rate:.1f}%)")
    
    if errors and logger.isEnabledFor(logging.DEBUG):
        logger.debug("Validation errors:")
        for error in errors:
            logger.debug(f"  - {error}")


def configure_format_logging(format_type: str, level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """
    Configure logging for a specific format with appropriate naming.
    
    Args:
        format_type: Format type (trivy, grype, etc.)
        level: Logging level
        log_file: Optional log file path
        
    Returns:
        Configured logger instance
    """
    logger_name = f"vulnerability_generator.{format_type.lower()}"
    
    if log_file is None:
        log_file = f"{format_type.lower()}_generator.log"
    
    return setup_logging(
        level=level,
        log_file=log_file,
        enable_console=True
    )
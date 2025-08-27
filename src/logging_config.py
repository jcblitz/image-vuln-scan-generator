"""
Logging configuration for the Trivy Test Data Generator.
"""

import logging
import sys
from pathlib import Path
from typing import Optional


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
    logger = logging.getLogger("trivy_generator")
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


def get_logger(name: str = "trivy_generator") -> logging.Logger:
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


def configure_production_logging(log_file: str = "trivy_generator.log") -> logging.Logger:
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
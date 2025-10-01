"""
Main CLI entry point for the Vulnerability Test Data Generator.
Supports both Trivy and Grype formats with auto-detection.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .exceptions import TrivyGeneratorError, ValidationError, GenerationError, FileOperationError, ConfigurationError
from .generator import TrivyDataGenerator
from .grype.generator import GrypeDataGenerator
from .logging_config import setup_logging, get_logger, log_exception
from .validators import TrivyValidator


def detect_format(file_path: str) -> str:
    """
    Auto-detect scanner format from JSON structure.
    
    Args:
        file_path: Path to the input JSON file
        
    Returns:
        Format type: 'trivy' or 'grype'
        
    Raises:
        ValidationError: If format cannot be determined or file is invalid
        FileOperationError: If file cannot be read
    """
    logger = get_logger(__name__)
    logger.debug(f"Detecting format for file: {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except FileNotFoundError:
        raise FileOperationError(
            "Input file not found",
            file_path=file_path,
            operation="format detection"
        )
    except json.JSONDecodeError as e:
        raise ValidationError(
            "Invalid JSON in input file",
            file_path=file_path,
            details=f"JSON parsing failed: {e}"
        )
    except IOError as e:
        raise FileOperationError(
            "Failed to read input file",
            file_path=file_path,
            operation="format detection",
            details=str(e)
        )
    
    # Check for Grype format indicators
    if "matches" in data and isinstance(data["matches"], list):
        # Additional Grype-specific checks
        if data["matches"]:  # If matches array is not empty
            first_match = data["matches"][0]
            if ("vulnerability" in first_match and 
                "artifact" in first_match and 
                "matchDetails" in first_match):
                logger.info("Detected Grype format")
                return "grype"
    
    # Check for Trivy format indicators
    if "Results" in data and isinstance(data["Results"], list):
        # Additional Trivy-specific checks
        if data["Results"]:  # If Results array is not empty
            first_result = data["Results"][0]
            if "Vulnerabilities" in first_result:
                logger.info("Detected Trivy format")
                return "trivy"
    
    # If we have an empty matches array, assume Grype
    if "matches" in data and isinstance(data["matches"], list):
        logger.info("Detected Grype format (empty matches)")
        return "grype"
    
    # If we have an empty Results array, assume Trivy
    if "Results" in data and isinstance(data["Results"], list):
        logger.info("Detected Trivy format (empty results)")
        return "trivy"
    
    # If neither format is clearly detected, raise an error
    logger.error(f"Unable to determine format for file: {file_path}")
    raise ValidationError(
        "Unable to determine scanner format",
        file_path=file_path,
        details="File does not match Trivy or Grype JSON structure"
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate randomized test data from Trivy or Grype JSON vulnerability reports"
    )
    
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the input JSON file (Trivy or Grype format)"
    )
    
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=10,
        help="Number of randomized files to generate (default: 10)"
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="output",
        help="Output directory for generated files (default: output)"
    )
    
    parser.add_argument(
        "-f", "--format",
        type=str,
        choices=["trivy", "grype"],
        help="Manually specify scanner format (auto-detected if not provided)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--log-file",
        type=str,
        help="Path to log file (optional)"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    return parser.parse_args()


def create_generator(format_type: str, input_file: str, output_dir: str):
    """
    Factory method to create format-specific generator.
    
    Args:
        format_type: Scanner format ('trivy' or 'grype')
        input_file: Path to input JSON file
        output_dir: Output directory for generated files
        
    Returns:
        Format-specific generator instance
        
    Raises:
        ConfigurationError: If format is unsupported
    """
    logger = get_logger(__name__)
    logger.debug(f"Creating generator for format: {format_type}")
    
    if format_type == "trivy":
        logger.info("Creating Trivy generator")
        return TrivyDataGenerator(input_file, output_dir)
    elif format_type == "grype":
        logger.info("Creating Grype generator")
        return GrypeDataGenerator(input_file, output_dir)
    else:
        raise ConfigurationError(
            f"Unsupported scanner format: {format_type}",
            parameter="format",
            details=f"Supported formats: trivy, grype"
        )


def validate_inputs(args: argparse.Namespace, logger) -> None:
    """
    Validate input parameters.
    
    Args:
        args: Parsed command line arguments
        logger: Logger instance
        
    Raises:
        ConfigurationError: If input parameters are invalid
    """
    logger.debug("Validating input parameters")
    
    input_path = Path(args.input_file)
    
    if not input_path.exists():
        raise ConfigurationError(
            f"Input file does not exist",
            parameter="input_file",
            details=f"Path: {args.input_file}"
        )
    
    if not input_path.is_file():
        raise ConfigurationError(
            f"Input path is not a file",
            parameter="input_file", 
            details=f"Path: {args.input_file}"
        )
    
    if args.count <= 0:
        raise ConfigurationError(
            "Count must be a positive integer",
            parameter="count",
            details=f"Provided value: {args.count}"
        )
    
    if args.count > 10000:
        logger.warning(f"Large file count requested: {args.count}")
    
    logger.debug("Input parameter validation passed")


def main() -> int:
    """Main CLI entry point."""
    logger = None
    
    try:
        args = parse_arguments()
        
        # Set up logging based on arguments
        log_level = "DEBUG" if args.debug else ("INFO" if args.verbose else "WARNING")
        logger = setup_logging(
            level=log_level,
            log_file=args.log_file,
            enable_console=True
        )
        
        logger.info("Starting Vulnerability Test Data Generator")
        logger.debug(f"Arguments: input_file={args.input_file}, count={args.count}, output_dir={args.output_dir}, format={args.format}")
        
        # Validate input parameters
        validate_inputs(args, logger)
        
        # Determine format (auto-detect or use specified)
        if args.format:
            format_type = args.format
            logger.info(f"Using manually specified format: {format_type}")
        else:
            logger.info("Auto-detecting scanner format...")
            format_type = detect_format(args.input_file)
        
        # Create format-specific generator
        logger.info(f"Creating {format_type} generator")
        generator = create_generator(format_type, args.input_file, args.output_dir)
        
        # Generate files
        logger.info(f"Generating {args.count} randomized {format_type} files...")
        print(f"Generating {args.count} randomized {format_type} files...")
        
        generated_files = generator.generate_files(args.count)
        
        success_msg = f"Successfully generated {len(generated_files)} {format_type} files in '{args.output_dir}'"
        logger.info(success_msg)
        print(success_msg)
        return 0
        
    except KeyboardInterrupt:
        error_msg = "Operation cancelled by user"
        if logger:
            logger.info(error_msg)
        print(f"\n{error_msg}")
        return 1
        
    except ConfigurationError as e:
        error_msg = f"Configuration error: {e}"
        if logger:
            logger.error(error_msg)
        print(error_msg)
        return 1
        
    except ValidationError as e:
        error_msg = f"Validation error: {e}"
        if logger:
            logger.error(error_msg)
        print(error_msg)
        return 1
        
    except GenerationError as e:
        error_msg = f"Generation error: {e}"
        if logger:
            logger.error(error_msg)
        print(error_msg)
        return 1
        
    except FileOperationError as e:
        error_msg = f"File operation error: {e}"
        if logger:
            logger.error(error_msg)
        print(error_msg)
        return 1
        
    except TrivyGeneratorError as e:
        error_msg = f"Generator error: {e}"
        if logger:
            logger.error(error_msg)
        print(error_msg)
        return 1
        
    except Exception as e:
        error_msg = f"Unexpected error: {e}"
        if logger:
            log_exception(logger, e, "main execution")
        print(error_msg)
        return 1


if __name__ == "__main__":
    sys.exit(main())
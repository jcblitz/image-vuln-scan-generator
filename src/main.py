"""
Main CLI entry point for the Trivy Test Data Generator.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .exceptions import TrivyGeneratorError, ValidationError, GenerationError, FileOperationError, ConfigurationError
from .generator import TrivyDataGenerator
from .logging_config import setup_logging, get_logger, log_exception
from .validators import TrivyValidator


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate randomized test data from Trivy JSON vulnerability reports"
    )
    
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the input Trivy JSON file"
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
        
        logger.info("Starting Trivy Test Data Generator")
        logger.debug(f"Arguments: input_file={args.input_file}, count={args.count}, output_dir={args.output_dir}")
        
        # Validate input parameters
        validate_inputs(args, logger)
        
        # Validate input file is valid Trivy JSON
        logger.info("Validating input file")
        validator = TrivyValidator()
        validator.validate_input_file(args.input_file)
        
        # Initialize generator
        logger.info("Initializing generator")
        generator = TrivyDataGenerator(args.input_file, args.output_dir)
        
        # Generate files
        logger.info(f"Generating {args.count} randomized files...")
        print(f"Generating {args.count} randomized files...")
        
        generated_files = generator.generate_files(args.count)
        
        success_msg = f"Successfully generated {len(generated_files)} files in '{args.output_dir}'"
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
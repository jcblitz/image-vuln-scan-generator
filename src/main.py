"""
Main CLI entry point for the Trivy Test Data Generator.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from .generator import TrivyDataGenerator
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
    
    return parser.parse_args()


def validate_inputs(args: argparse.Namespace) -> bool:
    """Validate input parameters."""
    input_path = Path(args.input_file)
    
    if not input_path.exists():
        print(f"Error: Input file '{args.input_file}' does not exist")
        return False
    
    if not input_path.is_file():
        print(f"Error: '{args.input_file}' is not a file")
        return False
    
    if args.count <= 0:
        print("Error: Count must be a positive integer")
        return False
    
    return True


def main() -> int:
    """Main CLI entry point."""
    try:
        args = parse_arguments()
        
        if not validate_inputs(args):
            return 1
        
        # Validate input file is valid Trivy JSON
        validator = TrivyValidator()
        if not validator.validate_input_file(args.input_file):
            print(f"Error: '{args.input_file}' is not a valid Trivy JSON file")
            return 1
        
        # Initialize generator
        generator = TrivyDataGenerator(args.input_file, args.output_dir)
        
        # Generate files
        print(f"Generating {args.count} randomized files...")
        generated_files = generator.generate_files(args.count)
        
        print(f"Successfully generated {len(generated_files)} files in '{args.output_dir}'")
        return 0
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
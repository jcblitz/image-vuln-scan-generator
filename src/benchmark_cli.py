"""
Command-line interface for running performance benchmarks.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List

from .generator import TrivyDataGenerator
from .logging_config import setup_logging, get_logger
from .performance import BenchmarkRunner
from .validators import TrivyValidator


def parse_benchmark_arguments() -> argparse.Namespace:
    """Parse command line arguments for benchmark tool."""
    parser = argparse.ArgumentParser(
        description="Run performance benchmarks for Trivy Test Data Generator"
    )
    
    parser.add_argument(
        "input_file",
        type=str,
        help="Path to the input Trivy JSON file"
    )
    
    parser.add_argument(
        "-c", "--counts",
        type=int,
        nargs="+",
        default=[10, 50, 100, 500, 1000],
        help="File counts to benchmark (default: 10 50 100 500 1000)"
    )
    
    parser.add_argument(
        "-i", "--iterations",
        type=int,
        default=3,
        help="Number of iterations per file count (default: 3)"
    )
    
    parser.add_argument(
        "-o", "--output-dir",
        type=str,
        default="benchmark_output",
        help="Output directory for generated files (default: benchmark_output)"
    )
    
    parser.add_argument(
        "--report-file",
        type=str,
        help="Save benchmark report to file (optional)"
    )
    
    parser.add_argument(
        "--json-results",
        type=str,
        help="Save detailed results as JSON file (optional)"
    )
    
    parser.add_argument(
        "--no-optimizations",
        action="store_true",
        help="Disable performance optimizations for comparison"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    return parser.parse_args()


def validate_benchmark_inputs(args: argparse.Namespace, logger) -> None:
    """Validate benchmark input parameters."""
    logger.debug("Validating benchmark input parameters")
    
    input_path = Path(args.input_file)
    
    if not input_path.exists():
        raise FileNotFoundError(f"Input file does not exist: {args.input_file}")
    
    if not input_path.is_file():
        raise ValueError(f"Input path is not a file: {args.input_file}")
    
    if args.iterations <= 0:
        raise ValueError(f"Iterations must be positive: {args.iterations}")
    
    for count in args.counts:
        if count <= 0:
            raise ValueError(f"File count must be positive: {count}")
    
    # Warn about large benchmarks
    max_count = max(args.counts)
    if max_count >= 1000:
        logger.warning(f"Large benchmark requested (max {max_count} files). This may take a while.")
    
    logger.debug("Benchmark input validation passed")


def run_benchmark_suite(args: argparse.Namespace, logger) -> dict:
    """Run the complete benchmark suite."""
    logger.info("Starting benchmark suite")
    
    # Validate input file
    logger.info("Validating input file")
    validator = TrivyValidator()
    validator.validate_input_file(args.input_file)
    
    # Initialize generator
    logger.info("Initializing generator")
    generator = TrivyDataGenerator(
        args.input_file, 
        args.output_dir,
        enable_performance_optimizations=not args.no_optimizations
    )
    
    optimization_status = "disabled" if args.no_optimizations else "enabled"
    logger.info(f"Performance optimizations: {optimization_status}")
    
    # Run benchmarks
    logger.info(f"Running benchmarks for file counts: {args.counts}")
    runner = BenchmarkRunner()
    
    start_time = time.time()
    results = runner.run_generation_benchmark(
        generator, 
        args.counts, 
        args.iterations
    )
    total_duration = time.time() - start_time
    
    results["benchmark_info"]["total_duration"] = total_duration
    results["benchmark_info"]["optimizations_enabled"] = not args.no_optimizations
    
    logger.info(f"Benchmark suite completed in {total_duration:.2f}s")
    
    return results


def generate_and_save_reports(results: dict, args: argparse.Namespace, logger) -> None:
    """Generate and save benchmark reports."""
    runner = BenchmarkRunner()
    
    # Generate text report
    report = runner.generate_benchmark_report(results)
    
    # Print report to console
    print("\n" + "="*60)
    print(report)
    print("="*60)
    
    # Save text report if requested
    if args.report_file:
        try:
            with open(args.report_file, 'w') as f:
                f.write(report)
            logger.info(f"Benchmark report saved to: {args.report_file}")
        except IOError as e:
            logger.error(f"Failed to save report file: {e}")
    
    # Save JSON results if requested
    if args.json_results:
        try:
            with open(args.json_results, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Detailed results saved to: {args.json_results}")
        except IOError as e:
            logger.error(f"Failed to save JSON results: {e}")


def analyze_performance_targets(results: dict, logger) -> None:
    """Analyze results against performance targets."""
    logger.info("Analyzing performance against targets")
    
    # Check 1000-file 30-second target
    if 1000 in results["results"]:
        result_1000 = results["results"][1000]
        max_duration = result_1000["max_duration"]
        avg_duration = result_1000["avg_duration"]
        
        if max_duration < 30.0:
            logger.info(f"✓ 1000-file target MET: max {max_duration:.2f}s < 30s")
        else:
            logger.warning(f"✗ 1000-file target MISSED: max {max_duration:.2f}s >= 30s")
        
        logger.info(f"1000-file performance: avg {avg_duration:.2f}s, max {max_duration:.2f}s")
    
    # Check general performance trends
    sorted_counts = sorted(results["results"].keys())
    if len(sorted_counts) >= 2:
        logger.info("Performance scaling analysis:")
        for count in sorted_counts:
            result = results["results"][count]
            logger.info(f"  {count:4d} files: {result['avg_files_per_second']:6.1f} files/sec avg")


def main() -> int:
    """Main benchmark CLI entry point."""
    logger = None
    
    try:
        args = parse_benchmark_arguments()
        
        # Set up logging
        log_level = "DEBUG" if args.debug else ("INFO" if args.verbose else "WARNING")
        logger = setup_logging(
            level=log_level,
            enable_console=True
        )
        
        logger.info("Starting Trivy Test Data Generator Benchmark")
        
        # Validate inputs
        validate_benchmark_inputs(args, logger)
        
        # Run benchmark suite
        results = run_benchmark_suite(args, logger)
        
        # Generate and save reports
        generate_and_save_reports(results, args, logger)
        
        # Analyze performance targets
        analyze_performance_targets(results, logger)
        
        logger.info("Benchmark completed successfully")
        return 0
        
    except KeyboardInterrupt:
        error_msg = "Benchmark cancelled by user"
        if logger:
            logger.info(error_msg)
        print(f"\n{error_msg}")
        return 1
        
    except Exception as e:
        error_msg = f"Benchmark failed: {e}"
        if logger:
            logger.error(error_msg)
        print(error_msg)
        return 1


if __name__ == "__main__":
    sys.exit(main())
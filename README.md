# Vulnerability Test Data Generator

A Python tool for generating randomized, synthetic test data based on vulnerability scanner JSON reports. Supports both **Trivy** and **Grype** formats with automatic format detection.

## Overview

The Vulnerability Test Data Generator helps developers and QA engineers create diverse test datasets for security scan data ingestion systems. It takes a single vulnerability scanner JSON report as input and generates multiple randomized versions while maintaining the original JSON schema structure.

### Supported Formats
- **Trivy**: Container and filesystem vulnerability scanner
- **Grype**: Container vulnerability scanner by Anchore

## Features

- **Multi-Format Support**: Supports both Trivy and Grype JSON formats with automatic detection
- **Schema Preservation**: Maintains the exact JSON structure of the original vulnerability report
- **Realistic Randomization**: Generates realistic vulnerability data including CVE IDs, package names, versions, and CVSS scores
- **Configurable Output**: Specify the number of files to generate (1-10,000+)
- **Performance Optimized**: Can generate 1,000 files in under 30 seconds
- **Extensible Architecture**: Modular design with base classes for easy extension to other scanner formats
- **Comprehensive Testing**: Full test suite with unit, integration, and performance tests
- **Robust Error Handling**: Detailed error messages and logging for troubleshooting

## Installation

### From Source

```bash
git clone <repository-url>
cd vulnerability-test-data-generator
pip install -r requirements.txt
pip install -e .
```

### Using pip (when published)

```bash
pip install vulnerability-test-data-generator
```

### Direct Python Execution
```bash
python -m src.main input.json
```
## Usage

### Command Line Interface

```bash
# Generate 10 randomized files (default) - auto-detects format
python -m src.main input.json

# Generate 100 randomized files
python -m src.main input.json -c 100

# Specify output directory
python -m src.main input.json -c 50 -o /path/to/output

# Manually specify format (Trivy or Grype)
python -m src.main input.json -f trivy -c 25
python -m src.main grype-report.json -f grype -c 25

# Enable verbose logging
python -m src.main input.json -v

# Enable debug logging with log file
python -m src.main input.json --debug --log-file generator.log

# Show help
python -m src.main --help
```

### Python API

```python
# Trivy format
from src.trivy.generator import TrivyDataGenerator

generator = TrivyDataGenerator("trivy-report.json", "output_directory")
generated_files = generator.generate_files(25)
print(f"Generated {len(generated_files)} Trivy files")

# Grype format
from src.grype.generator import GrypeDataGenerator

generator = GrypeDataGenerator("grype-report.json", "output_directory")
generated_files = generator.generate_files(25)
print(f"Generated {len(generated_files)} Grype files")

# Auto-detection using main module
from src.main import detect_format, create_generator

format_type = detect_format("input.json")
generator = create_generator(format_type, "input.json", "output_directory")
generated_files = generator.generate_files(25)
```

## Examples

### Basic Usage

#### Trivy Format
```bash
# Generate 10 files from a Trivy report (auto-detected)
python -m src.main tests/fixtures/sample_trivy.json

# Generate 25 files with custom output directory
python -m src.main trivy-scan-results.json -c 25 -o trivy-test-data

# Expected output files: trivy-generated-0000.json through trivy-generated-0024.json
```

#### Grype Format
```bash
# Generate 50 files from a Grype report (auto-detected)  
python -m src.main tests/fixtures/grype-golang-1.12-alpine.json -c 50

# Generate files with verbose logging to monitor progress
python -m src.main grype-scan-results.json -c 100 -v -o grype-test-data

# Expected output files: grype-generated-0000.json through grype-generated-0099.json
```

### Advanced Usage

#### Format Auto-Detection
```bash
# The tool automatically detects format based on JSON structure
python -m src.main unknown-format.json -c 10 -v
# Output: "Detected format: grype" or "Detected format: trivy"

# Manual format specification (useful if auto-detection fails)
python -m src.main input.json -f grype -c 25
python -m src.main input.json -f trivy -c 25
```

#### Performance Testing
```bash
# Generate large datasets for performance testing
python -m src.main input.json -c 1000 -o performance-test --verbose

# Monitor generation with debug logging
python -m src.main input.json -c 500 --debug --log-file generation.log
```

#### Integration with CI/CD
```bash
# Generate test data as part of CI pipeline
python -m src.main baseline-scan.json -c 100 -o test-data/
python -m src.main grype-baseline.json -c 50 -o grype-test-data/

# Validate generated files (returns exit code 0 on success)
python -m src.main input.json -c 5 --validate-only
```

### Sample Output

#### Grype Generation
```bash
$ python -m src.main tests/fixtures/grype-golang-1.12-alpine.json -c 5 -v

Detected format: grype
Generating 5 randomized grype files...
[1/5] Generated grype-generated-0000.json (47 matches)
[2/5] Generated grype-generated-0001.json (23 matches) 
[3/5] Generated grype-generated-0002.json (31 matches)
[4/5] Generated grype-generated-0003.json (42 matches)
[5/5] Generated grype-generated-0004.json (18 matches)
Successfully generated 5 grype files in 'output' (1.2s)

$ ls output/
grype-generated-0000.json  grype-generated-0002.json  grype-generated-0004.json
grype-generated-0001.json  grype-generated-0003.json
```

#### Trivy Generation
```bash
$ python -m src.main tests/fixtures/sample_trivy.json -c 3 -v

Detected format: trivy
Generating 3 randomized trivy files...
[1/3] Generated trivy-generated-0000.json (15 vulnerabilities)
[2/3] Generated trivy-generated-0001.json (22 vulnerabilities)
[3/3] Generated trivy-generated-0002.json (8 vulnerabilities)
Successfully generated 3 trivy files in 'output' (0.3s)

$ ls output/
trivy-generated-0000.json  trivy-generated-0001.json  trivy-generated-0002.json
```

## Randomized Fields

The tool randomizes different fields based on the scanner format while preserving the JSON schema:

### Trivy Format
**Root Level Fields:**
- `ArtifactName`: Container image names with realistic tags
- `Metadata.ImageID`: Docker image SHA256 hashes

**Vulnerability Fields:**
- `VulnerabilityID`: CVE identifiers in CVE-YYYY-XXXXX format
- `PkgName`: Package names from a curated list of common Linux packages
- `InstalledVersion` / `FixedVersion`: Realistic version strings
- `Severity`: Weighted distribution of severity levels (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
- `CVSS.V2Score` / `CVSS.V3Score`: Realistic CVSS scores (0.0-10.0)
- `PublishedDate` / `LastModifiedDate`: Random dates within the last 5 years

### Grype Format
**Match Fields:**
- `matches`: Array with 1-50 randomized vulnerability matches
- `vulnerability.id`: CVE identifiers in CVE-YYYY-XXXXX format
- `vulnerability.severity`: Grype severity levels (Critical, High, Medium, Low, Negligible, Unknown)
- `vulnerability.cvss`: CVSS metrics with realistic scores and vectors
- `vulnerability.epss`: EPSS scores and percentiles (0.0-1.0)

**Artifact Fields:**
- `artifact.name`: Package names from curated lists
- `artifact.version`: Realistic version strings
- `artifact.purl`: Valid Package URL (PURL) format strings
- `artifact.locations`: File system paths and layer IDs

**Related Vulnerabilities:**
- `relatedVulnerabilities`: 0-5 related CVEs per match
- `matchDetails`: Matcher types and search criteria

## Format Detection

The tool automatically detects the scanner format by analyzing the JSON structure, eliminating the need to manually specify the format in most cases.

### Detection Logic

#### Grype Format Detection
- **Primary Indicator**: Presence of `matches` array at root level
- **Secondary Validation**: Each match contains `vulnerability`, `artifact`, and `matchDetails` objects
- **Schema Markers**: PURL format in `artifact.purl`, CVSS arrays, EPSS data structures

#### Trivy Format Detection  
- **Primary Indicator**: Presence of `Results` array at root level
- **Secondary Validation**: Each result contains `Vulnerabilities` array
- **Schema Markers**: `ArtifactName`, `ArtifactType`, and `Metadata` at root level

### Auto-Detection Examples

```bash
# Auto-detection with verbose output
$ python -m src.main unknown-scanner-output.json -v
Analyzing input file format...
Detected format: grype (found 'matches' array with 23 vulnerability matches)
Generating 10 randomized grype files...

$ python -m src.main another-scan.json -v  
Analyzing input file format...
Detected format: trivy (found 'Results' array with 3 target results)
Generating 10 randomized trivy files...
```

### Manual Format Override

If auto-detection fails or you want to force a specific format:

```bash
# Force Grype format processing
python -m src.main input.json -f grype -c 25

# Force Trivy format processing  
python -m src.main input.json -f trivy -c 25

# Show detection details without generation
python -m src.main input.json --detect-only
```

### Detection Failure Handling

When format detection fails, the tool provides helpful error messages:

```bash
$ python -m src.main invalid-format.json
Error: Unable to detect scanner format. File does not match Trivy or Grype schema.
Suggestion: Use -f/--format flag to manually specify format (trivy or grype)

$ python -m src.main input.json -f grype
Error: File does not match Grype format. Missing required 'matches' array.
Suggestion: Try -f trivy or check if input file is valid JSON.
```

## Performance

### Benchmarks
- **Generation Speed**: ~27-33 files per second on standard hardware (Intel i5/AMD Ryzen 5 equivalent)
- **Target Performance**: 1,000 files generated in under 30 seconds
- **Memory Usage**: ~50-100MB for processing large JSON files (10MB+ input files)
- **Scalable**: Successfully tested with 10,000+ file generation
- **File Size Impact**: Generation speed decreases with larger input files and more complex match structures

### Performance by Format
- **Trivy**: ~30-35 files/second (simpler schema structure)
- **Grype**: ~25-30 files/second (more complex matches and artifact data)

### Limitations
- **Input File Size**: Optimal performance with input files under 50MB
- **Match Complexity**: Files with 50+ matches per vulnerability may see reduced generation speed
- **Disk I/O**: Performance limited by disk write speed for large batch generation
- **Memory**: Large batch generation (10,000+ files) may require 1GB+ available memory
- **Concurrent Execution**: Currently single-threaded; parallel processing not yet implemented

## Requirements

- Python 3.8+
- Faker library for realistic data generation
- Standard library modules: json, pathlib, argparse, logging, time

## Development

### Setup Development Environment

```bash
# Clone repository
git clone <repository-url>
cd vulnerability-test-data-generator

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks (optional)
pre-commit install
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=src

# Run specific test files
python -m pytest tests/test_trivy_* -v    # Trivy tests
python -m pytest tests/test_grype_* -v    # Grype tests
python -m pytest tests/test_integration.py -v  # Integration tests

# Run performance tests
python -m pytest tests/test_performance.py -v
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/
```

## Project Structure

```
vulnerability-test-data-generator/
├── src/
│   ├── __init__.py
│   ├── main.py              # CLI entry point with auto-detection
│   ├── exceptions.py        # Custom exception classes
│   ├── logging_config.py    # Logging configuration
│   ├── performance.py       # Performance monitoring
│   ├── base/                # Abstract base classes
│   │   ├── generator.py     # Base generator template
│   │   ├── randomizer.py    # Base randomization utilities
│   │   └── validator.py     # Base validation interface
│   ├── trivy/               # Trivy-specific implementation
│   │   ├── generator.py     # Trivy data generator
│   │   ├── randomizers.py   # Trivy field randomization
│   │   └── validators.py    # Trivy schema validation
│   └── grype/               # Grype-specific implementation
│       ├── generator.py     # Grype data generator
│       ├── randomizers.py   # Grype field randomization
│       └── validators.py    # Grype schema validation
├── tests/
│   ├── __init__.py
│   ├── test_trivy_*         # Trivy format tests
│   ├── test_grype_*         # Grype format tests
│   ├── test_integration.py  # End-to-end integration tests
│   ├── test_performance.py  # Performance benchmarks
│   └── fixtures/
│       ├── sample_trivy.json
│       └── grype-golang-1.12-alpine.json
├── requirements.txt
├── setup.py
└── README.md
```

## Troubleshooting

### Common Issues

**Format Detection Fails**
```bash
# Manually specify the format
python -m src.main input.json -f trivy  # or -f grype
```

**Large File Generation**
```bash
# Use verbose logging to monitor progress
python -m src.main input.json -c 1000 -v
```

**Permission Errors**
```bash
# Ensure output directory is writable
python -m src.main input.json -o /tmp/output
```

### Debug Mode
```bash
# Enable debug logging for detailed troubleshooting
python -m src.main input.json --debug --log-file debug.log
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality (both unit and integration tests)
5. Ensure all tests pass (`python -m pytest`)
6. Test with both Trivy and Grype sample files
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to the branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions, issues, or contributions, please open an issue on the GitHub repository.
# Trivy Test Data Generator

A Python tool for generating randomized, synthetic test data based on Trivy JSON vulnerability reports.

## Overview

The Trivy Test Data Generator helps developers and QA engineers create diverse test datasets for security scan data ingestion systems. It takes a single Trivy JSON vulnerability report as input and generates multiple randomized versions while maintaining the original JSON schema structure.

## Features

- **Schema Preservation**: Maintains the exact JSON structure of the original Trivy report
- **Realistic Randomization**: Generates realistic vulnerability data including CVE IDs, package names, versions, and CVSS scores
- **Configurable Output**: Specify the number of files to generate
- **Performance Optimized**: Can generate 1,000 files in under 30 seconds
- **Extensible Architecture**: Modular design allows for easy extension to other scanner formats

## Installation

### From Source

```bash
git clone <repository-url>
cd trivy-test-data-generator
pip install -r requirements.txt
pip install -e .
```

### Using pip (when published)

```bash
pip install trivy-test-data-generator
```

### Python command line
```bash
python -m src.main
```
## Usage

### Command Line Interface

```bash
# Generate 10 randomized files (default)
trivy-test-generator input.json

# Generate 100 randomized files
trivy-test-generator input.json -c 100

# Specify output directory
trivy-test-generator input.json -c 50 -o /path/to/output

# Show help
trivy-test-generator --help
```

### Python API

```python
from src.generator import TrivyDataGenerator

# Initialize generator
generator = TrivyDataGenerator("input.json", "output_directory")

# Generate 25 randomized files
generated_files = generator.generate_files(25)

print(f"Generated {len(generated_files)} files")
```

## Randomized Fields

The tool randomizes the following fields while preserving the JSON schema:

### Root Level Fields
- `ArtifactName`: Container image names with realistic tags
- `Metadata.ImageID`: Docker image SHA256 hashes

### Vulnerability Fields
- `VulnerabilityID`: CVE identifiers in CVE-YYYY-XXXXX format
- `PkgName`: Package names from a curated list of common Linux packages
- `InstalledVersion` / `FixedVersion`: Realistic version strings
- `Severity`: Weighted distribution of severity levels
- `CVSS.V2Score` / `CVSS.V3Score`: Realistic CVSS scores (0.0-10.0)
- `PublishedDate` / `LastModifiedDate`: Random dates within the last 5 years

## Requirements

- Python 3.8+
- Faker library for realistic data generation

## Development

### Setup Development Environment

```bash
# Clone repository
git clone <repository-url>
cd trivy-test-data-generator

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

# Run specific test file
python -m pytest tests/test_generator.py
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
trivy-test-generator/
├── src/
│   ├── __init__.py
│   ├── main.py              # CLI entry point
│   ├── generator.py         # Core generation logic
│   ├── randomizers.py       # Field randomization functions
│   ├── validators.py        # JSON schema validation
│   └── utils.py            # Utility functions
├── tests/
│   ├── __init__.py
│   ├── test_generator.py
│   ├── test_randomizers.py
│   └── fixtures/
│       └── sample_trivy.json
├── requirements.txt
├── setup.py
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`python -m pytest`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions, issues, or contributions, please open an issue on the GitHub repository.
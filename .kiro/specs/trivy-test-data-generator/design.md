# Design Document

## Overview

The Trivy Test Data Generator is a Python command-line tool that creates randomized, synthetic vulnerability scan data based on an input Trivy JSON report. The tool maintains the original JSON schema while randomizing key fields to generate diverse test datasets for security scan data ingestion systems.

## Architecture

The system follows a modular architecture with clear separation of concerns:

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

## Components and Interfaces

### 1. CLI Interface (main.py)
**Purpose**: Command-line argument parsing and orchestration
**Interface**:
```python
def main():
    """Main CLI entry point"""
    
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    
def validate_inputs(args: argparse.Namespace) -> bool:
    """Validate input parameters"""
```

### 2. Core Generator (generator.py)
**Purpose**: Main generation logic and file operations
**Interface**:
```python
class TrivyDataGenerator:
    def __init__(self, input_file: str, output_dir: str):
        """Initialize generator with input file and output directory"""
    
    def generate_files(self, count: int) -> List[str]:
        """Generate specified number of randomized files"""
    
    def _load_template(self) -> Dict[str, Any]:
        """Load and parse input JSON template"""
    
    def _generate_single_file(self, template: Dict[str, Any], index: int) -> str:
        """Generate a single randomized file"""
```

### 3. Randomization Engine (randomizers.py)
**Purpose**: Field-specific randomization logic
**Interface**:
```python
class VulnerabilityRandomizer:
    def randomize_root_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Randomize ArtifactName and ImageID"""
    
    def randomize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Randomize vulnerability array entries and count"""
    
    def randomize_vulnerability_count(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Randomize the number of vulnerabilities (0-20)"""
    
    def _generate_cve_id(self) -> str:
        """Generate realistic CVE identifier"""
    
    def _generate_package_name(self) -> str:
        """Select random package name from predefined list"""
    
    def _generate_version(self) -> str:
        """Generate realistic version string"""
    
    def _generate_severity(self) -> str:
        """Select random severity level"""
    
    def _generate_cvss_score(self, version: str) -> float:
        """Generate realistic CVSS score"""
    
    def _generate_date(self) -> str:
        """Generate random date in ISO format"""
```

### 4. Validation Module (validators.py)
**Purpose**: JSON schema validation and integrity checks
**Interface**:
```python
class TrivyValidator:
    def validate_input_file(self, file_path: str) -> bool:
        """Validate input file is valid Trivy JSON"""
    
    def validate_generated_file(self, data: Dict[str, Any]) -> bool:
        """Validate generated file maintains schema"""
    
    def _check_required_fields(self, data: Dict[str, Any]) -> bool:
        """Check presence of required fields"""
```

## Data Models

### Trivy JSON Structure
Based on typical Trivy output format:

```json
{
  "SchemaVersion": 2,
  "ArtifactName": "string",
  "ArtifactType": "string", 
  "Metadata": {
    "ImageID": "string",
    "DiffIDs": ["string"],
    "RepoTags": ["string"],
    "RepoDigests": ["string"],
    "ImageConfig": {}
  },
  "Results": [
    {
      "Target": "string",
      "Class": "string",
      "Type": "string",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-YYYY-XXXXX",
          "PkgName": "string",
          "InstalledVersion": "string",
          "FixedVersion": "string",
          "Layer": {},
          "SeveritySource": "string",
          "PrimaryURL": "string",
          "DataSource": {},
          "Title": "string",
          "Description": "string",
          "Severity": "CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN",
          "CweIDs": ["string"],
          "CVSS": {
            "nvd": {
              "V2Vector": "string",
              "V3Vector": "string", 
              "V2Score": 0.0,
              "V3Score": 0.0
            }
          },
          "References": ["string"],
          "PublishedDate": "2023-01-01T00:00:00Z",
          "LastModifiedDate": "2023-01-01T00:00:00Z"
        }
      ]
    }
  ]
}
```

### Randomization Targets
Fields to be randomized while preserving structure:
- **Root Level**: ArtifactName, Metadata.ImageID
- **Vulnerability Count**: Number of vulnerabilities in the array (0-20 range)
- **Vulnerabilities**: VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Severity, CVSS scores, dates

### Data Sources
Predefined lists for realistic randomization:
- **Package Names**: busybox, apk-tools, openssl, curl, wget, bash, coreutils, etc.
- **Severity Levels**: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
- **Version Patterns**: semantic versioning (x.y.z), date-based, git hashes

## Error Handling

### Input Validation Errors
- Invalid JSON format
- Missing required fields
- Unsupported Trivy schema version
- File access permissions

### Generation Errors
- Output directory creation failures
- Disk space limitations
- JSON serialization errors
- Template corruption

### Error Response Strategy
```python
class TrivyGeneratorError(Exception):
    """Base exception for generator errors"""

class ValidationError(TrivyGeneratorError):
    """Input validation failures"""

class GenerationError(TrivyGeneratorError):
    """File generation failures"""
```

## Testing Strategy

### Unit Tests
- **Randomizer Functions**: Test each randomization function independently
- **Validation Logic**: Test schema validation with valid/invalid inputs
- **File Operations**: Test file I/O with mocked filesystem
- **CLI Parsing**: Test argument parsing with various input combinations

### Integration Tests
- **End-to-End Generation**: Test complete workflow with sample Trivy files
- **Performance Testing**: Verify 1,000 file generation under 30 seconds
- **Schema Preservation**: Validate generated files maintain original structure

### Test Data
- **Sample Trivy Files**: Multiple valid Trivy JSON examples
- **Edge Cases**: Minimal files, large files, various vulnerability counts
- **Invalid Inputs**: Malformed JSON, missing fields, wrong schema

### Performance Benchmarks
- **Generation Speed**: Target 1,000 files in <30 seconds
- **Memory Usage**: Monitor memory consumption during large batch generation
- **File Size Scaling**: Test with various input file sizes

## Implementation Considerations

### Randomization Quality
- Use cryptographically secure random number generation
- Ensure realistic data distributions (e.g., more MEDIUM/HIGH than CRITICAL)
- Maintain correlation between related fields (e.g., CVSS scores and severity)
- Randomize vulnerability count (0-20) to simulate varying scan results from different environments

### Performance Optimization
- Template caching to avoid repeated JSON parsing
- Batch file writing operations
- Memory-efficient processing for large vulnerability lists

### Extensibility
- Plugin architecture for supporting other scanner formats
- Configurable randomization rules via external files
- Custom field randomization functions

### Security Considerations
- Validate all file paths to prevent directory traversal
- Sanitize output filenames
- Limit output file count to prevent resource exhaustion
# Design Document

## Overview

The Grype Test Data Generator is a Python command-line tool that creates randomized, synthetic vulnerability scan data based on an input Grype JSON report. The tool maintains the original JSON schema while randomizing key fields to generate diverse test datasets for security scan data ingestion systems. Unlike Trivy's results-based format, Grype uses a matches-based structure with detailed artifact information and match details.

## Architecture

The system follows a modular architecture with clear separation of concerns, extending the existing codebase to support both Trivy and Grype formats through a shared base:

```
vulnerability-test-generator/
├── src/
│   ├── __init__.py
│   ├── main.py              # CLI entry point with format selection
│   ├── base/
│   │   ├── __init__.py
│   │   ├── generator.py     # Abstract base generator
│   │   ├── randomizer.py    # Base randomization utilities
│   │   ├── validator.py     # Base validation interface
│   │   └── utils.py         # Shared utility functions
│   ├── trivy/
│   │   ├── __init__.py
│   │   ├── generator.py     # Trivy-specific generator
│   │   ├── randomizers.py   # Trivy field randomization
│   │   └── validators.py    # Trivy schema validation
│   ├── grype/
│   │   ├── __init__.py
│   │   ├── generator.py     # Grype-specific generator
│   │   ├── randomizers.py   # Grype field randomization
│   │   └── validators.py    # Grype schema validation
│   └── exceptions.py        # Shared exception classes
├── tests/
│   ├── __init__.py
│   ├── test_base/
│   │   ├── test_generator.py
│   │   └── test_utils.py
│   ├── test_trivy/
│   │   ├── test_generator.py
│   │   └── test_randomizers.py
│   ├── test_grype/
│   │   ├── test_generator.py
│   │   └── test_randomizers.py
│   └── fixtures/
│       ├── sample_trivy.json
│       └── grype-golang-1.12-alpine.json
├── requirements.txt
├── setup.py
└── README.md
```

## Components and Interfaces

### 1. CLI Interface (main.py)
**Purpose**: Command-line argument parsing and format-specific orchestration
**Interface**:
```python
def main():
    """Main CLI entry point with format detection/selection"""
    
def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments including format specification"""
    
def detect_format(file_path: str) -> str:
    """Auto-detect scanner format from input file"""
    
def create_generator(format_type: str, input_file: str, output_dir: str) -> BaseGenerator:
    """Factory method to create format-specific generator"""
```

### 2. Base Generator (base/generator.py)
**Purpose**: Abstract base class defining common generation workflow
**Interface**:
```python
from abc import ABC, abstractmethod

class BaseGenerator(ABC):
    def __init__(self, input_file: str, output_dir: str):
        """Initialize generator with input file and output directory"""
    
    def generate_files(self, count: int) -> List[str]:
        """Template method for file generation workflow"""
    
    def _load_template(self) -> Dict[str, Any]:
        """Load and parse input JSON template"""
    
    def _generate_single_file(self, template: Dict[str, Any], index: int) -> str:
        """Generate a single randomized file using format-specific logic"""
    
    @abstractmethod
    def _randomize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format-specific data randomization - implemented by subclasses"""
    
    @abstractmethod
    def _validate_input(self, data: Dict[str, Any]) -> bool:
        """Format-specific input validation - implemented by subclasses"""
    
    @abstractmethod
    def _get_output_filename(self, index: int) -> str:
        """Format-specific output filename generation"""
```

### 3. Grype Generator (grype/generator.py)
**Purpose**: Grype-specific implementation of base generator
**Interface**:
```python
class GrypeDataGenerator(BaseGenerator):
    def __init__(self, input_file: str, output_dir: str):
        """Initialize Grype generator"""
        super().__init__(input_file, output_dir)
        self.randomizer = GrypeRandomizer()
        self.validator = GrypeValidator()
    
    def _randomize_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Implement Grype-specific randomization"""
    
    def _validate_input(self, data: Dict[str, Any]) -> bool:
        """Implement Grype-specific validation"""
    
    def _get_output_filename(self, index: int) -> str:
        """Generate Grype-specific output filename"""
```

### 4. Base Randomization (base/randomizer.py)
**Purpose**: Shared randomization utilities and common field generators
**Interface**:
```python
class BaseRandomizer:
    def __init__(self):
        """Initialize with common data sources"""
        self.package_names = ["zlib", "openssl", "curl", "busybox", "glibc"]
        self.cve_years = range(2018, 2025)
    
    def generate_cve_id(self) -> str:
        """Generate realistic CVE identifier"""
    
    def generate_version(self) -> str:
        """Generate realistic version string"""
    
    def generate_date(self, format_type: str = "iso") -> str:
        """Generate random date in specified format"""
    
    def generate_hash(self, length: int = 16) -> str:
        """Generate random hash string"""
    
    def select_random_from_list(self, items: List[str]) -> str:
        """Select random item from list"""
    
    def generate_cvss_score(self, min_score: float = 0.0, max_score: float = 10.0) -> float:
        """Generate realistic CVSS score within range"""
```

### 5. Grype Randomization Engine (grype/randomizers.py)
**Purpose**: Grype-specific field randomization logic
**Interface**:
```python
class GrypeRandomizer(BaseRandomizer):
    def __init__(self):
        """Initialize with Grype-specific data sources"""
        super().__init__()
        self.grype_severities = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"]
        self.matcher_types = ["apk-matcher", "java-matcher", "python-matcher", "go-module-matcher"]
        self.distro_types = ["alpine", "ubuntu", "debian", "centos", "rhel"]
        self.fix_states = ["fixed", "not-fixed", "wont-fix", "unknown"]
    
    def randomize_matches(self, matches: List[Dict]) -> List[Dict]:
        """Randomize matches array and count (1-50)"""
    
    def randomize_vulnerability(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Randomize vulnerability object fields"""
    
    def randomize_related_vulnerabilities(self, related: List[Dict]) -> List[Dict]:
        """Randomize related vulnerabilities array (0-5 per match)"""
    
    def randomize_match_details(self, match_details: List[Dict]) -> List[Dict]:
        """Randomize match details array"""
    
    def randomize_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """Randomize artifact information"""
    
    def _generate_grype_severity(self) -> str:
        """Select random Grype severity level"""
    
    def _generate_cvss_metrics(self) -> Dict[str, float]:
        """Generate realistic CVSS metrics"""
    
    def _generate_epss_data(self) -> Dict[str, Any]:
        """Generate realistic EPSS data"""
    
    def _generate_fix_info(self) -> Dict[str, Any]:
        """Generate fix information with versions and state"""
    
    def _generate_package_url(self, pkg_type: str, name: str, version: str) -> str:
        """Generate valid Package URL (PURL) format"""
    
    def _generate_matcher_type(self) -> str:
        """Select random matcher type"""
    
    def _generate_distro_info(self) -> Dict[str, str]:
        """Generate realistic distro information"""
    
    def _generate_vulnerability_description(self) -> str:
        """Generate realistic vulnerability description"""
```

### 6. Base Validation (base/validator.py)
**Purpose**: Abstract validation interface and common validation utilities
**Interface**:
```python
from abc import ABC, abstractmethod

class BaseValidator(ABC):
    def validate_input_file(self, file_path: str) -> bool:
        """Template method for input file validation"""
        data = self._load_json(file_path)
        return self._validate_schema(data)
    
    def validate_generated_file(self, data: Dict[str, Any]) -> bool:
        """Template method for generated file validation"""
        return self._validate_schema(data)
    
    def _load_json(self, file_path: str) -> Dict[str, Any]:
        """Load and parse JSON file"""
    
    @abstractmethod
    def _validate_schema(self, data: Dict[str, Any]) -> bool:
        """Format-specific schema validation"""
    
    @abstractmethod
    def _get_required_fields(self) -> List[str]:
        """Get list of required top-level fields"""
```

### 7. Grype Validation Module (grype/validators.py)
**Purpose**: Grype-specific JSON schema validation and integrity checks
**Interface**:
```python
class GrypeValidator(BaseValidator):
    def _validate_schema(self, data: Dict[str, Any]) -> bool:
        """Validate Grype-specific schema"""
    
    def _get_required_fields(self) -> List[str]:
        """Get required Grype fields"""
        return ["matches"]
    
    def _check_matches_structure(self, matches: List[Dict]) -> bool:
        """Validate matches array structure"""
    
    def _validate_purl_format(self, purl: str) -> bool:
        """Validate Package URL format"""
    
    def _validate_cvss_structure(self, cvss: List[Dict]) -> bool:
        """Validate CVSS array structure"""
```

## Data Models

### Grype JSON Structure
Based on Grype output format:

```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-YYYY-XXXXX",
        "dataSource": "string",
        "namespace": "string",
        "severity": "Critical|High|Medium|Low|Negligible|Unknown",
        "urls": ["string"],
        "cvss": [
          {
            "source": "string",
            "type": "Primary|Secondary",
            "version": "3.1",
            "vector": "string",
            "metrics": {
              "baseScore": 0.0,
              "exploitabilityScore": 0.0,
              "impactScore": 0.0
            },
            "vendorMetadata": {}
          }
        ],
        "epss": [
          {
            "cve": "CVE-YYYY-XXXXX",
            "epss": 0.0,
            "percentile": 0.0,
            "date": "YYYY-MM-DD"
          }
        ],
        "fix": {
          "versions": ["string"],
          "state": "fixed|not-fixed|wont-fix|unknown",
          "available": [
            {
              "version": "string",
              "date": "YYYY-MM-DD",
              "kind": "first-observed"
            }
          ]
        },
        "advisories": [],
        "risk": 0.0
      },
      "relatedVulnerabilities": [
        {
          "id": "CVE-YYYY-XXXXX",
          "dataSource": "string",
          "namespace": "string",
          "severity": "string",
          "urls": ["string"],
          "description": "string",
          "cvss": [],
          "epss": []
        }
      ],
      "matchDetails": [
        {
          "type": "exact-direct-match|exact-indirect-match",
          "matcher": "apk-matcher|java-matcher|etc",
          "searchedBy": {
            "distro": {
              "type": "alpine|ubuntu|etc",
              "version": "string"
            },
            "package": {
              "name": "string",
              "version": "string"
            },
            "namespace": "string"
          },
          "found": {
            "vulnerabilityID": "CVE-YYYY-XXXXX",
            "versionConstraint": "string"
          },
          "fix": {
            "suggestedVersion": "string"
          }
        }
      ],
      "artifact": {
        "id": "string",
        "name": "string",
        "version": "string",
        "type": "apk|deb|rpm|java-archive|etc",
        "locations": [
          {
            "path": "string",
            "layerID": "string",
            "accessPath": "string",
            "annotations": {
              "evidence": "primary|supporting"
            }
          }
        ],
        "language": "string",
        "licenses": ["string"],
        "cpes": ["string"],
        "purl": "pkg:type/namespace/name@version?qualifiers#subpath",
        "upstreams": [
          {
            "name": "string"
          }
        ],
        "metadataType": "string",
        "metadata": {}
      }
    }
  ]
}
```

### Randomization Targets
Fields to be randomized while preserving structure:
- **Match Count**: Number of matches in the array (1-50 range)
- **Vulnerability Data**: id, severity, cvss metrics, epss data, fix information
- **Related Vulnerabilities**: Count (0-5), ids, descriptions, severity
- **Match Details**: matcher types, distro information, version constraints
- **Artifact Data**: id, name, version, purl, locations, metadata

### Data Sources
Predefined lists for realistic randomization:
- **Package Names**: zlib, openssl, curl, busybox, glibc, libxml2, etc.
- **Severity Levels**: Critical, High, Medium, Low, Negligible, Unknown
- **Matcher Types**: apk-matcher, java-matcher, python-matcher, go-module-matcher
- **Distro Types**: alpine, ubuntu, debian, centos, rhel
- **Package Types**: apk, deb, rpm, java-archive, python, go-module
- **Fix States**: fixed, not-fixed, wont-fix, unknown

## Error Handling

### Input Validation Errors
- Invalid JSON format
- Missing required Grype fields
- Malformed PURL strings
- File access permissions

### Generation Errors
- Output directory creation failures
- Disk space limitations
- JSON serialization errors
- Template corruption

### Error Response Strategy
```python
class GrypeGeneratorError(Exception):
    """Base exception for generator errors"""

class ValidationError(GrypeGeneratorError):
    """Input validation failures"""

class GenerationError(GrypeGeneratorError):
    """File generation failures"""

class PURLFormatError(GrypeGeneratorError):
    """Package URL format errors"""
```

## Testing Strategy

### Unit Tests
- **Randomizer Functions**: Test each Grype-specific randomization function
- **PURL Generation**: Test Package URL format generation and validation
- **Validation Logic**: Test schema validation with valid/invalid Grype inputs
- **Match Details**: Test match detail randomization logic
- **CLI Parsing**: Test argument parsing with various input combinations

### Integration Tests
- **End-to-End Generation**: Test complete workflow with sample Grype files
- **Performance Testing**: Verify 1,000 file generation under 30 seconds
- **Schema Preservation**: Validate generated files maintain Grype structure
- **Cross-Format Compatibility**: Ensure generated files work with Grype consumers

### Test Data
- **Sample Grype Files**: Multiple valid Grype JSON examples from different scanners
- **Edge Cases**: Minimal matches, large match arrays, various artifact types
- **Invalid Inputs**: Malformed JSON, missing fields, invalid PURLs

### Performance Benchmarks
- **Generation Speed**: Target 1,000 files in <30 seconds
- **Memory Usage**: Monitor memory consumption during large batch generation
- **Complex Match Processing**: Test with files containing many related vulnerabilities

## Implementation Considerations

### Randomization Quality
- Use cryptographically secure random number generation
- Ensure realistic data distributions (more Medium/High than Critical)
- Maintain correlation between CVSS scores and severity levels
- Generate realistic EPSS scores and percentiles
- Randomize match count (1-50) to simulate varying scan results

### Grype-Specific Features
- **PURL Generation**: Create valid Package URL strings for different package types
- **Match Details**: Generate realistic matcher types and search criteria
- **Related Vulnerabilities**: Create meaningful relationships between CVEs
- **EPSS Integration**: Generate realistic Exploit Prediction Scoring System data
- **Fix Information**: Create coherent fix states and version suggestions

### Performance Optimization
- Template caching to avoid repeated JSON parsing
- Efficient deep copying for complex nested structures
- Memory-efficient processing for large match arrays
- Batch file writing operations

### Extensibility
- **Shared Base Architecture**: Common functionality extracted to base classes for reuse
- **Plugin Architecture**: Easy addition of new scanner formats by extending base classes
- **Format Auto-Detection**: Automatic detection of input file format (Trivy vs Grype)
- **Unified CLI**: Single command-line interface supporting multiple formats
- **Configurable Randomization**: External configuration files for customizing randomization rules
- **Custom Field Handlers**: Pluggable field randomization functions for specific use cases

### Migration Strategy
To implement this shared architecture:

1. **Extract Common Code**: Move shared functionality from existing Trivy generator to base classes
2. **Refactor Trivy Generator**: Update existing Trivy generator to extend base classes
3. **Implement Grype Generator**: Create Grype-specific implementations extending base classes
4. **Update CLI**: Modify main.py to support format detection and selection
5. **Unified Testing**: Create shared test utilities and format-specific test suites

### Security Considerations
- Validate all file paths to prevent directory traversal
- Sanitize output filenames
- Limit output file count to prevent resource exhaustion
- Validate PURL format to prevent injection attacks
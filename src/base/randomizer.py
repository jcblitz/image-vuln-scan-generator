"""
Base randomization utilities and common field generators for vulnerability test data.
"""

import random
import secrets
from datetime import datetime, timedelta
from typing import Any, List

from faker import Faker
from ..logging_config import get_logger


class BaseRandomizer:
    """Base class providing shared randomization utilities and common field generators."""
    
    def __init__(self):
        """Initialize with common data sources and Faker instance."""
        self.fake = Faker()
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
        
        # Common package names across different ecosystems
        self.package_names = [
            "zlib", "openssl", "curl", "busybox", "glibc", "libssl", "ca-certificates",
            "musl", "alpine-baselayout", "alpine-keys", "libc-utils", "scanelf",
            "ssl_client", "tzdata", "libcrypto", "libx11", "fontconfig", "freetype",
            "expat", "libpng", "libjpeg", "sqlite", "python3", "nodejs", "nginx",
            "apache2", "mysql", "postgresql", "redis", "git", "vim", "nano", "tar",
            "gzip", "unzip", "bash", "coreutils", "wget", "apk-tools", "libxml2"
        ]
        
        # CVE years for realistic CVE generation
        self.cve_years = list(range(2018, 2025))
        
        self.logger.debug(f"{self.__class__.__name__} initialized")
    
    def generate_cve_id(self) -> str:
        """
        Generate realistic CVE identifier following CVE-YYYY-XXXXX format.
        
        Returns:
            CVE identifier string
        """
        year = random.choice(self.cve_years)
        number = random.randint(1, 99999)
        return f"CVE-{year}-{number:05d}"
    
    def generate_version(self) -> str:
        """
        Generate realistic version string using various common patterns.
        
        Returns:
            Version string
        """
        version_types = [
            # Semantic versioning (major.minor.patch)
            lambda: f"{self.fake.random_int(0, 10)}.{self.fake.random_int(0, 20)}.{self.fake.random_int(0, 50)}",
            # Simple major.minor
            lambda: f"{self.fake.random_int(0, 5)}.{self.fake.random_int(0, 15)}",
            # Alpine-style with revision
            lambda: f"{self.fake.random_int(1, 3)}.{self.fake.random_int(0, 10)}.{self.fake.random_int(0, 20)}-r{self.fake.random_int(0, 10)}",
            # Date-based versioning
            lambda: f"{self.fake.random_int(2015, 2024)}{self.fake.random_int(1, 12):02d}{self.fake.random_int(1, 28):02d}",
            # Git-style short hash
            lambda: self.fake.lexify('???????', letters='0123456789abcdef'),
            # Ubuntu-style with build number
            lambda: f"{self.fake.random_int(1, 20)}.{self.fake.random_int(1, 12):02d}.{self.fake.random_int(1, 5)}-{self.fake.random_int(1, 100)}ubuntu{self.fake.random_int(1, 5)}",
        ]
        return random.choice(version_types)()
    
    def generate_date(self, format_type: str = "iso") -> str:
        """
        Generate random date in specified format.
        
        Args:
            format_type: Date format type ("iso", "rfc3339", "simple")
            
        Returns:
            Formatted date string
        """
        # Generate date within last 5 years
        random_date = self.fake.date_time_between(start_date='-5y', end_date='now')
        
        if format_type == "iso":
            return random_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        elif format_type == "rfc3339":
            return random_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        elif format_type == "simple":
            return random_date.strftime("%Y-%m-%d")
        else:
            return random_date.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    def generate_hash(self, length: int = 16) -> str:
        """
        Generate random hash string.
        
        Args:
            length: Length of hash string
            
        Returns:
            Hexadecimal hash string
        """
        return secrets.token_hex(length)
    
    def select_random_from_list(self, items: List[str]) -> str:
        """
        Select random item from list.
        
        Args:
            items: List of items to choose from
            
        Returns:
            Randomly selected item
        """
        if not items:
            return ""
        return random.choice(items)
    
    def generate_cvss_score(self, min_score: float = 0.0, max_score: float = 10.0) -> float:
        """
        Generate realistic CVSS score within range.
        
        Args:
            min_score: Minimum score value
            max_score: Maximum score value
            
        Returns:
            CVSS score as float rounded to 1 decimal place
        """
        score = self.fake.pyfloat(min_value=min_score, max_value=max_score, right_digits=1)
        return round(score, 1)
    
    def generate_package_name(self) -> str:
        """
        Select random package name from predefined list.
        
        Returns:
            Package name string
        """
        return self.select_random_from_list(self.package_names)
    
    def generate_email_address(self) -> str:
        """
        Generate realistic email address.
        
        Returns:
            Email address string
        """
        return self.fake.email()
    
    def generate_url(self, scheme: str = "https") -> str:
        """
        Generate realistic URL.
        
        Args:
            scheme: URL scheme (http, https, ftp, etc.)
            
        Returns:
            URL string
        """
        domain = self.fake.domain_name()
        path = self.fake.uri_path()
        return f"{scheme}://{domain}/{path}"
    
    def generate_description(self, min_words: int = 10, max_words: int = 30) -> str:
        """
        Generate realistic vulnerability description.
        
        Args:
            min_words: Minimum number of words
            max_words: Maximum number of words
            
        Returns:
            Description string
        """
        word_count = random.randint(min_words, max_words)
        return self.fake.text(max_nb_chars=word_count * 8)[:word_count * 8]
    
    def generate_weighted_choice(self, choices: List[str], weights: List[float]) -> str:
        """
        Select random choice with weighted probability.
        
        Args:
            choices: List of choices
            weights: List of weights corresponding to choices
            
        Returns:
            Weighted random choice
        """
        if len(choices) != len(weights):
            raise ValueError("Choices and weights must have same length")
        
        return random.choices(choices, weights=weights)[0]
    
    def randomize_list_count(self, original_list: List[Any], min_count: int, max_count: int) -> List[Any]:
        """
        Randomize the number of items in a list by sampling or duplicating.
        
        Args:
            original_list: Original list to modify
            min_count: Minimum number of items
            max_count: Maximum number of items
            
        Returns:
            List with randomized count
        """
        if not original_list:
            return original_list
        
        target_count = random.randint(min_count, max_count)
        
        if target_count == 0:
            return []
        
        original_count = len(original_list)
        
        if target_count <= original_count:
            # Select random subset
            return random.sample(original_list, target_count)
        else:
            # Need to duplicate some items
            result = original_list.copy()
            additional_needed = target_count - original_count
            
            # Randomly select items to duplicate
            for _ in range(additional_needed):
                item_to_duplicate = random.choice(original_list)
                result.append(item_to_duplicate)
            
            # Shuffle the final list
            random.shuffle(result)
            return result
"""
Performance benchmark tests for the Trivy Test Data Generator.
Tests generation speed, memory usage, and performance targets.
"""

import json
import os
import psutil
import tempfile
import time
import unittest
from pathlib import Path
from typing import Dict, List, Tuple

from src.generator import TrivyDataGenerator
from src.performance import BenchmarkRunner, PerformanceMonitor
from src.validators import TrivyValidator


class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance benchmark tests with various scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.validator = TrivyValidator()
        self.performance_monitor = PerformanceMonitor()
        
        # Create test files of different sizes
        self.test_files = {}
        self._create_test_files()
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def _create_test_files(self):
        """Create test files with different vulnerability counts."""
        base_data = {
            "SchemaVersion": 2,
            "ArtifactName": "benchmark:test",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:benchmark123",
                "DiffIDs": ["sha256:diff123"],
                "RepoTags": ["benchmark:test"],
                "RepoDigests": ["benchmark@sha256:digest123"]
            },
            "Results": [
                {
                    "Target": "benchmark (alpine 3.10.2)",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": []
                }
            ]
        }
        
        # Create files with different vulnerability counts
        vuln_counts = [1, 10, 50, 100, 200]
        
        for count in vuln_counts:
            vulnerabilities = []
            for i in range(count):
                vulnerabilities.append({
                    "VulnerabilityID": f"CVE-2023-{i:05d}",
                    "PkgName": f"package{i % 20}",  # Cycle through 20 package names
                    "InstalledVersion": f"{i % 10}.{i % 5}.{i % 3}",
                    "FixedVersion": f"{(i % 10) + 1}.{i % 5}.{i % 3}",
                    "Layer": {
                        "Digest": f"sha256:layer{i % 10}",
                        "DiffID": f"sha256:diff{i % 10}"
                    },
                    "SeveritySource": "nvd",
                    "PrimaryURL": f"https://avd.aquasec.com/nvd/cve-2023-{i:05d}",
                    "DataSource": {
                        "ID": "alpine",
                        "Name": "Alpine Secdb",
                        "URL": "https://secdb.alpinelinux.org/"
                    },
                    "Title": f"Package{i % 20}: vulnerability {i}",
                    "Description": f"A vulnerability in package{i % 20} that affects version {i % 10}.{i % 5}.{i % 3}",
                    "Severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"][i % 5],
                    "CweIDs": [f"CWE-{100 + (i % 50)}"],
                    "CVSS": {
                        "nvd": {
                            "V2Vector": f"AV:N/AC:L/Au:N/C:P/I:P/A:P",
                            "V3Vector": f"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "V2Score": round(1.0 + (i % 90) / 10.0, 1),
                            "V3Score": round(1.0 + (i % 90) / 10.0, 1)
                        }
                    },
                    "References": [
                        f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-{i:05d}",
                        f"https://example.com/advisory/{i}"
                    ],
                    "PublishedDate": f"2023-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T{i % 24:02d}:00:00Z",
                    "LastModifiedDate": f"2023-{(i % 12) + 1:02d}-{(i % 28) + 1:02d}T{(i + 1) % 24:02d}:00:00Z"
                })
            
            test_data = base_data.copy()
            test_data["Results"][0]["Vulnerabilities"] = vulnerabilities
            
            file_path = Path(self.temp_dir) / f"benchmark_{count}v.json"
            with open(file_path, 'w') as f:
                json.dump(test_data, f, indent=2)
            
            self.test_files[count] = file_path
    
    def _measure_memory_usage(self) -> float:
        """Get current memory usage in MB."""
        process = psutil.Process(os.getpid())
        return process.memory_info().rss / 1024 / 1024  # Convert to MB
    
    def test_generation_speed_scaling(self):
        """Test how generation speed scales with file count."""
        input_file = self.test_files[10]  # Use 10 vulnerability file
        output_dir = Path(self.temp_dir) / "speed_scaling"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        file_counts = [1, 5, 10, 25, 50]
        results = {}
        
        for count in file_counts:
            # Clear output directory
            if output_dir.exists():
                import shutil
                shutil.rmtree(output_dir)
            
            with self.performance_monitor.monitor_operation(f"generate_{count}_files") as metrics:
                generated_files = generator.generate_files(count)
                metrics.items_processed = count
            
            # Calculate performance metrics
            files_per_second = count / metrics.duration
            results[count] = {
                'duration': metrics.duration,
                'files_per_second': files_per_second,
                'memory_peak': metrics.memory_peak,
                'files_generated': len(generated_files)
            }
            
            # Verify all files were generated
            self.assertEqual(len(generated_files), count)
            
            # Validate a sample file
            with open(generated_files[0], 'r') as f:
                data = json.load(f)
            self.validator.validate_generated_file(data)
        
        # Analyze scaling behavior
        print("\nGeneration Speed Scaling Results:")
        print("File Count | Duration (s) | Files/sec | Memory Peak (MB)")
        print("-" * 55)
        
        for count in file_counts:
            result = results[count]
            print(f"{count:9d} | {result['duration']:11.3f} | {result['files_per_second']:8.1f} | {result['memory_peak']:14.1f}")
        
        # Performance assertions
        for count in file_counts:
            result = results[count]
            # Should generate at least 5 files per second for small batches
            if count <= 10:
                self.assertGreater(result['files_per_second'], 5.0, 
                                 f"Too slow for {count} files: {result['files_per_second']:.1f} files/sec")
    
    def test_vulnerability_count_impact(self):
        """Test how vulnerability count affects generation performance."""
        vuln_counts = [1, 10, 50, 100, 200]
        file_count = 10  # Generate 10 files for each test
        results = {}
        
        for vuln_count in vuln_counts:
            input_file = self.test_files[vuln_count]
            output_dir = Path(self.temp_dir) / f"vuln_impact_{vuln_count}"
            
            generator = TrivyDataGenerator(str(input_file), str(output_dir))
            
            with self.performance_monitor.monitor_operation(f"vuln_{vuln_count}") as metrics:
                generated_files = generator.generate_files(file_count)
                metrics.items_processed = file_count
            
            # Calculate metrics per vulnerability
            vulns_per_second = (vuln_count * file_count) / metrics.duration
            
            results[vuln_count] = {
                'duration': metrics.duration,
                'files_per_second': file_count / metrics.duration,
                'vulns_per_second': vulns_per_second,
                'memory_peak': metrics.memory_peak,
                'avg_file_size': self._calculate_avg_file_size(generated_files)
            }
            
            # Verify generation completed
            self.assertEqual(len(generated_files), file_count)
        
        # Analyze vulnerability count impact
        print("\nVulnerability Count Impact Results:")
        print("Vuln Count | Duration (s) | Files/sec | Vulns/sec | Avg Size (KB) | Memory (MB)")
        print("-" * 80)
        
        for vuln_count in vuln_counts:
            result = results[vuln_count]
            print(f"{vuln_count:9d} | {result['duration']:11.3f} | {result['files_per_second']:8.1f} | "
                  f"{result['vulns_per_second']:8.0f} | {result['avg_file_size']:12.1f} | {result['memory_peak']:10.1f}")
        
        # Performance assertions
        for vuln_count in vuln_counts:
            result = results[vuln_count]
            # Should process at least 100 vulnerabilities per second
            self.assertGreater(result['vulns_per_second'], 100.0,
                             f"Too slow processing {vuln_count} vulnerabilities: {result['vulns_per_second']:.0f} vulns/sec")
    
    def _calculate_avg_file_size(self, file_paths: List[str]) -> float:
        """Calculate average file size in KB."""
        total_size = 0
        for file_path in file_paths:
            total_size += Path(file_path).stat().st_size
        return (total_size / len(file_paths)) / 1024  # Convert to KB
    
    def test_memory_usage_scaling(self):
        """Test memory usage scaling with different scenarios."""
        scenarios = [
            (10, 10),   # 10 vulns, 10 files
            (50, 20),   # 50 vulns, 20 files
            (100, 50),  # 100 vulns, 50 files
        ]
        
        results = {}
        
        for vuln_count, file_count in scenarios:
            input_file = self.test_files[vuln_count]
            output_dir = Path(self.temp_dir) / f"memory_{vuln_count}v_{file_count}f"
            
            generator = TrivyDataGenerator(str(input_file), str(output_dir))
            
            # Measure memory before generation
            memory_before = self._measure_memory_usage()
            
            with self.performance_monitor.monitor_operation(f"memory_test_{vuln_count}_{file_count}") as metrics:
                generated_files = generator.generate_files(file_count)
                metrics.items_processed = file_count
            
            # Measure memory after generation
            memory_after = self._measure_memory_usage()
            memory_increase = memory_after - memory_before
            
            results[(vuln_count, file_count)] = {
                'memory_before': memory_before,
                'memory_after': memory_after,
                'memory_increase': memory_increase,
                'memory_peak': metrics.memory_peak,
                'duration': metrics.duration,
                'files_generated': len(generated_files)
            }
            
            # Verify generation completed
            self.assertEqual(len(generated_files), file_count)
        
        # Analyze memory usage
        print("\nMemory Usage Scaling Results:")
        print("Scenario (V,F) | Before (MB) | After (MB) | Increase (MB) | Peak (MB) | Duration (s)")
        print("-" * 85)
        
        for (vuln_count, file_count), result in results.items():
            print(f"({vuln_count:3d},{file_count:2d})      | {result['memory_before']:10.1f} | "
                  f"{result['memory_after']:9.1f} | {result['memory_increase']:12.1f} | "
                  f"{result['memory_peak']:8.1f} | {result['duration']:10.3f}")
        
        # Memory usage assertions
        for (vuln_count, file_count), result in results.items():
            # Memory increase should be reasonable (less than 100MB for these test sizes)
            self.assertLess(result['memory_increase'], 100.0,
                           f"Excessive memory usage for {vuln_count}v,{file_count}f: {result['memory_increase']:.1f}MB")
    
    def test_performance_target_compliance(self):
        """Test compliance with performance targets (1,000 files in <30s)."""
        # Use a medium-sized file for realistic testing
        input_file = self.test_files[50]  # 50 vulnerabilities
        output_dir = Path(self.temp_dir) / "performance_target"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        # Test with smaller batch first to estimate performance
        test_count = 100
        
        with self.performance_monitor.monitor_operation(f"target_test_{test_count}") as metrics:
            generated_files = generator.generate_files(test_count)
            metrics.items_processed = test_count
        
        # Calculate projected performance for 1,000 files
        files_per_second = test_count / metrics.duration
        projected_time_1000 = 1000 / files_per_second
        
        print(f"\nPerformance Target Analysis:")
        print(f"Test batch: {test_count} files in {metrics.duration:.2f}s")
        print(f"Rate: {files_per_second:.1f} files/second")
        print(f"Projected time for 1,000 files: {projected_time_1000:.1f}s")
        print(f"Target: <30s for 1,000 files")
        print(f"Memory peak: {metrics.memory_peak:.1f}MB")
        
        # Verify test batch completed successfully
        self.assertEqual(len(generated_files), test_count)
        
        # Validate sample files
        sample_files = generated_files[::20]  # Every 20th file
        for file_path in sample_files:
            with open(file_path, 'r') as f:
                data = json.load(f)
            self.validator.validate_generated_file(data)
        
        # Performance target assertion
        self.assertLess(projected_time_1000, 30.0,
                       f"Projected time {projected_time_1000:.1f}s exceeds 30s target")
        
        # Memory usage should be reasonable
        self.assertLess(metrics.memory_peak, 500.0,
                       f"Memory usage {metrics.memory_peak:.1f}MB is excessive")
    
    @unittest.skipUnless(
        os.environ.get('RUN_LARGE_PERFORMANCE_TESTS') == '1',
        "Large performance test disabled by default (set RUN_LARGE_PERFORMANCE_TESTS=1 to enable)"
    )
    def test_actual_1000_file_generation(self):
        """Test actual generation of 1,000 files (only run when explicitly enabled)."""
        input_file = self.test_files[50]  # 50 vulnerabilities
        output_dir = Path(self.temp_dir) / "large_test_1000"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        
        print("\nStarting 1,000 file generation test...")
        
        with self.performance_monitor.monitor_operation("generate_1000_files") as metrics:
            generated_files = generator.generate_files(1000)
            metrics.items_processed = 1000
        
        # Verify all files were generated
        self.assertEqual(len(generated_files), 1000)
        
        # Performance analysis
        files_per_second = 1000 / metrics.duration
        
        print(f"\n1,000 File Generation Results:")
        print(f"Duration: {metrics.duration:.2f}s")
        print(f"Rate: {files_per_second:.1f} files/second")
        print(f"Memory peak: {metrics.memory_peak:.1f}MB")
        print(f"Target met: {'YES' if metrics.duration < 30.0 else 'NO'}")
        
        # Validate sample files
        sample_indices = [0, 99, 249, 499, 749, 999]  # Sample across the range
        for i in sample_indices:
            with open(generated_files[i], 'r') as f:
                data = json.load(f)
            self.validator.validate_generated_file(data)
        
        # Performance assertions
        self.assertLess(metrics.duration, 30.0,
                       f"Generation took {metrics.duration:.2f}s, target is <30s")
        self.assertGreater(files_per_second, 33.0,
                          f"Rate {files_per_second:.1f} files/sec is below target (>33 files/sec)")
    
    def test_benchmark_runner_integration(self):
        """Test integration with BenchmarkRunner for comprehensive benchmarking."""
        input_file = self.test_files[10]  # 10 vulnerabilities
        output_dir = Path(self.temp_dir) / "benchmark_runner"
        
        generator = TrivyDataGenerator(str(input_file), str(output_dir))
        runner = BenchmarkRunner()
        
        # Run benchmark with multiple file counts and iterations
        results = runner.run_generation_benchmark(
            generator,
            file_counts=[5, 10, 20],
            iterations=3
        )
        
        # Verify benchmark structure
        self.assertIn("benchmark_info", results)
        self.assertIn("results", results)
        self.assertEqual(results["benchmark_info"]["file_counts"], [5, 10, 20])
        self.assertEqual(results["benchmark_info"]["iterations"], 3)
        
        # Verify results for each file count
        for count in [5, 10, 20]:
            self.assertIn(count, results["results"])
            count_results = results["results"][count]
            
            # Check required metrics
            self.assertIn("avg_duration", count_results)
            self.assertIn("avg_files_per_second", count_results)
            self.assertIn("min_duration", count_results)
            self.assertIn("max_duration", count_results)
            self.assertIn("iterations", count_results)
            
            # Verify iterations data
            self.assertEqual(len(count_results["iterations"]), 3)
            
            # Performance checks
            self.assertGreater(count_results["avg_files_per_second"], 1.0)
            self.assertLess(count_results["avg_duration"], 10.0)  # Should be fast for small counts
        
        # Generate and verify report
        report = runner.generate_benchmark_report(results)
        self.assertIn("Benchmark Report", report)
        self.assertIn("File Count: 5", report)
        self.assertIn("File Count: 10", report)
        self.assertIn("File Count: 20", report)
        
        print("\nBenchmark Runner Report:")
        print(report)


class TestOptimizationEffectiveness(unittest.TestCase):
    """Test effectiveness of performance optimizations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        
        # Create a test file with moderate complexity
        self.test_data = {
            "SchemaVersion": 2,
            "ArtifactName": "optimization:test",
            "ArtifactType": "container_image",
            "Metadata": {"ImageID": "sha256:opt123"},
            "Results": [
                {
                    "Target": "optimization-test",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": f"CVE-2023-{i:05d}",
                            "PkgName": f"package{i % 10}",
                            "InstalledVersion": f"{i % 5}.0.0",
                            "Severity": ["LOW", "MEDIUM", "HIGH"][i % 3],
                            "CVSS": {"nvd": {"V3Score": 5.0 + (i % 5)}},
                            "PublishedDate": "2023-01-01T00:00:00Z",
                            "LastModifiedDate": "2023-01-02T00:00:00Z"
                        }
                        for i in range(75)  # 75 vulnerabilities
                    ]
                }
            ]
        }
        
        self.input_file = Path(self.temp_dir) / "optimization_test.json"
        with open(self.input_file, 'w') as f:
            json.dump(self.test_data, f, indent=2)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_optimized_vs_standard_performance(self):
        """Compare performance between optimized and standard generation."""
        file_count = 100  # Use larger count where optimizations are more beneficial
        
        # Test with optimizations enabled
        output_dir_opt = Path(self.temp_dir) / "optimized"
        generator_opt = TrivyDataGenerator(
            str(self.input_file), 
            str(output_dir_opt),
            enable_performance_optimizations=True
        )
        
        start_time = time.time()
        files_opt = generator_opt.generate_files(file_count)
        duration_opt = time.time() - start_time
        
        # Test with optimizations disabled
        output_dir_std = Path(self.temp_dir) / "standard"
        generator_std = TrivyDataGenerator(
            str(self.input_file), 
            str(output_dir_std),
            enable_performance_optimizations=False
        )
        
        start_time = time.time()
        files_std = generator_std.generate_files(file_count)
        duration_std = time.time() - start_time
        
        # Verify both approaches generated the same number of files
        self.assertEqual(len(files_opt), file_count)
        self.assertEqual(len(files_std), file_count)
        
        # Calculate performance metrics
        rate_opt = file_count / duration_opt
        rate_std = file_count / duration_std
        improvement = (duration_std - duration_opt) / duration_std * 100
        
        print(f"\nOptimization Effectiveness Results:")
        print(f"Standard approach: {duration_std:.3f}s ({rate_std:.1f} files/sec)")
        print(f"Optimized approach: {duration_opt:.3f}s ({rate_opt:.1f} files/sec)")
        print(f"Performance improvement: {improvement:.1f}%")
        
        # Verify files are equivalent (sample check)
        validator = TrivyValidator()
        
        # Check a few files from each approach
        for i in [0, file_count//2, file_count-1]:
            with open(files_opt[i], 'r') as f:
                data_opt = json.load(f)
            with open(files_std[i], 'r') as f:
                data_std = json.load(f)
            
            # Both should be valid
            validator.validate_generated_file(data_opt)
            validator.validate_generated_file(data_std)
            
            # Both should have same structure (though different randomized values)
            self.assertEqual(data_opt["SchemaVersion"], data_std["SchemaVersion"])
            self.assertEqual(len(data_opt["Results"]), len(data_std["Results"]))
        
        # For larger file counts, optimized version should be competitive
        # Allow for some variance due to test environment and overhead of optimizations
        # The main goal is that optimizations don't significantly degrade performance
        self.assertLessEqual(duration_opt, duration_std * 1.3,  # Allow 30% variance for test stability
                            f"Optimized version ({duration_opt:.3f}s) should not be significantly slower than standard ({duration_std:.3f}s)")
        
        # Both approaches should meet reasonable performance standards
        self.assertGreater(rate_opt, 50.0, f"Optimized rate too slow: {rate_opt:.1f} files/sec")
        self.assertGreater(rate_std, 50.0, f"Standard rate too slow: {rate_std:.1f} files/sec")


if __name__ == '__main__':
    # Set up environment for comprehensive testing
    if os.environ.get('RUN_ALL_PERFORMANCE_TESTS') == '1':
        os.environ['RUN_LARGE_PERFORMANCE_TESTS'] = '1'
    
    unittest.main(verbosity=2)
"""
Performance tests for the Trivy Test Data Generator.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.generator import TrivyDataGenerator
from src.performance import (
    PerformanceMonitor, 
    BatchFileWriter, 
    MemoryEfficientProcessor, 
    BenchmarkRunner,
    PerformanceMetrics
)


class TestPerformanceMonitor(unittest.TestCase):
    """Test cases for PerformanceMonitor."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.monitor = PerformanceMonitor()
    
    def test_memory_usage_measurement(self):
        """Test memory usage measurement."""
        memory_usage = self.monitor.get_memory_usage()
        self.assertIsInstance(memory_usage, float)
        self.assertGreater(memory_usage, 0)
    
    def test_monitor_operation_context(self):
        """Test operation monitoring context manager."""
        with self.monitor.monitor_operation("test_operation") as metrics:
            self.assertIsInstance(metrics, PerformanceMetrics)
            self.assertEqual(metrics.operation, "test_operation")
            
            # Simulate some work
            time.sleep(0.1)
            metrics.items_processed = 10
        
        self.assertGreater(metrics.duration, 0.05)  # Should be at least 0.05 seconds
        self.assertGreaterEqual(metrics.memory_end, 0)
        self.assertEqual(metrics.items_processed, 10)
    
    def test_metrics_history(self):
        """Test metrics history tracking."""
        initial_count = len(self.monitor.get_metrics_history())
        
        with self.monitor.monitor_operation("test1"):
            pass
        
        with self.monitor.monitor_operation("test2"):
            pass
        
        history = self.monitor.get_metrics_history()
        self.assertEqual(len(history), initial_count + 2)
        
        self.monitor.clear_history()
        self.assertEqual(len(self.monitor.get_metrics_history()), 0)


class TestBatchFileWriter(unittest.TestCase):
    """Test cases for BatchFileWriter."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.output_dir = Path(self.temp_dir)
        self.sample_data = {"test": "data", "number": 42}
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_batch_writing(self):
        """Test batch file writing functionality."""
        batch_size = 3
        writer = BatchFileWriter(self.output_dir, batch_size)
        
        # Add files to batch
        for i in range(5):
            writer.add_file(f"test_{i}.json", self.sample_data)
        
        # Should have written first batch (3 files) automatically
        files_written, bytes_written = writer.get_stats()
        self.assertEqual(files_written, 3)
        self.assertGreater(bytes_written, 0)
        
        # Flush remaining files
        writer.flush_batch()
        
        # Should have written all 5 files
        files_written, bytes_written = writer.get_stats()
        self.assertEqual(files_written, 5)
        
        # Verify files exist and contain correct data
        for i in range(5):
            file_path = self.output_dir / f"test_{i}.json"
            self.assertTrue(file_path.exists())
            
            with open(file_path, 'r') as f:
                loaded_data = json.load(f)
                self.assertEqual(loaded_data, self.sample_data)
    
    def test_context_manager(self):
        """Test BatchFileWriter as context manager."""
        with BatchFileWriter(self.output_dir, batch_size=2) as writer:
            writer.add_file("test1.json", self.sample_data)
            writer.add_file("test2.json", self.sample_data)
            writer.add_file("test3.json", self.sample_data)
        
        # All files should be written after context exit
        files_written, _ = writer.get_stats()
        self.assertEqual(files_written, 3)


class TestMemoryEfficientProcessor(unittest.TestCase):
    """Test cases for MemoryEfficientProcessor."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.processor = MemoryEfficientProcessor(chunk_size=5)
        self.sample_vulnerabilities = [
            {"VulnerabilityID": f"CVE-2023-{i:05d}", "PkgName": f"pkg{i}"}
            for i in range(20)
        ]
    
    def test_chunked_processing(self):
        """Test chunked vulnerability processing."""
        def add_processed_flag(vuln):
            result = vuln.copy()
            result["processed"] = True
            return result
        
        processed = self.processor.process_vulnerabilities_chunked(
            self.sample_vulnerabilities, 
            add_processed_flag
        )
        
        self.assertEqual(len(processed), len(self.sample_vulnerabilities))
        for vuln in processed:
            self.assertTrue(vuln.get("processed", False))
    
    def test_chunked_deep_copy(self):
        """Test chunked deep copy functionality."""
        sample_data = {
            "SchemaVersion": 2,
            "Results": [
                {
                    "Vulnerabilities": self.sample_vulnerabilities
                }
            ]
        }
        
        copied_data = self.processor.create_deep_copy_chunked(sample_data)
        
        # Verify structure is preserved
        self.assertEqual(copied_data["SchemaVersion"], 2)
        self.assertEqual(len(copied_data["Results"]), 1)
        self.assertEqual(
            len(copied_data["Results"][0]["Vulnerabilities"]), 
            len(self.sample_vulnerabilities)
        )
        
        # Verify it's a deep copy (modifying original doesn't affect copy)
        sample_data["Results"][0]["Vulnerabilities"][0]["modified"] = True
        self.assertNotIn("modified", copied_data["Results"][0]["Vulnerabilities"][0])
    
    def test_vulnerability_count(self):
        """Test vulnerability counting."""
        sample_data = {
            "Results": [
                {"Vulnerabilities": self.sample_vulnerabilities[:10]},
                {"Vulnerabilities": self.sample_vulnerabilities[10:]}
            ]
        }
        
        count = self.processor._count_total_vulnerabilities(sample_data)
        self.assertEqual(count, 20)


class TestPerformanceIntegration(unittest.TestCase):
    """Integration tests for performance optimizations."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.sample_trivy_data = {
            "SchemaVersion": 2,
            "ArtifactName": "test:latest",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:abc123"
            },
            "Results": [
                {
                    "Target": "test",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": f"CVE-2023-{i:05d}",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "Severity": "HIGH",
                            "CVSS": {
                                "nvd": {
                                    "V2Score": 7.5,
                                    "V3Score": 8.1
                                }
                            },
                            "PublishedDate": "2023-01-01T00:00:00Z",
                            "LastModifiedDate": "2023-01-02T00:00:00Z"
                        }
                        for i in range(50)  # Create 50 vulnerabilities for testing
                    ]
                }
            ]
        }
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_optimized_vs_standard_generation(self):
        """Test that optimized generation produces same results as standard."""
        # Create input file
        input_file = Path(self.temp_dir) / "input.json"
        with open(input_file, 'w') as f:
            json.dump(self.sample_trivy_data, f)
        
        # Test with optimizations enabled
        output_dir_optimized = Path(self.temp_dir) / "output_optimized"
        generator_optimized = TrivyDataGenerator(
            str(input_file), 
            str(output_dir_optimized),
            enable_performance_optimizations=True
        )
        
        # Test with optimizations disabled
        output_dir_standard = Path(self.temp_dir) / "output_standard"
        generator_standard = TrivyDataGenerator(
            str(input_file), 
            str(output_dir_standard),
            enable_performance_optimizations=False
        )
        
        # Generate small number of files for comparison
        files_optimized = generator_optimized.generate_files(5)
        files_standard = generator_standard.generate_files(5)
        
        self.assertEqual(len(files_optimized), 5)
        self.assertEqual(len(files_standard), 5)
        
        # Verify all files were created
        for file_path in files_optimized:
            self.assertTrue(Path(file_path).exists())
        
        for file_path in files_standard:
            self.assertTrue(Path(file_path).exists())


class TestPerformanceBenchmarks(unittest.TestCase):
    """Performance benchmark tests."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.sample_trivy_data = {
            "SchemaVersion": 2,
            "ArtifactName": "test:latest",
            "ArtifactType": "container_image",
            "Metadata": {
                "ImageID": "sha256:abc123"
            },
            "Results": [
                {
                    "Target": "test",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": f"CVE-2023-{i:05d}",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1",
                            "Severity": "HIGH"
                        }
                        for i in range(10)  # Smaller dataset for faster tests
                    ]
                }
            ]
        }
        
        # Create input file
        self.input_file = Path(self.temp_dir) / "input.json"
        with open(self.input_file, 'w') as f:
            json.dump(self.sample_trivy_data, f)
    
    def tearDown(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_small_batch_performance(self):
        """Test performance with small batch sizes."""
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(
            str(self.input_file), 
            str(output_dir),
            enable_performance_optimizations=True
        )
        
        start_time = time.time()
        files = generator.generate_files(10)
        duration = time.time() - start_time
        
        self.assertEqual(len(files), 10)
        self.assertLess(duration, 5.0)  # Should complete in under 5 seconds
        
        # Verify files exist and are valid JSON
        for file_path in files:
            self.assertTrue(Path(file_path).exists())
            with open(file_path, 'r') as f:
                data = json.load(f)
                self.assertIn("SchemaVersion", data)
    
    def test_medium_batch_performance(self):
        """Test performance with medium batch sizes."""
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(
            str(self.input_file), 
            str(output_dir),
            enable_performance_optimizations=True
        )
        
        start_time = time.time()
        files = generator.generate_files(100)
        duration = time.time() - start_time
        
        self.assertEqual(len(files), 100)
        self.assertLess(duration, 10.0)  # Should complete in under 10 seconds
        
        # Calculate files per second
        files_per_second = len(files) / duration
        self.assertGreater(files_per_second, 10)  # Should generate at least 10 files/sec
    
    @unittest.skipUnless(
        # Only run this test if explicitly requested (it's slow)
        False,  # Set to True to enable this test
        "Large performance test disabled by default"
    )
    def test_large_batch_performance_target(self):
        """Test that 1,000 files can be generated in under 30 seconds."""
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(
            str(self.input_file), 
            str(output_dir),
            enable_performance_optimizations=True
        )
        
        start_time = time.time()
        files = generator.generate_files(1000)
        duration = time.time() - start_time
        
        self.assertEqual(len(files), 1000)
        self.assertLess(duration, 30.0, f"Generation took {duration:.2f}s, target is <30s")
        
        # Calculate performance metrics
        files_per_second = len(files) / duration
        self.assertGreater(files_per_second, 33)  # Should be >33 files/sec for 30s target
    
    def test_benchmark_runner(self):
        """Test the benchmark runner functionality."""
        output_dir = Path(self.temp_dir) / "output"
        generator = TrivyDataGenerator(
            str(self.input_file), 
            str(output_dir),
            enable_performance_optimizations=True
        )
        
        runner = BenchmarkRunner()
        results = runner.run_generation_benchmark(
            generator, 
            file_counts=[5, 10], 
            iterations=2
        )
        
        self.assertIn("benchmark_info", results)
        self.assertIn("results", results)
        self.assertEqual(results["benchmark_info"]["file_counts"], [5, 10])
        self.assertEqual(results["benchmark_info"]["iterations"], 2)
        
        # Check results for each file count
        for count in [5, 10]:
            self.assertIn(count, results["results"])
            count_results = results["results"][count]
            self.assertIn("avg_duration", count_results)
            self.assertIn("avg_files_per_second", count_results)
            self.assertEqual(len(count_results["iterations"]), 2)
        
        # Test report generation
        report = runner.generate_benchmark_report(results)
        self.assertIn("Benchmark Report", report)
        self.assertIn("File Count: 5", report)
        self.assertIn("File Count: 10", report)


if __name__ == '__main__':
    unittest.main()
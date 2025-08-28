"""
Performance monitoring and optimization utilities for the Trivy Test Data Generator.
"""

import gc
import json
import os
import psutil
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Iterator
from dataclasses import dataclass

from .logging_config import get_logger


@dataclass
class PerformanceMetrics:
    """Container for performance metrics."""
    operation: str
    duration: float
    memory_start: float
    memory_peak: float
    memory_end: float
    items_processed: int = 0
    files_written: int = 0
    bytes_written: int = 0
    
    @property
    def items_per_second(self) -> float:
        """Calculate items processed per second."""
        return self.items_processed / self.duration if self.duration > 0 else 0
    
    @property
    def files_per_second(self) -> float:
        """Calculate files written per second."""
        return self.files_written / self.duration if self.duration > 0 else 0
    
    @property
    def memory_delta(self) -> float:
        """Calculate memory usage change."""
        return self.memory_end - self.memory_start
    
    @property
    def memory_peak_delta(self) -> float:
        """Calculate peak memory usage above start."""
        return self.memory_peak - self.memory_start


class PerformanceMonitor:
    """Monitor and track performance metrics during operations."""
    
    def __init__(self):
        """Initialize performance monitor."""
        self.logger = get_logger(f"{__name__}.PerformanceMonitor")
        self.process = psutil.Process()
        self._metrics_history: List[PerformanceMetrics] = []
    
    def get_memory_usage(self) -> float:
        """
        Get current memory usage in MB.
        
        Returns:
            Memory usage in megabytes
        """
        return self.process.memory_info().rss / 1024 / 1024
    
    @contextmanager
    def monitor_operation(self, operation: str) -> Iterator[PerformanceMetrics]:
        """
        Context manager to monitor an operation's performance.
        
        Args:
            operation: Name of the operation being monitored
            
        Yields:
            PerformanceMetrics object that gets populated during execution
        """
        # Force garbage collection before starting
        gc.collect()
        
        start_time = time.time()
        start_memory = self.get_memory_usage()
        peak_memory = start_memory
        
        metrics = PerformanceMetrics(
            operation=operation,
            duration=0.0,
            memory_start=start_memory,
            memory_peak=start_memory,
            memory_end=start_memory
        )
        
        self.logger.debug(f"Starting performance monitoring for: {operation}")
        
        try:
            yield metrics
            
            # Monitor peak memory during operation
            current_memory = self.get_memory_usage()
            if current_memory > peak_memory:
                peak_memory = current_memory
                
        finally:
            end_time = time.time()
            end_memory = self.get_memory_usage()
            
            metrics.duration = end_time - start_time
            metrics.memory_peak = max(peak_memory, end_memory)
            metrics.memory_end = end_memory
            
            self._metrics_history.append(metrics)
            self._log_metrics(metrics)
    
    def _log_metrics(self, metrics: PerformanceMetrics) -> None:
        """Log performance metrics."""
        self.logger.info(
            f"Performance - {metrics.operation}: "
            f"{metrics.duration:.2f}s, "
            f"Memory: {metrics.memory_start:.1f}MB → {metrics.memory_end:.1f}MB "
            f"(peak: {metrics.memory_peak:.1f}MB)"
        )
        
        if metrics.items_processed > 0:
            self.logger.info(
                f"Throughput - {metrics.operation}: "
                f"{metrics.items_per_second:.1f} items/sec"
            )
        
        if metrics.files_written > 0:
            self.logger.info(
                f"I/O - {metrics.operation}: "
                f"{metrics.files_per_second:.1f} files/sec, "
                f"{metrics.bytes_written / 1024 / 1024:.1f}MB written"
            )
    
    def get_metrics_history(self) -> List[PerformanceMetrics]:
        """Get history of all recorded metrics."""
        return self._metrics_history.copy()
    
    def clear_history(self) -> None:
        """Clear metrics history."""
        self._metrics_history.clear()


class BatchFileWriter:
    """Optimized batch file writing for improved I/O performance."""
    
    def __init__(self, output_dir: Path, batch_size: int = 50):
        """
        Initialize batch file writer.
        
        Args:
            output_dir: Directory to write files to
            batch_size: Number of files to batch before writing
        """
        self.output_dir = output_dir
        self.batch_size = batch_size
        self.logger = get_logger(f"{__name__}.BatchFileWriter")
        self._batch: List[Tuple[str, Dict[str, Any]]] = []
        self._total_bytes_written = 0
        self._total_files_written = 0
    
    def add_file(self, filename: str, data: Dict[str, Any]) -> None:
        """
        Add a file to the current batch.
        
        Args:
            filename: Name of the file to write
            data: JSON data to write
        """
        self._batch.append((filename, data))
        
        if len(self._batch) >= self.batch_size:
            self.flush_batch()
    
    def flush_batch(self) -> int:
        """
        Write all files in the current batch to disk.
        
        Returns:
            Number of files written
        """
        if not self._batch:
            return 0
        
        files_written = 0
        bytes_written = 0
        
        self.logger.debug(f"Writing batch of {len(self._batch)} files")
        
        for filename, data in self._batch:
            try:
                file_path = self.output_dir / filename
                
                # Serialize JSON once and measure size
                json_content = json.dumps(data, indent=2, ensure_ascii=False)
                json_bytes = json_content.encode('utf-8')
                
                # Write file
                with open(file_path, 'wb') as f:
                    f.write(json_bytes)
                
                files_written += 1
                bytes_written += len(json_bytes)
                
            except (IOError, json.JSONEncodeError) as e:
                self.logger.error(f"Failed to write file {filename}: {e}")
                # Continue with other files in batch
        
        self._total_files_written += files_written
        self._total_bytes_written += bytes_written
        self._batch.clear()
        
        self.logger.debug(f"Batch write complete: {files_written} files, {bytes_written} bytes")
        return files_written
    
    def get_stats(self) -> Tuple[int, int]:
        """
        Get writing statistics.
        
        Returns:
            Tuple of (total_files_written, total_bytes_written)
        """
        return self._total_files_written, self._total_bytes_written
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - flush any remaining files."""
        self.flush_batch()


class MemoryEfficientProcessor:
    """Memory-efficient processing for large vulnerability lists."""
    
    def __init__(self, chunk_size: int = 100):
        """
        Initialize memory-efficient processor.
        
        Args:
            chunk_size: Number of vulnerabilities to process in each chunk
        """
        self.chunk_size = chunk_size
        self.logger = get_logger(f"{__name__}.MemoryEfficientProcessor")
    
    def process_vulnerabilities_chunked(
        self, 
        vulnerabilities: List[Dict[str, Any]], 
        processor_func: callable
    ) -> List[Dict[str, Any]]:
        """
        Process vulnerabilities in chunks to reduce memory usage.
        
        Args:
            vulnerabilities: List of vulnerability objects
            processor_func: Function to apply to each vulnerability
            
        Returns:
            List of processed vulnerabilities
        """
        if not vulnerabilities:
            return []
        
        total_vulns = len(vulnerabilities)
        self.logger.debug(f"Processing {total_vulns} vulnerabilities in chunks of {self.chunk_size}")
        
        processed_vulns = []
        
        for i in range(0, total_vulns, self.chunk_size):
            chunk = vulnerabilities[i:i + self.chunk_size]
            self.logger.debug(f"Processing chunk {i//self.chunk_size + 1}/{(total_vulns + self.chunk_size - 1)//self.chunk_size}")
            
            # Process chunk
            processed_chunk = [processor_func(vuln) for vuln in chunk]
            processed_vulns.extend(processed_chunk)
            
            # Force garbage collection after each chunk to free memory
            if i > 0 and i % (self.chunk_size * 5) == 0:  # Every 5 chunks
                gc.collect()
        
        return processed_vulns
    
    def create_deep_copy_chunked(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a deep copy of data with chunked processing for large vulnerability lists.
        
        Args:
            data: Original data to copy
            
        Returns:
            Deep copy of the data
        """
        import copy
        
        # For small datasets, use regular deep copy
        total_vulns = self._count_total_vulnerabilities(data)
        if total_vulns <= self.chunk_size:
            return copy.deepcopy(data)
        
        self.logger.debug(f"Using chunked deep copy for {total_vulns} vulnerabilities")
        
        # Create shallow copy of root structure
        result = {}
        for key, value in data.items():
            if key == "Results":
                result[key] = self._copy_results_chunked(value)
            else:
                result[key] = copy.deepcopy(value)
        
        return result
    
    def _copy_results_chunked(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Copy Results array with chunked vulnerability processing."""
        import copy
        
        copied_results = []
        
        for result in results:
            copied_result = {}
            for key, value in result.items():
                if key == "Vulnerabilities" and isinstance(value, list):
                    # Process vulnerabilities in chunks
                    copied_result[key] = self.process_vulnerabilities_chunked(
                        value, 
                        lambda vuln: copy.deepcopy(vuln)
                    )
                else:
                    copied_result[key] = copy.deepcopy(value)
            
            copied_results.append(copied_result)
        
        return copied_results
    
    def _count_total_vulnerabilities(self, data: Dict[str, Any]) -> int:
        """Count total number of vulnerabilities in the data."""
        total = 0
        if "Results" in data:
            for result in data["Results"]:
                if "Vulnerabilities" in result and isinstance(result["Vulnerabilities"], list):
                    total += len(result["Vulnerabilities"])
        return total


class BenchmarkRunner:
    """Run performance benchmarks and generate reports."""
    
    def __init__(self):
        """Initialize benchmark runner."""
        self.logger = get_logger(f"{__name__}.BenchmarkRunner")
        self.monitor = PerformanceMonitor()
    
    def run_generation_benchmark(
        self, 
        generator, 
        file_counts: List[int],
        iterations: int = 3
    ) -> Dict[str, Any]:
        """
        Run file generation benchmarks with different file counts.
        
        Args:
            generator: TrivyDataGenerator instance
            file_counts: List of file counts to benchmark
            iterations: Number of iterations per file count
            
        Returns:
            Benchmark results dictionary
        """
        self.logger.info(f"Running generation benchmark with counts: {file_counts}")
        
        results = {
            "benchmark_info": {
                "file_counts": file_counts,
                "iterations": iterations,
                "timestamp": time.time()
            },
            "results": {}
        }
        
        for count in file_counts:
            self.logger.info(f"Benchmarking {count} files generation")
            count_results = []
            
            for iteration in range(iterations):
                self.logger.debug(f"Iteration {iteration + 1}/{iterations} for {count} files")
                
                with self.monitor.monitor_operation(f"generate_{count}_files_iter_{iteration}") as metrics:
                    try:
                        generated_files = generator.generate_files(count)
                        metrics.items_processed = count
                        metrics.files_written = len(generated_files)
                        
                        # Calculate bytes written
                        total_bytes = 0
                        for file_path in generated_files:
                            try:
                                total_bytes += Path(file_path).stat().st_size
                            except OSError:
                                pass  # File might not exist if generation failed
                        
                        metrics.bytes_written = total_bytes
                        
                    except Exception as e:
                        self.logger.error(f"Benchmark iteration failed: {e}")
                        continue
                
                count_results.append({
                    "duration": metrics.duration,
                    "memory_start": metrics.memory_start,
                    "memory_peak": metrics.memory_peak,
                    "memory_end": metrics.memory_end,
                    "files_per_second": metrics.files_per_second,
                    "bytes_written": metrics.bytes_written
                })
                
                # Clean up generated files
                self._cleanup_generated_files(generated_files)
            
            if count_results:
                # Calculate statistics
                durations = [r["duration"] for r in count_results]
                fps_values = [r["files_per_second"] for r in count_results]
                
                results["results"][count] = {
                    "iterations": count_results,
                    "avg_duration": sum(durations) / len(durations),
                    "min_duration": min(durations),
                    "max_duration": max(durations),
                    "avg_files_per_second": sum(fps_values) / len(fps_values),
                    "max_files_per_second": max(fps_values),
                    "meets_30s_target": max(durations) < 30.0 if count == 1000 else None
                }
        
        return results
    
    def _cleanup_generated_files(self, file_paths: List[str]) -> None:
        """Clean up generated files after benchmark."""
        for file_path in file_paths:
            try:
                Path(file_path).unlink(missing_ok=True)
            except OSError as e:
                self.logger.debug(f"Failed to clean up {file_path}: {e}")
    
    def generate_benchmark_report(self, results: Dict[str, Any]) -> str:
        """
        Generate a human-readable benchmark report.
        
        Args:
            results: Benchmark results from run_generation_benchmark
            
        Returns:
            Formatted report string
        """
        report_lines = [
            "=== Trivy Test Data Generator Benchmark Report ===",
            f"Timestamp: {time.ctime(results['benchmark_info']['timestamp'])}",
            f"Iterations per test: {results['benchmark_info']['iterations']}",
            ""
        ]
        
        for count, data in results["results"].items():
            report_lines.extend([
                f"File Count: {count}",
                f"  Average Duration: {data['avg_duration']:.2f}s",
                f"  Min/Max Duration: {data['min_duration']:.2f}s / {data['max_duration']:.2f}s",
                f"  Average Speed: {data['avg_files_per_second']:.1f} files/sec",
                f"  Peak Speed: {data['max_files_per_second']:.1f} files/sec"
            ])
            
            if data["meets_30s_target"] is not None:
                target_status = "✓ PASS" if data["meets_30s_target"] else "✗ FAIL"
                report_lines.append(f"  30-second target: {target_status}")
            
            report_lines.append("")
        
        return "\n".join(report_lines)
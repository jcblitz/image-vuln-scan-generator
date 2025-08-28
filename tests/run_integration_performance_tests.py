#!/usr/bin/env python3
"""
Comprehensive test runner for integration and performance tests.
This script runs all integration and performance tests and provides a summary report.
"""

import os
import subprocess
import sys
import time
from pathlib import Path


def run_command(cmd, description):
    """Run a command and return the result."""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {cmd}")
    print('='*60)
    
    start_time = time.time()
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    duration = time.time() - start_time
    
    print(f"Duration: {duration:.2f}s")
    print(f"Exit code: {result.returncode}")
    
    if result.stdout:
        print("\nSTDOUT:")
        print(result.stdout)
    
    if result.stderr:
        print("\nSTDERR:")
        print(result.stderr)
    
    return result.returncode == 0, duration


def main():
    """Run comprehensive integration and performance tests."""
    print("Trivy Test Data Generator - Integration & Performance Test Suite")
    print("=" * 70)
    
    # Change to project root directory
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    test_results = []
    total_duration = 0
    
    # Test configurations
    tests = [
        {
            'cmd': 'python -m pytest tests/test_integration.py -v',
            'description': 'Integration Tests - End-to-End Workflows'
        },
        {
            'cmd': 'python -m pytest tests/test_integration.py::TestSchemaPreservation -v',
            'description': 'Schema Preservation Tests'
        },
        {
            'cmd': 'python -m pytest tests/test_integration.py::TestVariousFileSizes -v',
            'description': 'Various File Sizes Tests'
        },
        {
            'cmd': 'python -m pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_generation_speed_scaling -v -s',
            'description': 'Performance - Generation Speed Scaling'
        },
        {
            'cmd': 'python -m pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_vulnerability_count_impact -v -s',
            'description': 'Performance - Vulnerability Count Impact'
        },
        {
            'cmd': 'python -m pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_memory_usage_scaling -v -s',
            'description': 'Performance - Memory Usage Scaling'
        },
        {
            'cmd': 'python -m pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_performance_target_compliance -v -s',
            'description': 'Performance - Target Compliance (1000 files <30s)'
        },
        {
            'cmd': 'python -m pytest tests/test_performance_benchmarks.py::TestOptimizationEffectiveness -v -s',
            'description': 'Performance - Optimization Effectiveness'
        },
        {
            'cmd': 'python -m pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_benchmark_runner_integration -v -s',
            'description': 'Performance - Benchmark Runner Integration'
        }
    ]
    
    # Run each test
    for test in tests:
        success, duration = run_command(test['cmd'], test['description'])
        test_results.append({
            'description': test['description'],
            'success': success,
            'duration': duration
        })
        total_duration += duration
    
    # Optional large performance test (if enabled)
    if os.environ.get('RUN_LARGE_PERFORMANCE_TESTS') == '1':
        print(f"\n{'='*60}")
        print("LARGE PERFORMANCE TEST ENABLED")
        print('='*60)
        
        large_test = {
            'cmd': 'RUN_LARGE_PERFORMANCE_TESTS=1 python -m pytest tests/test_performance_benchmarks.py::TestPerformanceBenchmarks::test_actual_1000_file_generation -v -s',
            'description': 'Performance - Actual 1000 File Generation Test'
        }
        
        success, duration = run_command(large_test['cmd'], large_test['description'])
        test_results.append({
            'description': large_test['description'],
            'success': success,
            'duration': duration
        })
        total_duration += duration
    
    # Generate summary report
    print(f"\n{'='*70}")
    print("TEST SUMMARY REPORT")
    print('='*70)
    
    passed_tests = sum(1 for result in test_results if result['success'])
    failed_tests = len(test_results) - passed_tests
    
    print(f"Total Tests: {len(test_results)}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {failed_tests}")
    print(f"Total Duration: {total_duration:.2f}s")
    print()
    
    # Detailed results
    print("DETAILED RESULTS:")
    print("-" * 70)
    for result in test_results:
        status = "PASS" if result['success'] else "FAIL"
        print(f"{status:4s} | {result['duration']:6.2f}s | {result['description']}")
    
    # Performance insights
    print(f"\n{'='*70}")
    print("PERFORMANCE INSIGHTS")
    print('='*70)
    
    performance_tests = [r for r in test_results if 'Performance' in r['description']]
    if performance_tests:
        avg_perf_duration = sum(r['duration'] for r in performance_tests) / len(performance_tests)
        print(f"Average Performance Test Duration: {avg_perf_duration:.2f}s")
        print(f"Performance Tests Passed: {sum(1 for r in performance_tests if r['success'])}/{len(performance_tests)}")
    
    integration_tests = [r for r in test_results if 'Integration' in r['description'] or 'Schema' in r['description'] or 'Various' in r['description']]
    if integration_tests:
        avg_int_duration = sum(r['duration'] for r in integration_tests) / len(integration_tests)
        print(f"Average Integration Test Duration: {avg_int_duration:.2f}s")
        print(f"Integration Tests Passed: {sum(1 for r in integration_tests if r['success'])}/{len(integration_tests)}")
    
    # Recommendations
    print(f"\n{'='*70}")
    print("RECOMMENDATIONS")
    print('='*70)
    
    if failed_tests == 0:
        print("✅ All tests passed! The implementation meets all requirements.")
        print("✅ Schema preservation is working correctly.")
        print("✅ Performance targets are being met.")
        print("✅ Integration workflows are functioning properly.")
    else:
        print("❌ Some tests failed. Please review the detailed results above.")
        print("   Focus on fixing failed tests before proceeding.")
    
    if not os.environ.get('RUN_LARGE_PERFORMANCE_TESTS'):
        print("\n💡 To run the full 1000-file performance test, set:")
        print("   export RUN_LARGE_PERFORMANCE_TESTS=1")
        print("   This will verify the 30-second target for 1000 files.")
    
    print(f"\n{'='*70}")
    print("TEST SUITE COMPLETED")
    print('='*70)
    
    # Exit with appropriate code
    sys.exit(0 if failed_tests == 0 else 1)


if __name__ == '__main__':
    main()
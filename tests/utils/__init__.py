"""
Test utilities package.

This package provides comprehensive testing utilities including:
- Mock factories for creating test doubles
- Test data generators for realistic test scenarios
- Custom assertions for more expressive tests
- Helper functions for common testing operations
"""

from .mock_factory import (
    MockFactory,
    create_failing_mock,
    create_slow_mock,
    create_flaky_mock,
    create_progressive_mock
)

from .test_data import (
    TestDataGenerator,
    create_large_dataset,
    create_nested_structure,
    create_time_series_data,
    create_error_scenarios
)

from .assertions import (
    AssertionHelpers,
    assert_async_raises,
    assert_async_timeout,
    assert_dict_subset,
    assert_lists_equal_unordered,
    assert_close
)

from .helpers import (
    TestHelpers,
    create_test_server,
    cleanup_test_server,
    deep_update,
    remove_keys,
    flatten_dict,
    load_test_fixture,
    save_test_output,
    run_subprocess,
    create_mock_api_client,
    create_test_database_session
)

__all__ = [
    # Mock Factory
    "MockFactory",
    "create_failing_mock",
    "create_slow_mock",
    "create_flaky_mock",
    "create_progressive_mock",
    
    # Test Data
    "TestDataGenerator",
    "create_large_dataset",
    "create_nested_structure",
    "create_time_series_data",
    "create_error_scenarios",
    
    # Assertions
    "AssertionHelpers",
    "assert_async_raises",
    "assert_async_timeout",
    "assert_dict_subset",
    "assert_lists_equal_unordered",
    "assert_close",
    
    # Helpers
    "TestHelpers",
    "create_test_server",
    "cleanup_test_server",
    "deep_update",
    "remove_keys",
    "flatten_dict",
    "load_test_fixture",
    "save_test_output",
    "run_subprocess",
    "create_mock_api_client",
    "create_test_database_session"
]
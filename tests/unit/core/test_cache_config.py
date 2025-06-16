"""
Comprehensive test suite for cache_config module.

Tests cover:
- CacheConfiguration creation and validation
- Environment variable overrides
- Configuration presets (development, production, testing)
- File-based configuration loading/saving
- Configuration validation and error handling
- Specific subsystem configurations
- Global configuration management
"""

import os
import json
import tempfile
import pytest
from unittest.mock import patch, mock_open
from pathlib import Path

from src.core.cache_config import (
    CacheConfiguration,
    ConfigPresets,
    get_cache_config,
    set_cache_config,
    reset_cache_config
)


class TestCacheConfiguration:
    """Test CacheConfiguration class functionality."""
    
    def test_default_configuration(self):
        """Test default CacheConfiguration values."""
        config = CacheConfiguration(enable_env_overrides=False)
        
        # Circle of Experts defaults
        assert config.expert_queries_max_size == 1000
        assert config.expert_queries_ttl == 7200.0
        assert config.expert_responses_max_size == 500
        assert config.expert_responses_ttl == 14400.0
        assert config.response_files_max_size == 2000
        assert config.response_files_ttl == 14400.0
        
        # MCP defaults
        assert config.mcp_contexts_max_size == 200
        assert config.mcp_contexts_ttl == 3600.0
        assert config.mcp_tool_calls_max_per_context == 100
        
        # Connection pool defaults
        assert config.http_sessions_max_size == 50
        assert config.http_sessions_ttl == 1800.0
        assert config.http_metrics_max_size == 100
        assert config.http_metrics_ttl == 3600.0
        
        # Database defaults
        assert config.db_pool_metrics_max_size == 50
        assert config.db_pool_metrics_ttl == 3600.0
        
        # Audit system defaults
        assert config.audit_stats_max_size == 1000
        assert config.audit_stats_ttl == 3600.0
        assert config.audit_buffer_max_size == 500
        assert config.audit_high_freq_buffer_max_size == 500
        
        # Generic defaults
        assert config.default_lru_max_size == 1000
        assert config.default_ttl == 3600.0
        assert config.default_cleanup_interval == 300.0
        
        # Memory and cleanup defaults
        assert config.memory_threshold_mb == 100.0
        assert config.enable_memory_monitoring is True
        assert config.cleanup_check_interval == 10.0
        assert config.cleanup_auto_start is True
        
        # Environment overrides
        assert config.enable_env_overrides is True
        assert config.config_prefix == "CACHE_"
    
    def test_custom_configuration(self):
        """Test CacheConfiguration with custom values."""
        config = CacheConfiguration(
            expert_queries_max_size=2000,
            expert_queries_ttl=14400.0,
            mcp_contexts_max_size=500,
            default_lru_max_size=2000,
            memory_threshold_mb=200.0,
            enable_env_overrides=False
        )
        
        assert config.expert_queries_max_size == 2000
        assert config.expert_queries_ttl == 14400.0
        assert config.mcp_contexts_max_size == 500
        assert config.default_lru_max_size == 2000
        assert config.memory_threshold_mb == 200.0
    
    @patch.dict(os.environ, {
        'CACHE_EXPERT_QUERIES_MAX_SIZE': '1500',
        'CACHE_EXPERT_QUERIES_TTL': '10800.0',
        'CACHE_ENABLE_MEMORY_MONITORING': 'false',
        'CACHE_MEMORY_THRESHOLD_MB': '150.0'
    })
    def test_environment_variable_overrides(self):
        """Test environment variable overrides."""
        config = CacheConfiguration(enable_env_overrides=True)
        
        assert config.expert_queries_max_size == 1500
        assert config.expert_queries_ttl == 10800.0
        assert config.enable_memory_monitoring is False
        assert config.memory_threshold_mb == 150.0
    
    @patch.dict(os.environ, {
        'CACHE_EXPERT_QUERIES_MAX_SIZE': 'invalid_int',
        'CACHE_EXPERT_QUERIES_TTL': 'invalid_float',
        'CACHE_ENABLE_MEMORY_MONITORING': 'invalid_bool'
    })
    def test_environment_variable_invalid_values(self, caplog):
        """Test handling of invalid environment variable values."""
        config = CacheConfiguration(enable_env_overrides=True)
        
        # Should use defaults when environment values are invalid
        assert config.expert_queries_max_size == 1000  # Default value
        assert config.expert_queries_ttl == 7200.0     # Default value
        assert config.enable_memory_monitoring is True  # Default value
        
        # Should log warnings for invalid values
        assert "Invalid environment value" in caplog.text
    
    @patch.dict(os.environ, {
        'CACHE_ENABLE_MEMORY_MONITORING': 'true',
        'CACHE_CLEANUP_AUTO_START': '1',
        'CACHE_ENABLE_ENV_OVERRIDES': 'yes'
    })
    def test_boolean_environment_parsing(self):
        """Test boolean environment variable parsing."""
        config = CacheConfiguration(enable_env_overrides=True)
        
        assert config.enable_memory_monitoring is True
        assert config.cleanup_auto_start is True
    
    @patch.dict(os.environ, {
        'CACHE_ENABLE_MEMORY_MONITORING': 'false',
        'CACHE_CLEANUP_AUTO_START': '0',
        'CACHE_ENABLE_ENV_OVERRIDES': 'no'
    })
    def test_boolean_environment_parsing_false(self):
        """Test boolean environment variable parsing for false values."""
        config = CacheConfiguration(enable_env_overrides=True)
        
        assert config.enable_memory_monitoring is False
        assert config.cleanup_auto_start is False
    
    def test_to_dict(self):
        """Test converting configuration to dictionary."""
        config = CacheConfiguration(enable_env_overrides=False)
        config_dict = config.to_dict()
        
        assert isinstance(config_dict, dict)
        assert 'expert_queries_max_size' in config_dict
        assert 'expert_queries_ttl' in config_dict
        assert 'mcp_contexts_max_size' in config_dict
        assert 'default_lru_max_size' in config_dict
        assert 'memory_threshold_mb' in config_dict
        
        # Check that values match
        assert config_dict['expert_queries_max_size'] == config.expert_queries_max_size
        assert config_dict['memory_threshold_mb'] == config.memory_threshold_mb
    
    def test_save_to_file(self):
        """Test saving configuration to file."""
        config = CacheConfiguration(
            expert_queries_max_size=1500,
            memory_threshold_mb=150.0,
            enable_env_overrides=False
        )
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            config.save_to_file(temp_file)
            
            # Verify file was created and contains expected data
            with open(temp_file, 'r') as f:
                saved_data = json.load(f)
            
            assert saved_data['expert_queries_max_size'] == 1500
            assert saved_data['memory_threshold_mb'] == 150.0
            
        finally:
            os.unlink(temp_file)
    
    def test_save_to_file_error_handling(self, caplog):
        """Test error handling when saving configuration to file."""
        config = CacheConfiguration(enable_env_overrides=False)
        
        # Try to save to invalid path
        config.save_to_file('/invalid/path/config.json')
        
        assert "Failed to save configuration" in caplog.text
    
    def test_load_from_file(self):
        """Test loading configuration from file."""
        test_config = {
            'expert_queries_max_size': 1500,
            'expert_queries_ttl': 10800.0,
            'memory_threshold_mb': 150.0,
            'enable_memory_monitoring': False
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(test_config, f)
            temp_file = f.name
        
        try:
            config = CacheConfiguration.load_from_file(temp_file)
            
            assert config.expert_queries_max_size == 1500
            assert config.expert_queries_ttl == 10800.0
            assert config.memory_threshold_mb == 150.0
            assert config.enable_memory_monitoring is False
            
        finally:
            os.unlink(temp_file)
    
    def test_load_from_file_nonexistent(self, caplog):
        """Test loading configuration from nonexistent file."""
        config = CacheConfiguration.load_from_file('/nonexistent/config.json')
        
        # Should return default configuration
        assert config.expert_queries_max_size == 1000  # Default value
        assert "Configuration file /nonexistent/config.json not found" in caplog.text
    
    def test_load_from_file_invalid_json(self, caplog):
        """Test loading configuration from file with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write("invalid json content")
            temp_file = f.name
        
        try:
            config = CacheConfiguration.load_from_file(temp_file)
            
            # Should return default configuration
            assert config.expert_queries_max_size == 1000  # Default value
            assert "Failed to load configuration" in caplog.text
            
        finally:
            os.unlink(temp_file)
    
    def test_load_from_file_unknown_fields(self):
        """Test loading configuration with unknown fields (should be filtered out)."""
        test_config = {
            'expert_queries_max_size': 1500,
            'unknown_field': 'should_be_ignored',
            'another_unknown': 42,
            'memory_threshold_mb': 150.0
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(test_config, f)
            temp_file = f.name
        
        try:
            config = CacheConfiguration.load_from_file(temp_file)
            
            # Known fields should be loaded
            assert config.expert_queries_max_size == 1500
            assert config.memory_threshold_mb == 150.0
            
            # Unknown fields should not cause errors
            assert not hasattr(config, 'unknown_field')
            assert not hasattr(config, 'another_unknown')
            
        finally:
            os.unlink(temp_file)


class TestConfigurationMethods:
    """Test specific configuration retrieval methods."""
    
    def test_get_expert_config(self):
        """Test getting Circle of Experts specific configuration."""
        config = CacheConfiguration(
            expert_queries_max_size=1500,
            expert_queries_ttl=10800.0,
            expert_responses_max_size=750,
            expert_responses_ttl=21600.0,
            response_files_max_size=3000,
            response_files_ttl=18000.0,
            default_cleanup_interval=600.0,
            enable_env_overrides=False
        )
        
        expert_config = config.get_expert_config()
        
        assert expert_config['queries_max_size'] == 1500
        assert expert_config['queries_ttl'] == 10800.0
        assert expert_config['responses_max_size'] == 750
        assert expert_config['responses_ttl'] == 21600.0
        assert expert_config['response_files_max_size'] == 3000
        assert expert_config['response_files_ttl'] == 18000.0
        assert expert_config['cleanup_interval'] == 600.0
    
    def test_get_mcp_config(self):
        """Test getting MCP specific configuration."""
        config = CacheConfiguration(
            mcp_contexts_max_size=300,
            mcp_contexts_ttl=7200.0,
            mcp_tool_calls_max_per_context=150,
            default_cleanup_interval=450.0,
            enable_env_overrides=False
        )
        
        mcp_config = config.get_mcp_config()
        
        assert mcp_config['contexts_max_size'] == 300
        assert mcp_config['contexts_ttl'] == 7200.0
        assert mcp_config['tool_calls_max_per_context'] == 150
        assert mcp_config['cleanup_interval'] == 450.0
    
    def test_get_connection_config(self):
        """Test getting connection pool specific configuration."""
        config = CacheConfiguration(
            http_sessions_max_size=75,
            http_sessions_ttl=2700.0,
            http_metrics_max_size=150,
            http_metrics_ttl=7200.0,
            db_pool_metrics_max_size=75,
            db_pool_metrics_ttl=7200.0,
            default_cleanup_interval=600.0,
            enable_env_overrides=False
        )
        
        conn_config = config.get_connection_config()
        
        assert conn_config['http_sessions_max_size'] == 75
        assert conn_config['http_sessions_ttl'] == 2700.0
        assert conn_config['http_metrics_max_size'] == 150
        assert conn_config['http_metrics_ttl'] == 7200.0
        assert conn_config['db_metrics_max_size'] == 75
        assert conn_config['db_metrics_ttl'] == 7200.0
        assert conn_config['cleanup_interval'] == 600.0
    
    def test_get_audit_config(self):
        """Test getting audit system specific configuration."""
        config = CacheConfiguration(
            audit_stats_max_size=1500,
            audit_stats_ttl=7200.0,
            audit_buffer_max_size=750,
            audit_high_freq_buffer_max_size=1000,
            default_cleanup_interval=600.0,
            enable_env_overrides=False
        )
        
        audit_config = config.get_audit_config()
        
        assert audit_config['stats_max_size'] == 1500
        assert audit_config['stats_ttl'] == 7200.0
        assert audit_config['buffer_max_size'] == 750
        assert audit_config['high_freq_buffer_max_size'] == 1000
        assert audit_config['cleanup_interval'] == 600.0
    
    def test_get_scheduler_config(self):
        """Test getting cleanup scheduler configuration."""
        config = CacheConfiguration(
            cleanup_check_interval=15.0,
            memory_threshold_mb=200.0,
            enable_memory_monitoring=False,
            cleanup_auto_start=False,
            enable_env_overrides=False
        )
        
        scheduler_config = config.get_scheduler_config()
        
        assert scheduler_config['check_interval'] == 15.0
        assert scheduler_config['memory_threshold_mb'] == 200.0
        assert scheduler_config['enable_memory_monitoring'] is False
        assert scheduler_config['auto_start'] is False


class TestConfigurationValidation:
    """Test configuration validation functionality."""
    
    def test_validate_valid_configuration(self):
        """Test validation of valid configuration."""
        config = CacheConfiguration(enable_env_overrides=False)
        assert config.validate() is True
    
    def test_validate_negative_sizes(self, caplog):
        """Test validation fails for negative size values."""
        config = CacheConfiguration(
            expert_queries_max_size=-100,
            default_lru_max_size=0,
            enable_env_overrides=False
        )
        
        assert config.validate() is False
        assert "expert_queries_max_size must be positive" in caplog.text
        assert "default_lru_max_size must be positive" in caplog.text
    
    def test_validate_negative_ttl(self, caplog):
        """Test validation fails for negative TTL values."""
        config = CacheConfiguration(
            expert_queries_ttl=-3600.0,
            default_ttl=0.0,
            enable_env_overrides=False
        )
        
        assert config.validate() is False
        assert "expert_queries_ttl must be positive" in caplog.text
        assert "default_ttl must be positive" in caplog.text
    
    def test_validate_negative_memory_threshold(self, caplog):
        """Test validation fails for negative memory threshold."""
        config = CacheConfiguration(
            memory_threshold_mb=-50.0,
            enable_env_overrides=False
        )
        
        assert config.validate() is False
        assert "memory_threshold_mb must be positive" in caplog.text
    
    def test_validate_negative_cleanup_interval(self, caplog):
        """Test validation fails for negative cleanup interval."""
        config = CacheConfiguration(
            default_cleanup_interval=-100.0,
            enable_env_overrides=False
        )
        
        assert config.validate() is False
        assert "default_cleanup_interval must be positive" in caplog.text
    
    def test_validate_multiple_errors(self, caplog):
        """Test validation reports multiple errors."""
        config = CacheConfiguration(
            expert_queries_max_size=-100,
            expert_queries_ttl=-3600.0,
            memory_threshold_mb=-50.0,
            enable_env_overrides=False
        )
        
        assert config.validate() is False
        
        # Should report all errors
        log_text = caplog.text
        assert "expert_queries_max_size must be positive" in log_text
        assert "expert_queries_ttl must be positive" in log_text
        assert "memory_threshold_mb must be positive" in log_text


class TestConfigPresets:
    """Test predefined configuration presets."""
    
    def test_development_preset(self):
        """Test development environment preset."""
        dev_config = ConfigPresets.development()
        
        # Should have smaller caches and shorter TTLs
        assert dev_config.expert_queries_max_size == 100
        assert dev_config.expert_queries_ttl == 1800.0  # 30 minutes
        assert dev_config.expert_responses_max_size == 50
        assert dev_config.expert_responses_ttl == 3600.0  # 1 hour
        assert dev_config.mcp_contexts_max_size == 50
        assert dev_config.mcp_contexts_ttl == 1800.0  # 30 minutes
        assert dev_config.http_sessions_max_size == 20
        assert dev_config.audit_stats_max_size == 500
        assert dev_config.memory_threshold_mb == 50.0
        assert dev_config.cleanup_check_interval == 30.0
    
    def test_production_preset(self):
        """Test production environment preset."""
        prod_config = ConfigPresets.production()
        
        # Should have larger caches and longer TTLs
        assert prod_config.expert_queries_max_size == 2000
        assert prod_config.expert_queries_ttl == 14400.0  # 4 hours
        assert prod_config.expert_responses_max_size == 1000
        assert prod_config.expert_responses_ttl == 28800.0  # 8 hours
        assert prod_config.mcp_contexts_max_size == 500
        assert prod_config.mcp_contexts_ttl == 7200.0  # 2 hours
        assert prod_config.http_sessions_max_size == 100
        assert prod_config.audit_stats_max_size == 2000
        assert prod_config.memory_threshold_mb == 200.0
        assert prod_config.cleanup_check_interval == 60.0
    
    def test_testing_preset(self):
        """Test testing environment preset."""
        test_config = ConfigPresets.testing()
        
        # Should have minimal caches and very short TTLs
        assert test_config.expert_queries_max_size == 10
        assert test_config.expert_queries_ttl == 60.0  # 1 minute
        assert test_config.expert_responses_max_size == 10
        assert test_config.expert_responses_ttl == 60.0  # 1 minute
        assert test_config.mcp_contexts_max_size == 10
        assert test_config.mcp_contexts_ttl == 60.0  # 1 minute
        assert test_config.http_sessions_max_size == 5
        assert test_config.audit_stats_max_size == 50
        assert test_config.memory_threshold_mb == 25.0
        assert test_config.cleanup_check_interval == 5.0
    
    def test_preset_validation(self):
        """Test that all presets are valid configurations."""
        presets = [
            ConfigPresets.development(),
            ConfigPresets.production(),
            ConfigPresets.testing()
        ]
        
        for preset in presets:
            assert preset.validate() is True


class TestGlobalConfigurationManagement:
    """Test global configuration management functions."""
    
    def setup_method(self):
        """Reset global configuration before each test."""
        reset_cache_config()
    
    def teardown_method(self):
        """Reset global configuration after each test."""
        reset_cache_config()
    
    def test_get_cache_config_default(self):
        """Test getting default global cache configuration."""
        config = get_cache_config()
        
        assert isinstance(config, CacheConfiguration)
        assert config.expert_queries_max_size == 1000  # Default value
    
    def test_set_cache_config_valid(self):
        """Test setting valid global cache configuration."""
        custom_config = CacheConfiguration(
            expert_queries_max_size=1500,
            enable_env_overrides=False
        )
        
        set_cache_config(custom_config)
        
        retrieved_config = get_cache_config()
        assert retrieved_config.expert_queries_max_size == 1500
    
    def test_set_cache_config_invalid(self, caplog):
        """Test setting invalid global cache configuration."""
        invalid_config = CacheConfiguration(
            expert_queries_max_size=-100,  # Invalid
            enable_env_overrides=False
        )
        
        set_cache_config(invalid_config)
        
        # Should keep current config and log error
        assert "Invalid configuration provided" in caplog.text
    
    def test_reset_cache_config(self):
        """Test resetting global cache configuration."""
        # Set custom config
        custom_config = CacheConfiguration(
            expert_queries_max_size=1500,
            enable_env_overrides=False
        )
        set_cache_config(custom_config)
        
        # Reset
        reset_cache_config()
        
        # Should return new default config
        config = get_cache_config()
        assert config.expert_queries_max_size == 1000  # Back to default
    
    @patch('os.path.exists')
    @patch('src.core.cache_config.CacheConfiguration.load_from_file')
    def test_get_cache_config_from_file(self, mock_load, mock_exists):
        """Test getting cache configuration from file."""
        # Mock file existence check
        mock_exists.return_value = True
        
        # Mock loaded configuration
        file_config = CacheConfiguration(
            expert_queries_max_size=1500,
            enable_env_overrides=False
        )
        mock_load.return_value = file_config
        
        # Reset and get config (should load from file)
        reset_cache_config()
        config = get_cache_config()
        
        assert config.expert_queries_max_size == 1500
        mock_load.assert_called()
    
    @patch.dict(os.environ, {'CACHE_CONFIG_FILE': '/custom/config.json'})
    @patch('os.path.exists')
    @patch('src.core.cache_config.CacheConfiguration.load_from_file')
    def test_get_cache_config_custom_file_env(self, mock_load, mock_exists):
        """Test getting cache configuration from custom file via environment."""
        # Mock file existence for custom path
        def exists_side_effect(path):
            return path == '/custom/config.json'
        mock_exists.side_effect = exists_side_effect
        
        # Mock loaded configuration
        file_config = CacheConfiguration(
            expert_queries_max_size=2000,
            enable_env_overrides=False
        )
        mock_load.return_value = file_config
        
        # Reset and get config
        reset_cache_config()
        config = get_cache_config()
        
        assert config.expert_queries_max_size == 2000
        mock_load.assert_called_with('/custom/config.json')


class TestConfigurationIntegration:
    """Test configuration integration scenarios."""
    
    def test_full_configuration_lifecycle(self):
        """Test complete configuration lifecycle."""
        # Create custom configuration
        config = CacheConfiguration(
            expert_queries_max_size=1500,
            memory_threshold_mb=150.0,
            enable_env_overrides=False
        )
        
        # Save to file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            config.save_to_file(temp_file)
            
            # Load from file
            loaded_config = CacheConfiguration.load_from_file(temp_file)
            
            # Verify loaded config matches original
            assert loaded_config.expert_queries_max_size == 1500
            assert loaded_config.memory_threshold_mb == 150.0
            
            # Validate loaded config
            assert loaded_config.validate() is True
            
            # Get specific subsystem configs
            expert_config = loaded_config.get_expert_config()
            assert expert_config['queries_max_size'] == 1500
            
        finally:
            os.unlink(temp_file)
    
    @patch.dict(os.environ, {
        'CACHE_EXPERT_QUERIES_MAX_SIZE': '1200',
        'CACHE_MEMORY_THRESHOLD_MB': '120.0'
    })
    def test_environment_override_integration(self):
        """Test environment variable override integration."""
        # Create config with env overrides enabled
        config = CacheConfiguration(enable_env_overrides=True)
        
        # Should use environment values
        assert config.expert_queries_max_size == 1200
        assert config.memory_threshold_mb == 120.0
        
        # Get expert config should reflect overrides
        expert_config = config.get_expert_config()
        assert expert_config['queries_max_size'] == 1200
        
        # Validation should still work
        assert config.validate() is True
    
    def test_preset_to_file_round_trip(self):
        """Test saving preset to file and loading it back."""
        # Get production preset
        prod_config = ConfigPresets.production()
        
        # Save to file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_file = f.name
        
        try:
            prod_config.save_to_file(temp_file)
            
            # Load from file
            loaded_config = CacheConfiguration.load_from_file(temp_file)
            
            # Should match production preset values
            assert loaded_config.expert_queries_max_size == 2000
            assert loaded_config.expert_responses_max_size == 1000
            assert loaded_config.memory_threshold_mb == 200.0
            
        finally:
            os.unlink(temp_file)


class TestEdgeCases:
    """Test edge cases and error conditions."""
    
    def test_zero_values_in_configuration(self):
        """Test configuration with zero values (should fail validation)."""
        config = CacheConfiguration(
            expert_queries_max_size=0,
            expert_queries_ttl=0.0,
            enable_env_overrides=False
        )
        
        assert config.validate() is False
    
    def test_very_large_values(self):
        """Test configuration with very large values."""
        config = CacheConfiguration(
            expert_queries_max_size=1000000,
            expert_queries_ttl=86400.0 * 365,  # 1 year
            memory_threshold_mb=100000.0,      # 100GB
            enable_env_overrides=False
        )
        
        # Should still be valid
        assert config.validate() is True
    
    def test_custom_prefix_environment_override(self):
        """Test custom prefix for environment variables."""
        with patch.dict(os.environ, {
            'CUSTOM_EXPERT_QUERIES_MAX_SIZE': '1800',
            'CUSTOM_MEMORY_THRESHOLD_MB': '180.0'
        }):
            config = CacheConfiguration(
                config_prefix="CUSTOM_",
                enable_env_overrides=True
            )
            
            assert config.expert_queries_max_size == 1800
            assert config.memory_threshold_mb == 180.0
    
    def test_partial_environment_overrides(self):
        """Test partial environment variable overrides."""
        with patch.dict(os.environ, {
            'CACHE_EXPERT_QUERIES_MAX_SIZE': '1300'
            # Only override one value
        }):
            config = CacheConfiguration(enable_env_overrides=True)
            
            # Overridden value
            assert config.expert_queries_max_size == 1300
            
            # Non-overridden values should use defaults
            assert config.expert_queries_ttl == 7200.0
            assert config.memory_threshold_mb == 100.0


if __name__ == "__main__":
    pytest.main([__file__])
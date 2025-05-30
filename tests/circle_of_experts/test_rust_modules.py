"""
Test suite for Rust Circle of Experts modules.

Tests the Rust implementation of ExpertAnalyzer and QueryValidator,
ensuring proper functionality and Python integration.
"""

import pytest
import asyncio
from typing import List, Dict, Any
import time
import json

# These will be imported after Rust build
expert_analyzer = None
query_validator = None


@pytest.fixture(scope="module", autouse=True)
def setup_rust_modules():
    """Import Rust modules after ensuring they're built."""
    global expert_analyzer, query_validator
    
    try:
        # Try to import the Rust-accelerated modules
        from claude_optimized_deployment_rust.circle_of_experts import (
            ExpertAnalyzer,
            QueryValidator
        )
        expert_analyzer = ExpertAnalyzer
        query_validator = QueryValidator
        return True
    except ImportError:
        # Fallback to marking tests as skipped if Rust modules not available
        pytest.skip("Rust modules not built. Run 'make rust-build' first.")
        return False


class TestExpertAnalyzer:
    """Test the Rust ExpertAnalyzer implementation."""
    
    def test_analyzer_creation(self):
        """Test creating an ExpertAnalyzer instance."""
        analyzer = expert_analyzer(confidence_threshold=0.8, consensus_threshold=0.9)
        assert analyzer is not None
        
        # Test with defaults
        analyzer_default = expert_analyzer()
        assert analyzer_default is not None
    
    def test_analyze_responses_empty(self):
        """Test analyzing empty responses."""
        analyzer = expert_analyzer()
        result = analyzer.analyze_responses([])
        
        assert result["total_responses"] == 0
        assert result["average_confidence"] == 0.0
        assert result["consensus_score"] == 0.0
        assert result["high_confidence_count"] == 0
        assert result["common_recommendations"] == []
        assert result["unique_limitations"] == []
    
    def test_analyze_single_response(self):
        """Test analyzing a single expert response."""
        analyzer = expert_analyzer(confidence_threshold=0.7)
        
        response = {
            "confidence": 0.85,
            "expert_type": "technical",
            "recommendations": ["Use Rust for performance", "Implement caching"],
            "limitations": ["Requires learning curve", "Initial setup complexity"]
        }
        
        result = analyzer.analyze_responses([response])
        
        assert result["total_responses"] == 1
        assert result["average_confidence"] == 0.85
        assert result["high_confidence_count"] == 1
        assert len(result["unique_limitations"]) == 2
    
    def test_analyze_multiple_responses(self):
        """Test analyzing multiple expert responses with consensus."""
        analyzer = expert_analyzer(confidence_threshold=0.7)
        
        responses = [
            {
                "confidence": 0.9,
                "expert_type": "technical",
                "recommendations": ["Use Rust", "Implement caching", "Add monitoring"],
                "limitations": ["Learning curve", "Setup complexity"]
            },
            {
                "confidence": 0.8,
                "expert_type": "infrastructure",
                "recommendations": ["Use Rust", "Add monitoring", "Use Docker"],
                "limitations": ["Resource usage", "Setup complexity"]
            },
            {
                "confidence": 0.85,
                "expert_type": "security",
                "recommendations": ["Use Rust", "Enable TLS", "Add monitoring"],
                "limitations": ["Certificate management", "Performance overhead"]
            }
        ]
        
        result = analyzer.analyze_responses(responses)
        
        assert result["total_responses"] == 3
        assert 0.84 < result["average_confidence"] < 0.86
        assert result["high_confidence_count"] == 3
        
        # Check common recommendations (appearing in at least 2 responses)
        common_recs = [r.lower() for r in result["common_recommendations"]]
        assert "use rust" in common_recs
        assert "add monitoring" in common_recs
        
        # Check unique limitations
        assert len(result["unique_limitations"]) >= 4
    
    def test_calculate_overlap(self):
        """Test recommendation overlap calculation."""
        analyzer = expert_analyzer()
        
        responses = [
            {
                "recommendations": ["A", "B", "C", "D"]
            },
            {
                "recommendations": ["B", "C", "D", "E"]
            },
            {
                "recommendations": ["C", "D", "E", "F"]
            }
        ]
        
        overlap = analyzer.calculate_overlap(responses)
        
        # Should have moderate overlap
        assert 0.3 < overlap < 0.7
    
    def test_find_similar_recommendations(self):
        """Test finding similar recommendations across experts."""
        analyzer = expert_analyzer()
        
        recommendations = [
            ["Use Rust for performance", "Implement Redis caching"],
            ["Utilize Rust for speed", "Add Redis cache layer"],
            ["Consider Rust implementation", "Enable caching with Redis"]
        ]
        
        groups = analyzer.find_similar_recommendations(recommendations)
        
        # Should group similar recommendations
        assert len(groups) > 0
        # Each group should have related recommendations
        for group in groups:
            assert len(group) >= 1
    
    def test_parallel_performance(self):
        """Test that parallel processing improves performance for large datasets."""
        analyzer = expert_analyzer()
        
        # Create many responses
        responses = []
        for i in range(100):
            responses.append({
                "confidence": 0.7 + (i % 3) * 0.1,
                "expert_type": f"expert_{i % 5}",
                "recommendations": [f"Rec {j}" for j in range(5)],
                "limitations": [f"Limit {j}" for j in range(3)]
            })
        
        # Time the analysis
        start_time = time.time()
        result = analyzer.analyze_responses(responses)
        end_time = time.time()
        
        # Should complete quickly even with many responses
        assert end_time - start_time < 1.0  # Should be much faster than 1 second
        assert result["total_responses"] == 100
    
    def test_edge_cases(self):
        """Test edge cases and error handling."""
        analyzer = expert_analyzer()
        
        # Missing fields
        response_missing_fields = {
            "confidence": 0.8
            # Missing other fields
        }
        
        result = analyzer.analyze_responses([response_missing_fields])
        assert result["total_responses"] == 1
        assert result["common_recommendations"] == []
        
        # Invalid confidence values
        response_invalid = {
            "confidence": "not_a_number",  # Will be parsed as 0.0
            "recommendations": ["Test"]
        }
        
        result = analyzer.analyze_responses([response_invalid])
        assert result["average_confidence"] == 0.0


class TestQueryValidator:
    """Test the Rust QueryValidator implementation."""
    
    def test_validator_creation(self):
        """Test creating a QueryValidator instance."""
        validator = query_validator(
            max_length=1000,
            min_length=20,
            forbidden_patterns=["spam", "malicious"]
        )
        assert validator is not None
        
        # Test with defaults
        validator_default = query_validator()
        assert validator_default is not None
    
    def test_validate_single_query(self):
        """Test validating a single query."""
        validator = query_validator(min_length=10, max_length=100)
        
        # Valid query
        assert validator.is_valid_query("This is a valid query string")
        
        # Too short
        assert not validator.is_valid_query("Short")
        
        # Too long
        assert not validator.is_valid_query("x" * 101)
    
    def test_validate_batch(self):
        """Test batch validation of queries."""
        validator = query_validator(
            min_length=10,
            max_length=100,
            forbidden_patterns=["spam", "hack"]
        )
        
        queries = [
            "This is a valid query",
            "Too short",
            "This contains spam content",
            "Another valid query here",
            "x" * 101,  # Too long
            "Attempting to hack the system"
        ]
        
        results = validator.validate_batch(queries)
        
        assert results[0] is True   # Valid
        assert results[1] is False  # Too short
        assert results[2] is False  # Contains forbidden pattern
        assert results[3] is True   # Valid
        assert results[4] is False  # Too long
        assert results[5] is False  # Contains forbidden pattern
    
    def test_sanitize_query(self):
        """Test query sanitization."""
        validator = query_validator(
            max_length=50,
            forbidden_patterns=["spam", "malicious", "hack"]
        )
        
        # Test removing forbidden patterns
        query = "This is a spam message with malicious content"
        sanitized = validator.sanitize_query(query)
        assert "spam" not in sanitized
        assert "malicious" not in sanitized
        
        # Test truncation
        long_query = "x" * 100
        sanitized = validator.sanitize_query(long_query)
        assert len(sanitized) == 50
        
        # Test trimming
        query_with_spaces = "  Valid query with spaces  "
        sanitized = validator.sanitize_query(query_with_spaces)
        assert sanitized == "Valid query with spaces"
    
    def test_batch_performance(self):
        """Test batch validation performance."""
        validator = query_validator()
        
        # Create many queries
        queries = [f"This is test query number {i}" for i in range(1000)]
        
        # Time the batch validation
        start_time = time.time()
        results = validator.validate_batch(queries)
        end_time = time.time()
        
        # Should be very fast
        assert end_time - start_time < 0.1  # Should complete in under 100ms
        assert len(results) == 1000
        assert all(results)  # All should be valid
    
    def test_unicode_handling(self):
        """Test handling of unicode characters."""
        validator = query_validator(min_length=5)
        
        # Various unicode strings
        queries = [
            "Hello 世界",  # Chinese
            "Привет мир",  # Russian
            "مرحبا بالعالم",  # Arabic
            "🚀 Rocket emoji query",
            "Query with émojis 😀"
        ]
        
        results = validator.validate_batch(queries)
        assert all(results)  # All should be valid


class TestRustPythonIntegration:
    """Test integration between Rust modules and Python code."""
    
    def test_rust_module_imports(self):
        """Test that Rust modules can be imported correctly."""
        assert expert_analyzer is not None
        assert query_validator is not None
        
        # Check module attributes
        assert hasattr(expert_analyzer, '__new__')
        assert hasattr(query_validator, '__new__')
    
    def test_type_conversions(self):
        """Test type conversions between Python and Rust."""
        analyzer = expert_analyzer()
        
        # Test various Python types
        response = {
            "confidence": 0.9,  # float
            "expert_type": "test",  # string
            "recommendations": ["rec1", "rec2"],  # list of strings
            "limitations": ["lim1"],  # list
            "extra_field": {"nested": "data"}  # dict (should be ignored)
        }
        
        result = analyzer.analyze_responses([response])
        
        # Check return types
        assert isinstance(result, dict)
        assert isinstance(result["total_responses"], int)
        assert isinstance(result["average_confidence"], float)
        assert isinstance(result["common_recommendations"], list)
    
    def test_error_propagation(self):
        """Test that Rust errors are properly propagated to Python."""
        analyzer = expert_analyzer()
        
        # Test with invalid input types
        with pytest.raises(TypeError):
            analyzer.analyze_responses("not a list")
        
        validator = query_validator()
        
        # Test with invalid input
        with pytest.raises(TypeError):
            validator.validate_batch("not a list")
    
    def test_memory_efficiency(self):
        """Test memory efficiency of Rust modules."""
        import sys
        
        analyzer = expert_analyzer()
        
        # Create large dataset
        large_responses = []
        for i in range(1000):
            large_responses.append({
                "confidence": 0.8,
                "expert_type": f"expert_{i}",
                "recommendations": [f"Recommendation {j}" for j in range(10)],
                "limitations": [f"Limitation {j}" for j in range(5)]
            })
        
        # Get size before
        size_before = sys.getsizeof(large_responses)
        
        # Process with Rust
        result = analyzer.analyze_responses(large_responses)
        
        # Result should be much smaller than input
        size_after = sys.getsizeof(result)
        assert size_after < size_before / 10  # Result should be < 10% of input size


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
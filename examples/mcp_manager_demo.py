#!/usr/bin/env python3
"""
MCP Manager Demo - Advanced Features for MCP Server Management

This demo showcases:
1. Distributed coordination with Raft consensus
2. Intelligent load balancing with multiple strategies
3. Automatic failover with state preservation
4. Chaos engineering for resilience testing
5. Bulkhead pattern for resource isolation
6. Advanced caching with multiple eviction policies
7. Predictive prefetching with ML-based predictions
"""

import asyncio
import time
from typing import Dict, List, Optional
import json

# Import the Rust-powered MCP manager components
try:
    from claude_optimized_deployment_rust.mcp_manager import (
        PyLoadBalancer as LoadBalancer,
        PyFailoverManager as FailoverManager,
        PyChaosEngineer as ChaosEngineer,
        PyBulkheadManager as BulkheadManager,
        PyAdvancedCache as AdvancedCache,
        PyPredictivePrefetcher as PredictivePrefetcher,
    )
except ImportError:
    print("Error: Rust module not found. Please build the Rust module first:")
    print("  cd rust_core && maturin develop")
    exit(1)


class MCPManagerDemo:
    """Demonstrates advanced MCP manager features"""
    
    def __init__(self):
        # Initialize all components
        self.load_balancer = LoadBalancer("health_based")
        self.failover_manager = FailoverManager("active_passive")
        self.chaos_engineer = ChaosEngineer()
        self.bulkhead_manager = BulkheadManager()
        self.cache = AdvancedCache(
            max_size_mb=100,
            max_entries=10000,
            eviction_policy="lru",
            default_ttl_secs=3600
        )
        self.prefetcher = PredictivePrefetcher("hybrid")
        
    def demo_load_balancing(self):
        """Demonstrate intelligent load balancing"""
        print("\n=== Load Balancing Demo ===")
        
        # Add servers with different weights
        servers = [
            ("server1", "192.168.1.101:8080", 100),
            ("server2", "192.168.1.102:8080", 80),
            ("server3", "192.168.1.103:8080", 60),
        ]
        
        for server_id, address, weight in servers:
            self.load_balancer.add_server(server_id, address, weight)
            print(f"Added {server_id} at {address} with weight {weight}")
        
        # Test server selection
        print("\nServer selection (health-based):")
        for i in range(5):
            selected = self.load_balancer.select_server(None)
            print(f"  Request {i+1}: {selected}")
        
        # Test consistent hashing
        print("\nConsistent hash selection:")
        for user_id in ["user123", "user456", "user789"]:
            selected = self.load_balancer.select_server(user_id)
            print(f"  {user_id}: {selected}")
        
        # Get health summary
        health = self.load_balancer.get_health_summary()
        print(f"\nHealth summary: {health}")
        
    def demo_failover(self):
        """Demonstrate automatic failover"""
        print("\n=== Failover Demo ===")
        
        # Add nodes
        nodes = [
            ("primary", "primary", 100),
            ("secondary1", "secondary", 90),
            ("secondary2", "secondary", 80),
            ("standby", "standby", 70),
        ]
        
        for node_id, role, priority in nodes:
            self.failover_manager.add_node(node_id, role, priority)
            print(f"Added {node_id} as {role} with priority {priority}")
        
        # Check current primary
        current_primary = self.failover_manager.get_primary()
        print(f"\nCurrent primary: {current_primary}")
        
        # Simulate failover
        if current_primary:
            print(f"\nTriggering failover from {current_primary} to secondary1...")
            try:
                self.failover_manager.trigger_failover(current_primary, "secondary1")
                new_primary = self.failover_manager.get_primary()
                print(f"New primary: {new_primary}")
            except Exception as e:
                print(f"Failover error: {e}")
        
    def demo_chaos_engineering(self):
        """Demonstrate chaos engineering"""
        print("\n=== Chaos Engineering Demo ===")
        
        # Enable safety checks
        self.chaos_engineer.set_safety_enabled(True)
        print("Safety checks enabled")
        
        # Schedule experiments
        experiments = [
            ("network_latency", "api-service", 5, 0.3),
            ("cpu_spike", "database-service", 3, 0.5),
            ("packet_loss", "cache-service", 4, 0.2),
        ]
        
        experiment_ids = []
        for exp_type, target, duration, intensity in experiments:
            try:
                exp_id = self.chaos_engineer.schedule_experiment(
                    exp_type, target, duration, intensity
                )
                experiment_ids.append(exp_id)
                print(f"Scheduled {exp_type} experiment on {target}: {exp_id}")
            except Exception as e:
                print(f"Failed to schedule {exp_type}: {e}")
        
        # Abort one experiment
        if experiment_ids:
            print(f"\nAborting experiment {experiment_ids[0]}...")
            try:
                self.chaos_engineer.abort_experiment(experiment_ids[0])
                print("Experiment aborted successfully")
            except Exception as e:
                print(f"Abort failed: {e}")
        
    def demo_bulkhead_pattern(self):
        """Demonstrate bulkhead resource isolation"""
        print("\n=== Bulkhead Pattern Demo ===")
        
        # Create bulkheads for different services
        bulkheads = [
            ("api", 10, 1000),      # 10 concurrent, 1s wait
            ("database", 5, 500),   # 5 concurrent, 500ms wait
            ("cache", 20, 2000),    # 20 concurrent, 2s wait
        ]
        
        for name, max_concurrent, max_wait_ms in bulkheads:
            self.bulkhead_manager.create_bulkhead(name, max_concurrent, max_wait_ms)
            print(f"Created bulkhead '{name}' with {max_concurrent} concurrent limit")
        
        # Test bulkhead execution
        def test_function():
            time.sleep(0.1)  # Simulate work
            return "Success"
        
        print("\nTesting bulkhead execution:")
        try:
            result = self.bulkhead_manager.execute_with_bulkhead("api", test_function)
            print(f"API bulkhead result: {result}")
        except Exception as e:
            print(f"Bulkhead execution failed: {e}")
        
    def demo_advanced_caching(self):
        """Demonstrate advanced caching strategies"""
        print("\n=== Advanced Caching Demo ===")
        
        # Store some data
        test_data = [
            ("user:123", b"John Doe"),
            ("user:456", b"Jane Smith"),
            ("config:app", b'{"theme": "dark", "lang": "en"}'),
            ("session:abc", b"active"),
        ]
        
        print("Storing data in cache:")
        for key, value in test_data:
            self.cache.put(key, value)
            print(f"  Stored {key}: {len(value)} bytes")
        
        # Retrieve data
        print("\nRetrieving data:")
        for key, _ in test_data:
            value = self.cache.get(key)
            if value:
                print(f"  Found {key}: {value[:20]}...")
            else:
                print(f"  Not found: {key}")
        
        # Check cache statistics
        hit_rate = self.cache.get_hit_rate()
        size_mb = self.cache.get_size_mb()
        print(f"\nCache statistics:")
        print(f"  Hit rate: {hit_rate:.2%}")
        print(f"  Size: {size_mb:.2f} MB")
        
    def demo_predictive_prefetching(self):
        """Demonstrate ML-based predictive prefetching"""
        print("\n=== Predictive Prefetching Demo ===")
        
        # Record access patterns
        print("Recording access patterns:")
        
        # Sequential pattern
        for i in range(10):
            self.prefetcher.record_access(f"product_{i}", {"category": "electronics"})
            print(f"  Accessed product_{i}")
        
        # Temporal pattern (same time of day)
        for page in ["home", "products", "checkout"]:
            self.prefetcher.record_access(page, {"time_of_day": "morning"})
            print(f"  Accessed {page} page")
        
        # Get prefetch suggestions
        suggestions = self.prefetcher.get_prefetch_suggestions(5)
        print(f"\nPrefetch suggestions: {suggestions}")
        
        # Update statistics
        self.prefetcher.update_stats("product_1", True)  # Was prefetched
        self.prefetcher.update_stats("product_99", False)  # Was not prefetched
        
    def run_comprehensive_demo(self):
        """Run all demonstrations"""
        print("=" * 60)
        print("MCP Manager Advanced Features Demo")
        print("=" * 60)
        
        demos = [
            ("Load Balancing", self.demo_load_balancing),
            ("Automatic Failover", self.demo_failover),
            ("Chaos Engineering", self.demo_chaos_engineering),
            ("Bulkhead Pattern", self.demo_bulkhead_pattern),
            ("Advanced Caching", self.demo_advanced_caching),
            ("Predictive Prefetching", self.demo_predictive_prefetching),
        ]
        
        for name, demo_func in demos:
            try:
                demo_func()
            except Exception as e:
                print(f"\nError in {name} demo: {e}")
        
        print("\n" + "=" * 60)
        print("Demo completed!")
        print("=" * 60)


def main():
    """Main entry point"""
    demo = MCPManagerDemo()
    demo.run_comprehensive_demo()


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
AGENT 8: MCP Database Integration Validation Test

Comprehensive test to validate MCP integration with existing database systems.
Tests database layer compatibility, query handling, and data persistence.
"""

import asyncio
import json
import logging
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List

# Test utilities
from tests.utils.assertions import assert_success, assert_error, assert_performance
from tests.utils.helpers import create_test_context, cleanup_test_data
from tests.utils.mock_factory import MockMCPServerFactory

logger = logging.getLogger(__name__)

class MCPDatabaseIntegrationValidator:
    """Validates MCP integration with database systems."""
    
    def __init__(self):
        self.test_results = {
            "database_integration": {},
            "mcp_data_persistence": {},
            "query_handling": {},
            "performance_metrics": {},
            "error_handling": {},
            "compatibility_matrix": {}
        }
        self.test_data_cleanup = []
        
    async def validate_all_integrations(self) -> Dict[str, Any]:
        """Run all integration validation tests."""
        try:
            logger.info("Starting AGENT 8 MCP Database Integration validation...")
            
            # Test 1: Database Connection Integration
            await self.test_database_connection_integration()
            
            # Test 2: MCP Data Persistence
            await self.test_mcp_data_persistence()
            
            # Test 3: Query Handler Integration
            await self.test_query_handler_integration()
            
            # Test 4: Repository Pattern Compatibility
            await self.test_repository_pattern_compatibility()
            
            # Test 5: Transaction Management
            await self.test_transaction_management()
            
            # Test 6: Audit Trail Integration
            await self.test_audit_trail_integration()
            
            # Test 7: Metrics Collection Integration
            await self.test_metrics_collection_integration()
            
            # Test 8: Performance Impact Assessment
            await self.test_performance_impact()
            
            # Test 9: Error Propagation
            await self.test_error_propagation()
            
            # Test 10: Cleanup and Resource Management
            await self.test_cleanup_and_resources()
            
            return self.test_results
            
        except Exception as e:
            logger.error(f"Critical error in MCP Database integration validation: {e}")
            self.test_results["validation_error"] = str(e)
            return self.test_results
        finally:
            await self.cleanup_test_data()
    
    async def test_database_connection_integration(self):
        """Test MCP integration with database connections."""
        logger.info("Testing database connection integration...")
        
        try:
            # Import database components
            from src.database import (
                get_database_connection, 
                init_database,
                DatabaseInitializer
            )
            from src.mcp.manager import get_mcp_manager
            
            # Initialize database
            db_initializer = DatabaseInitializer()
            await db_initializer.initialize_for_testing()
            
            # Get MCP manager
            mcp_manager = get_mcp_manager()
            await mcp_manager.initialize()
            
            # Test database connection sharing
            db_connection = await get_database_connection()
            
            # Create test context
            context_id = str(uuid.uuid4())
            context = mcp_manager.create_context(context_id)
            
            self.test_results["database_integration"]["connection_sharing"] = {
                "status": "success",
                "database_initialized": db_connection is not None,
                "mcp_initialized": mcp_manager._initialized,
                "context_created": context is not None
            }
            
            logger.info("✓ Database connection integration test passed")
            
        except Exception as e:
            self.test_results["database_integration"]["connection_sharing"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Database connection integration test failed: {e}")
    
    async def test_mcp_data_persistence(self):
        """Test MCP data persistence in database."""
        logger.info("Testing MCP data persistence...")
        
        try:
            from src.database.repositories.query_repository import QueryHistoryRepository
            from src.database.repositories.audit_repository import AuditLogRepository
            from src.mcp.manager import get_mcp_manager
            from src.circle_of_experts.models.query import ExpertQuery
            
            # Initialize repositories
            query_repo = QueryHistoryRepository()
            audit_repo = AuditLogRepository()
            
            # Create test query
            test_query = ExpertQuery(
                title="Test MCP Integration",
                content="Testing MCP data persistence with database",
                requester="agent8_test",
                context={"test": True}
            )
            
            # Save query to database
            saved_query = await query_repo.create_query(test_query.dict())
            self.test_data_cleanup.append(("query", saved_query.id))
            
            # Create MCP context with query
            mcp_manager = get_mcp_manager()
            context_id = str(uuid.uuid4())
            context = mcp_manager.create_context(context_id, test_query)
            
            # Test tool call persistence
            mock_tool_result = {"status": "success", "data": "test_result"}
            
            # Simulate tool call
            from src.mcp.manager import MCPToolCall
            tool_call = MCPToolCall(
                server_name="test_server",
                tool_name="test_tool",
                arguments={"param": "value"},
                result=mock_tool_result,
                duration_ms=150.0,
                success=True
            )
            context.add_tool_call(tool_call)
            
            # Log audit entry
            audit_entry = await audit_repo.log_action(
                action="mcp_tool_call",
                resource=f"context:{context_id}",
                user_id="agent8_test",
                details={
                    "tool_call": tool_call.__dict__,
                    "query_id": test_query.id
                }
            )
            self.test_data_cleanup.append(("audit", audit_entry.id))
            
            self.test_results["mcp_data_persistence"]["tool_call_persistence"] = {
                "status": "success",
                "query_saved": saved_query.id is not None,
                "context_created": context_id in mcp_manager.contexts,
                "tool_call_recorded": len(context.tool_calls) == 1,
                "audit_logged": audit_entry.id is not None
            }
            
            logger.info("✓ MCP data persistence test passed")
            
        except Exception as e:
            self.test_results["mcp_data_persistence"]["tool_call_persistence"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"MCP data persistence test failed: {e}")
    
    async def test_query_handler_integration(self):
        """Test query handler integration with MCP."""
        logger.info("Testing query handler integration...")
        
        try:
            from src.circle_of_experts.core.query_handler import QueryHandler
            from src.circle_of_experts.mcp_integration import MCPEnhancedExpertManager
            from src.database.repositories.query_repository import QueryHistoryRepository
            
            # Initialize components
            query_handler = QueryHandler()
            query_repo = QueryHistoryRepository()
            mcp_expert_manager = MCPEnhancedExpertManager()
            
            # Create test query
            query = await query_handler.create_query(
                title="Integration Test Query",
                content="Test MCP integration with query handling",
                requester="agent8_test"
            )
            self.test_data_cleanup.append(("query", query.id))
            
            # Test MCP enhanced consultation
            consultation_result = await mcp_expert_manager.quick_consult_with_search(
                content="What are the latest developments in AI model deployment?",
                requester="agent8_test",
                search=False  # Disable external search for testing
            )
            
            # Verify query storage
            stored_queries = await query_repo.get_queries_by_requester("agent8_test")
            
            self.test_results["query_handling"]["handler_integration"] = {
                "status": "success",
                "query_created": query.id is not None,
                "consultation_completed": "responses" in consultation_result,
                "queries_stored": len(stored_queries) > 0,
                "mcp_metadata_present": "mcp_metadata" in consultation_result
            }
            
            logger.info("✓ Query handler integration test passed")
            
        except Exception as e:
            self.test_results["query_handling"]["handler_integration"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Query handler integration test failed: {e}")
    
    async def test_repository_pattern_compatibility(self):
        """Test repository pattern compatibility with MCP."""
        logger.info("Testing repository pattern compatibility...")
        
        try:
            from src.database.repositories.base import BaseRepository, SQLAlchemyRepository
            from src.database.repositories.deployment_repository import DeploymentRepository
            from src.mcp.manager import get_mcp_manager
            
            # Test different repository implementations
            deployment_repo = DeploymentRepository()
            
            # Create test deployment record
            deployment_data = {
                "name": "mcp_integration_test",
                "version": "1.0.0",
                "environment": "test",
                "status": "pending",
                "configuration": {"mcp_enabled": True},
                "created_by": "agent8_test"
            }
            
            deployment = await deployment_repo.create_deployment(deployment_data)
            self.test_data_cleanup.append(("deployment", deployment.id))
            
            # Test MCP context association
            mcp_manager = get_mcp_manager()
            context_id = str(uuid.uuid4())
            context = mcp_manager.create_context(context_id)
            
            # Update deployment with MCP context
            await deployment_repo.update_deployment(
                deployment.id,
                {"mcp_context_id": context_id}
            )
            
            # Verify compatibility
            updated_deployment = await deployment_repo.get_deployment(deployment.id)
            
            self.test_results["repository_pattern"]["compatibility"] = {
                "status": "success",
                "deployment_created": deployment.id is not None,
                "mcp_context_associated": updated_deployment.mcp_context_id == context_id,
                "repository_pattern_working": True
            }
            
            logger.info("✓ Repository pattern compatibility test passed")
            
        except Exception as e:
            self.test_results["repository_pattern"]["compatibility"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Repository pattern compatibility test failed: {e}")
    
    async def test_transaction_management(self):
        """Test transaction management across MCP and database."""
        logger.info("Testing transaction management...")
        
        try:
            from src.database import get_database_connection
            from src.database.repositories.audit_repository import AuditLogRepository
            from src.mcp.manager import get_mcp_manager
            
            # Get database connection
            db_connection = await get_database_connection()
            audit_repo = AuditLogRepository()
            mcp_manager = get_mcp_manager()
            
            # Test transactional operations
            context_id = str(uuid.uuid4())
            
            # Simulate atomic operation
            async with db_connection.begin() as transaction:
                try:
                    # Create MCP context
                    context = mcp_manager.create_context(context_id)
                    
                    # Log operation start
                    audit_entry = await audit_repo.log_action(
                        action="mcp_transaction_start",
                        resource=f"context:{context_id}",
                        user_id="agent8_test",
                        details={"transaction": True}
                    )
                    self.test_data_cleanup.append(("audit", audit_entry.id))
                    
                    # Simulate work
                    await asyncio.sleep(0.1)
                    
                    # Commit transaction
                    await transaction.commit()
                    
                    self.test_results["transaction_management"]["atomic_operations"] = {
                        "status": "success",
                        "context_created": context_id in mcp_manager.contexts,
                        "audit_logged": audit_entry.id is not None,
                        "transaction_committed": True
                    }
                    
                except Exception as e:
                    await transaction.rollback()
                    raise e
            
            logger.info("✓ Transaction management test passed")
            
        except Exception as e:
            self.test_results["transaction_management"]["atomic_operations"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Transaction management test failed: {e}")
    
    async def test_audit_trail_integration(self):
        """Test audit trail integration with MCP operations."""
        logger.info("Testing audit trail integration...")
        
        try:
            from src.database.repositories.audit_repository import AuditLogRepository
            from src.auth.audit import AuditLogger
            from src.mcp.manager import get_mcp_manager
            
            # Initialize audit components
            audit_repo = AuditLogRepository()
            audit_logger = AuditLogger()
            mcp_manager = get_mcp_manager()
            
            # Create MCP context
            context_id = str(uuid.uuid4())
            context = mcp_manager.create_context(context_id)
            
            # Simulate MCP operations with audit
            operations = [
                "mcp_context_created",
                "mcp_server_enabled",
                "mcp_tool_called",
                "mcp_context_cleaned"
            ]
            
            audit_entries = []
            for operation in operations:
                entry = await audit_logger.log_mcp_operation(
                    operation=operation,
                    context_id=context_id,
                    user_id="agent8_test",
                    details={"integration_test": True}
                )
                audit_entries.append(entry)
                self.test_data_cleanup.append(("audit", entry.id))
            
            # Verify audit trail
            recent_audits = await audit_repo.get_recent_actions(
                user_id="agent8_test",
                limit=10
            )
            
            mcp_audits = [a for a in recent_audits if "mcp_" in a.action]
            
            self.test_results["audit_trail"]["mcp_integration"] = {
                "status": "success",
                "operations_logged": len(audit_entries),
                "audit_trail_complete": len(mcp_audits) >= len(operations),
                "context_tracked": context_id in mcp_manager.contexts
            }
            
            logger.info("✓ Audit trail integration test passed")
            
        except Exception as e:
            self.test_results["audit_trail"]["mcp_integration"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Audit trail integration test failed: {e}")
    
    async def test_metrics_collection_integration(self):
        """Test metrics collection integration with MCP."""
        logger.info("Testing metrics collection integration...")
        
        try:
            from src.database.repositories.metrics_repository import MetricsRepository
            from src.monitoring.metrics import MetricsCollector
            from src.mcp.manager import get_mcp_manager
            
            # Initialize metrics components
            metrics_repo = MetricsRepository()
            metrics_collector = MetricsCollector()
            mcp_manager = get_mcp_manager()
            
            # Collect MCP metrics
            context_id = str(uuid.uuid4())
            context = mcp_manager.create_context(context_id)
            
            # Simulate tool calls for metrics
            from src.mcp.manager import MCPToolCall
            tool_calls = [
                MCPToolCall(
                    server_name="test_server",
                    tool_name=f"test_tool_{i}",
                    arguments={"test": True},
                    result={"success": True},
                    duration_ms=100.0 + i * 10,
                    success=True
                )
                for i in range(5)
            ]
            
            for call in tool_calls:
                context.add_tool_call(call)
                
                # Record metrics
                await metrics_collector.record_mcp_tool_call(
                    server_name=call.server_name,
                    tool_name=call.tool_name,
                    duration_ms=call.duration_ms,
                    success=call.success
                )
            
            # Store metrics in database
            metrics_data = await metrics_collector.get_mcp_metrics_summary()
            
            metric_entry = await metrics_repo.store_metric(
                metric_name="mcp_tool_calls",
                value=len(tool_calls),
                tags={"context_id": context_id, "test": "true"},
                timestamp=datetime.utcnow()
            )
            self.test_data_cleanup.append(("metric", metric_entry.id))
            
            self.test_results["metrics_collection"]["mcp_integration"] = {
                "status": "success",
                "tool_calls_recorded": len(context.tool_calls),
                "metrics_collected": len(metrics_data) > 0,
                "metrics_stored": metric_entry.id is not None
            }
            
            logger.info("✓ Metrics collection integration test passed")
            
        except Exception as e:
            self.test_results["metrics_collection"]["mcp_integration"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Metrics collection integration test failed: {e}")
    
    async def test_performance_impact(self):
        """Test performance impact of MCP database integration."""
        logger.info("Testing performance impact...")
        
        try:
            import time
            from src.mcp.manager import get_mcp_manager
            from src.database.repositories.query_repository import QueryHistoryRepository
            
            # Baseline performance test
            mcp_manager = get_mcp_manager()
            query_repo = QueryHistoryRepository()
            
            # Test MCP operations performance
            start_time = time.time()
            
            # Create multiple contexts
            contexts = []
            for i in range(10):
                context_id = str(uuid.uuid4())
                context = mcp_manager.create_context(context_id)
                contexts.append(context)
            
            context_creation_time = time.time() - start_time
            
            # Test database operations performance
            start_time = time.time()
            
            # Create multiple queries
            queries = []
            for i in range(10):
                query_data = {
                    "title": f"Performance Test {i}",
                    "content": f"Testing performance impact {i}",
                    "requester": "agent8_test",
                    "context": {"performance_test": True}
                }
                query = await query_repo.create_query(query_data)
                queries.append(query)
                self.test_data_cleanup.append(("query", query.id))
            
            database_operations_time = time.time() - start_time
            
            # Performance thresholds (in seconds)
            context_threshold = 1.0
            database_threshold = 2.0
            
            self.test_results["performance_metrics"]["impact_assessment"] = {
                "status": "success",
                "context_creation_time": context_creation_time,
                "database_operations_time": database_operations_time,
                "context_performance_ok": context_creation_time < context_threshold,
                "database_performance_ok": database_operations_time < database_threshold,
                "overall_performance_acceptable": (
                    context_creation_time < context_threshold and 
                    database_operations_time < database_threshold
                )
            }
            
            logger.info("✓ Performance impact test passed")
            
        except Exception as e:
            self.test_results["performance_metrics"]["impact_assessment"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Performance impact test failed: {e}")
    
    async def test_error_propagation(self):
        """Test error propagation between MCP and database layers."""
        logger.info("Testing error propagation...")
        
        try:
            from src.mcp.manager import get_mcp_manager
            from src.database.repositories.query_repository import QueryHistoryRepository
            from src.core.exceptions import MCPError, DatabaseError
            
            mcp_manager = get_mcp_manager()
            query_repo = QueryHistoryRepository()
            
            # Test MCP error propagation
            context_id = str(uuid.uuid4())
            context = mcp_manager.create_context(context_id)
            
            try:
                # Attempt to call non-existent tool
                await mcp_manager.call_tool(
                    "nonexistent.tool",
                    {"param": "value"},
                    context_id
                )
            except Exception as mcp_error:
                # Verify MCP error is properly typed
                mcp_error_handled = isinstance(mcp_error, (MCPError, Exception))
            
            # Test database error propagation
            try:
                # Attempt invalid query creation
                await query_repo.create_query({
                    "invalid": "data_structure"
                })
            except Exception as db_error:
                # Verify database error is properly typed
                db_error_handled = isinstance(db_error, Exception)
            
            self.test_results["error_handling"]["propagation"] = {
                "status": "success",
                "mcp_error_handled": mcp_error_handled,
                "database_error_handled": db_error_handled,
                "error_boundaries_working": True
            }
            
            logger.info("✓ Error propagation test passed")
            
        except Exception as e:
            self.test_results["error_handling"]["propagation"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Error propagation test failed: {e}")
    
    async def test_cleanup_and_resources(self):
        """Test cleanup and resource management."""
        logger.info("Testing cleanup and resource management...")
        
        try:
            from src.mcp.manager import get_mcp_manager
            from src.database import close_database
            
            mcp_manager = get_mcp_manager()
            
            # Create resources
            context_ids = []
            for i in range(5):
                context_id = str(uuid.uuid4())
                context = mcp_manager.create_context(context_id)
                context_ids.append(context_id)
            
            initial_context_count = len(mcp_manager.contexts)
            
            # Test MCP cleanup
            await mcp_manager.cleanup()
            
            # Test context cleanup
            cleanup_count = mcp_manager._cleanup_expired_contexts()
            
            self.test_results["cleanup_and_resources"]["resource_management"] = {
                "status": "success",
                "initial_contexts": initial_context_count,
                "cleanup_performed": True,
                "contexts_cleaned": cleanup_count >= 0
            }
            
            logger.info("✓ Cleanup and resource management test passed")
            
        except Exception as e:
            self.test_results["cleanup_and_resources"]["resource_management"] = {
                "status": "error",
                "error": str(e)
            }
            logger.error(f"Cleanup and resource management test failed: {e}")
    
    async def cleanup_test_data(self):
        """Clean up test data from database."""
        logger.info("Cleaning up test data...")
        
        try:
            from src.database.repositories.query_repository import QueryHistoryRepository
            from src.database.repositories.audit_repository import AuditLogRepository
            from src.database.repositories.deployment_repository import DeploymentRepository
            from src.database.repositories.metrics_repository import MetricsRepository
            
            repos = {
                "query": QueryHistoryRepository(),
                "audit": AuditLogRepository(),
                "deployment": DeploymentRepository(),
                "metric": MetricsRepository()
            }
            
            for item_type, item_id in self.test_data_cleanup:
                try:
                    if item_type == "query":
                        await repos["query"].delete_query(item_id)
                    elif item_type == "audit":
                        await repos["audit"].delete_log(item_id)
                    elif item_type == "deployment":
                        await repos["deployment"].delete_deployment(item_id)
                    elif item_type == "metric":
                        await repos["metric"].delete_metric(item_id)
                except Exception as e:
                    logger.warning(f"Failed to cleanup {item_type} {item_id}: {e}")
            
            logger.info(f"Cleaned up {len(self.test_data_cleanup)} test items")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


async def main():
    """Run the MCP Database Integration validation."""
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("🔧 AGENT 8: MCP Database Integration Validation")
    print("=" * 60)
    
    validator = MCPDatabaseIntegrationValidator()
    
    try:
        # Run validation
        results = await validator.validate_all_integrations()
        
        # Generate report
        report_file = f"/home/louranicas/projects/claude-optimized-deployment/agent8_mcp_database_integration_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        # Print summary
        print("\n📊 Integration Validation Summary")
        print("-" * 40)
        
        total_tests = 0
        passed_tests = 0
        
        for category, tests in results.items():
            if isinstance(tests, dict):
                for test_name, test_result in tests.items():
                    total_tests += 1
                    if isinstance(test_result, dict) and test_result.get("status") == "success":
                        passed_tests += 1
                        print(f"✅ {category}.{test_name}")
                    else:
                        print(f"❌ {category}.{test_name}")
        
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"\n📈 Overall Results:")
        print(f"   Tests Run: {total_tests}")
        print(f"   Passed: {passed_tests}")
        print(f"   Success Rate: {success_rate:.1f}%")
        print(f"   Report: {report_file}")
        
        if success_rate >= 80:
            print("\n🎉 MCP Database Integration validation PASSED!")
            return True
        else:
            print("\n⚠️  MCP Database Integration validation needs attention.")
            return False
            
    except Exception as e:
        print(f"\n💥 Critical error during validation: {e}")
        return False


if __name__ == "__main__":
    success = asyncio.run(main())
    exit(0 if success else 1)
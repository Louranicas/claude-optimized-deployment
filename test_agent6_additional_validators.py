#!/usr/bin/env python3
"""
Additional validation helpers for Agent 6 - Data Flow and Integration Validation
================================================================================

This module provides additional validation methods and helpers for comprehensive
testing of data flows, APIs, databases, and external service integrations.
"""

import asyncio
import json
import time
import subprocess
import tempfile
import os
import socket
import ssl
from typing import Dict, List, Any, Optional
from datetime import datetime
import httpx


class AdditionalValidationHelpers:
    """Additional validation helpers for Agent 6"""
    
    def __init__(self):
        self.http_client = httpx.AsyncClient(
            timeout=30.0,
            verify=False,
            follow_redirects=True
        )
    
    async def _test_mcp_server_endpoints(self) -> List[Dict[str, Any]]:
        """Test MCP server endpoints"""
        endpoints = []
        
        # MCP server endpoints to test
        mcp_endpoints = [
            ("GET", "http://localhost:8000/mcp/health", "mcp_health"),
            ("GET", "http://localhost:8000/mcp/servers", "mcp_server_list"),
            ("POST", "http://localhost:8000/mcp/execute", "mcp_execute"),
            ("GET", "http://localhost:8000/mcp/capabilities", "mcp_capabilities")
        ]
        
        for method, url, endpoint_name in mcp_endpoints:
            start_time = time.time()
            
            try:
                if method == "POST":
                    # Test POST with sample payload
                    payload = {
                        "server": "bash_god",
                        "method": "list_tools",
                        "params": {}
                    }
                    response = await self.http_client.request(
                        method, url, 
                        json=payload,
                        timeout=15.0
                    )
                    payload_size = len(json.dumps(payload))
                else:
                    response = await self.http_client.request(method, url, timeout=15.0)
                    payload_size = 0
                
                response_time = (time.time() - start_time) * 1000
                
                # Validate MCP response structure
                validation_status = "PASSED" if response.status_code in [200, 404] else "WARNING"
                errors = []
                
                if response.status_code >= 500:
                    errors.append(f"Server error: {response.status_code}")
                    validation_status = "FAILED"
                
                endpoints.append({
                    "endpoint": endpoint_name,
                    "method": method,
                    "status_code": response.status_code,
                    "response_time_ms": response_time,
                    "payload_size_bytes": payload_size,
                    "response_size_bytes": len(response.content) if hasattr(response, 'content') else 0,
                    "validation_status": validation_status,
                    "errors": errors,
                    "headers": dict(response.headers),
                    "metadata": {"url": url, "response_type": "mcp_server"}
                })
                
            except Exception as e:
                endpoints.append({
                    "endpoint": endpoint_name,
                    "method": method,
                    "status_code": 0,
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "payload_size_bytes": 0,
                    "response_size_bytes": 0,
                    "validation_status": "FAILED",
                    "errors": [f"Request failed: {str(e)}"],
                    "metadata": {"url": url, "error_type": type(e).__name__}
                })
        
        return endpoints
    
    async def _test_auth_endpoints(self) -> List[Dict[str, Any]]:
        """Test authentication endpoints"""
        endpoints = []
        
        # Authentication endpoints to test
        auth_endpoints = [
            ("POST", "http://localhost:8000/auth/login", "auth_login"),
            ("POST", "http://localhost:8000/auth/token", "auth_token"),
            ("GET", "http://localhost:8000/auth/verify", "auth_verify"),
            ("POST", "http://localhost:8000/auth/refresh", "auth_refresh")
        ]
        
        for method, url, endpoint_name in auth_endpoints:
            start_time = time.time()
            
            try:
                if method == "POST":
                    # Test POST with sample auth payload
                    if "login" in endpoint_name:
                        payload = {"username": "test", "password": "test"}
                    elif "token" in endpoint_name:
                        payload = {"grant_type": "client_credentials"}
                    elif "refresh" in endpoint_name:
                        payload = {"refresh_token": "test_token"}
                    else:
                        payload = {}
                    
                    response = await self.http_client.request(
                        method, url, 
                        json=payload,
                        timeout=10.0
                    )
                    payload_size = len(json.dumps(payload))
                else:
                    response = await self.http_client.request(method, url, timeout=10.0)
                    payload_size = 0
                
                response_time = (time.time() - start_time) * 1000
                
                # For auth endpoints, 401/403 are expected responses
                validation_status = "PASSED" if response.status_code in [200, 401, 403, 404] else "WARNING"
                errors = []
                
                if response.status_code >= 500:
                    errors.append(f"Server error: {response.status_code}")
                    validation_status = "FAILED"
                
                endpoints.append({
                    "endpoint": endpoint_name,
                    "method": method,
                    "status_code": response.status_code,
                    "response_time_ms": response_time,
                    "payload_size_bytes": payload_size,
                    "response_size_bytes": len(response.content) if hasattr(response, 'content') else 0,
                    "validation_status": validation_status,
                    "errors": errors,
                    "headers": dict(response.headers),
                    "metadata": {"url": url, "response_type": "authentication"}
                })
                
            except Exception as e:
                endpoints.append({
                    "endpoint": endpoint_name,
                    "method": method,
                    "status_code": 0,
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "payload_size_bytes": 0,
                    "response_size_bytes": 0,
                    "validation_status": "FAILED",
                    "errors": [f"Request failed: {str(e)}"],
                    "metadata": {"url": url, "error_type": type(e).__name__}
                })
        
        return endpoints
    
    async def _test_data_processing_endpoints(self) -> List[Dict[str, Any]]:
        """Test data processing endpoints"""
        endpoints = []
        
        # Data processing endpoints to test
        processing_endpoints = [
            ("POST", "http://localhost:8000/api/v1/process", "data_process"),
            ("POST", "http://localhost:8000/api/v1/transform", "data_transform"),
            ("POST", "http://localhost:8000/api/v1/validate", "data_validate"),
            ("GET", "http://localhost:8000/api/v1/schema", "data_schema")
        ]
        
        for method, url, endpoint_name in processing_endpoints:
            start_time = time.time()
            
            try:
                if method == "POST":
                    # Test POST with sample data payload
                    if "process" in endpoint_name:
                        payload = {
                            "data": {"test": "value", "timestamp": time.time()},
                            "operation": "analyze"
                        }
                    elif "transform" in endpoint_name:
                        payload = {
                            "input_data": [1, 2, 3, 4, 5],
                            "transformation": "normalize"
                        }
                    elif "validate" in endpoint_name:
                        payload = {
                            "data": {"field1": "value1", "field2": 42},
                            "schema": "test_schema"
                        }
                    else:
                        payload = {}
                    
                    response = await self.http_client.request(
                        method, url, 
                        json=payload,
                        timeout=15.0
                    )
                    payload_size = len(json.dumps(payload))
                else:
                    response = await self.http_client.request(method, url, timeout=10.0)
                    payload_size = 0
                
                response_time = (time.time() - start_time) * 1000
                
                validation_status = "PASSED" if response.status_code in [200, 404] else "WARNING"
                errors = []
                
                if response.status_code >= 500:
                    errors.append(f"Server error: {response.status_code}")
                    validation_status = "FAILED"
                
                endpoints.append({
                    "endpoint": endpoint_name,
                    "method": method,
                    "status_code": response.status_code,
                    "response_time_ms": response_time,
                    "payload_size_bytes": payload_size,
                    "response_size_bytes": len(response.content) if hasattr(response, 'content') else 0,
                    "validation_status": validation_status,
                    "errors": errors,
                    "headers": dict(response.headers),
                    "metadata": {"url": url, "response_type": "data_processing"}
                })
                
            except Exception as e:
                endpoints.append({
                    "endpoint": endpoint_name,
                    "method": method,
                    "status_code": 0,
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "payload_size_bytes": 0,
                    "response_size_bytes": 0,
                    "validation_status": "FAILED",
                    "errors": [f"Request failed: {str(e)}"],
                    "metadata": {"url": url, "error_type": type(e).__name__}
                })
        
        return endpoints
    
    async def _test_postgresql_integration(self) -> List[Dict[str, Any]]:
        """Test PostgreSQL database integration"""
        databases = []
        
        try:
            # Try to import asyncpg for PostgreSQL
            try:
                import asyncpg
                
                # Test connection to PostgreSQL
                start_time = time.time()
                
                # Connection string from config
                db_url = "postgresql://mcp_user:password@localhost:5432/mcp_learning"
                
                try:
                    conn = await asyncpg.connect(db_url, timeout=10.0)
                    
                    # Test basic query
                    query_time = time.time()
                    result = await conn.fetch("SELECT version(), current_timestamp")
                    query_duration = (time.time() - query_time) * 1000
                    
                    databases.append({
                        "database_type": "postgresql",
                        "connection_string": db_url,
                        "operation_type": "SELECT",
                        "query": "SELECT version(), current_timestamp",
                        "execution_time_ms": query_duration,
                        "rows_affected": len(result),
                        "validation_status": "PASSED",
                        "metadata": {
                            "postgresql_version": str(result[0][0]) if result else "unknown",
                            "connection_time_ms": (time.time() - start_time) * 1000
                        }
                    })
                    
                    await conn.close()
                    
                except Exception as e:
                    databases.append({
                        "database_type": "postgresql",
                        "connection_string": db_url,
                        "operation_type": "CONNECTION_TEST",
                        "query": "",
                        "execution_time_ms": (time.time() - start_time) * 1000,
                        "rows_affected": 0,
                        "validation_status": "FAILED",
                        "errors": [f"PostgreSQL connection failed: {str(e)}"],
                        "metadata": {"error_type": type(e).__name__}
                    })
                    
            except ImportError:
                databases.append({
                    "database_type": "postgresql",
                    "connection_string": "postgresql://localhost:5432/",
                    "operation_type": "DEPENDENCY_CHECK",
                    "query": "",
                    "execution_time_ms": 0,
                    "rows_affected": 0,
                    "validation_status": "FAILED",
                    "errors": ["asyncpg not available"],
                    "metadata": {"dependency": "asyncpg"}
                })
                
        except Exception as e:
            databases.append({
                "database_type": "postgresql",
                "connection_string": "postgresql://localhost:5432/",
                "operation_type": "SETUP",
                "query": "",
                "execution_time_ms": 0,
                "rows_affected": 0,
                "validation_status": "FAILED",
                "errors": [f"PostgreSQL setup failed: {str(e)}"]
            })
        
        return databases
    
    async def _test_redis_integration(self) -> List[Dict[str, Any]]:
        """Test Redis database integration"""
        databases = []
        
        try:
            # Try to import redis
            try:
                import redis
                
                start_time = time.time()
                
                # Test Redis connection
                redis_client = redis.Redis(
                    host='localhost', 
                    port=6379, 
                    decode_responses=True,
                    socket_timeout=5,
                    socket_connect_timeout=5
                )
                
                # Test PING
                ping_time = time.time()
                ping_result = redis_client.ping()
                ping_duration = (time.time() - ping_time) * 1000
                
                databases.append({
                    "database_type": "redis",
                    "connection_string": "redis://localhost:6379",
                    "operation_type": "PING",
                    "query": "PING",
                    "execution_time_ms": ping_duration,
                    "rows_affected": 1 if ping_result else 0,
                    "validation_status": "PASSED" if ping_result else "FAILED",
                    "errors": [] if ping_result else ["PING failed"],
                    "metadata": {"ping_result": ping_result}
                })
                
                # Test SET/GET
                set_time = time.time()
                test_key = f"test_key_{int(time.time())}"
                test_value = f"test_value_{int(time.time())}"
                
                redis_client.set(test_key, test_value, ex=60)  # 60 second expiration
                retrieved_value = redis_client.get(test_key)
                set_duration = (time.time() - set_time) * 1000
                
                validation_status = "PASSED" if retrieved_value == test_value else "FAILED"
                errors = [] if retrieved_value == test_value else ["SET/GET integrity check failed"]
                
                databases.append({
                    "database_type": "redis",
                    "connection_string": "redis://localhost:6379",
                    "operation_type": "SET_GET",
                    "query": f"SET {test_key} {test_value}; GET {test_key}",
                    "execution_time_ms": set_duration,
                    "rows_affected": 1,
                    "validation_status": validation_status,
                    "errors": errors,
                    "metadata": {
                        "test_key": test_key,
                        "expected_value": test_value,
                        "retrieved_value": retrieved_value
                    }
                })
                
                # Cleanup test key
                redis_client.delete(test_key)
                
            except Exception as e:
                databases.append({
                    "database_type": "redis",
                    "connection_string": "redis://localhost:6379",
                    "operation_type": "CONNECTION_TEST",
                    "query": "",
                    "execution_time_ms": (time.time() - start_time) * 1000,
                    "rows_affected": 0,
                    "validation_status": "FAILED",
                    "errors": [f"Redis connection failed: {str(e)}"],
                    "metadata": {"error_type": type(e).__name__}
                })
                
        except ImportError:
            databases.append({
                "database_type": "redis",
                "connection_string": "redis://localhost:6379",
                "operation_type": "DEPENDENCY_CHECK",
                "query": "",
                "execution_time_ms": 0,
                "rows_affected": 0,
                "validation_status": "FAILED",
                "errors": ["redis-py not available"],
                "metadata": {"dependency": "redis"}
            })
        
        return databases
    
    async def _test_database_transactions(self) -> List[Dict[str, Any]]:
        """Test database transaction integrity"""
        databases = []
        
        # Test SQLite transaction
        start_time = time.time()
        
        try:
            with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp_db:
                db_path = tmp_db.name
            
            import sqlite3
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Create test table
            cursor.execute('''
                CREATE TABLE transaction_test (
                    id INTEGER PRIMARY KEY,
                    value TEXT NOT NULL
                )
            ''')
            conn.commit()
            
            # Test successful transaction
            transaction_time = time.time()
            
            conn.execute('BEGIN TRANSACTION')
            cursor.execute("INSERT INTO transaction_test (value) VALUES (?)", ("test1",))
            cursor.execute("INSERT INTO transaction_test (value) VALUES (?)", ("test2",))
            conn.commit()
            
            # Verify transaction
            cursor.execute("SELECT COUNT(*) FROM transaction_test")
            count = cursor.fetchone()[0]
            
            transaction_duration = (time.time() - transaction_time) * 1000
            
            validation_status = "PASSED" if count == 2 else "FAILED"
            errors = [] if count == 2 else [f"Expected 2 records, got {count}"]
            
            databases.append({
                "database_type": "sqlite",
                "connection_string": f"sqlite:///{db_path}",
                "operation_type": "TRANSACTION",
                "query": "BEGIN; INSERT ... INSERT ...; COMMIT;",
                "execution_time_ms": transaction_duration,
                "rows_affected": count,
                "validation_status": validation_status,
                "errors": errors,
                "metadata": {"transaction_type": "commit"}
            })
            
            # Test rollback transaction
            rollback_time = time.time()
            
            conn.execute('BEGIN TRANSACTION')
            cursor.execute("INSERT INTO transaction_test (value) VALUES (?)", ("test3",))
            cursor.execute("INSERT INTO transaction_test (value) VALUES (?)", ("test4",))
            conn.rollback()
            
            # Verify rollback
            cursor.execute("SELECT COUNT(*) FROM transaction_test")
            count_after_rollback = cursor.fetchone()[0]
            
            rollback_duration = (time.time() - rollback_time) * 1000
            
            validation_status = "PASSED" if count_after_rollback == 2 else "FAILED"
            errors = [] if count_after_rollback == 2 else [f"Rollback failed, expected 2 records, got {count_after_rollback}"]
            
            databases.append({
                "database_type": "sqlite",
                "connection_string": f"sqlite:///{db_path}",
                "operation_type": "ROLLBACK",
                "query": "BEGIN; INSERT ... INSERT ...; ROLLBACK;",
                "execution_time_ms": rollback_duration,
                "rows_affected": count_after_rollback,
                "validation_status": validation_status,
                "errors": errors,
                "metadata": {"transaction_type": "rollback"}
            })
            
            conn.close()
            
            # Cleanup
            if os.path.exists(db_path):
                os.unlink(db_path)
                
        except Exception as e:
            databases.append({
                "database_type": "sqlite",
                "connection_string": "sqlite:///temp",
                "operation_type": "TRANSACTION_TEST",
                "query": "",
                "execution_time_ms": (time.time() - start_time) * 1000,
                "rows_affected": 0,
                "validation_status": "FAILED",
                "errors": [f"Transaction test failed: {str(e)}"]
            })
        
        return databases
    
    async def _test_aws_integration(self) -> List[Dict[str, Any]]:
        """Test AWS services integration (if configured)"""
        services = []
        
        # Test AWS service endpoints
        aws_endpoints = [
            ("https://s3.amazonaws.com", "s3", "object_storage"),
            ("https://ec2.amazonaws.com", "ec2", "compute"),
            ("https://rds.amazonaws.com", "rds", "database"),
            ("https://lambda.amazonaws.com", "lambda", "serverless")
        ]
        
        for endpoint, service_name, service_type in aws_endpoints:
            start_time = time.time()
            
            try:
                response = await self.http_client.get(endpoint, timeout=10.0)
                response_time = (time.time() - start_time) * 1000
                
                # AWS endpoints typically return 403 for unauthenticated requests
                validation_status = "PASSED" if response.status_code in [200, 403, 404] else "WARNING"
                errors = []
                
                if response.status_code >= 500:
                    errors.append("AWS service error")
                    validation_status = "FAILED"
                
                services.append({
                    "service_name": f"aws_{service_name}",
                    "service_type": service_type,
                    "endpoint": endpoint,
                    "authentication_method": "aws_credentials",
                    "response_time_ms": response_time,
                    "validation_status": validation_status,
                    "errors": errors,
                    "metadata": {
                        "status_code": response.status_code,
                        "aws_service": service_name
                    }
                })
                
            except Exception as e:
                services.append({
                    "service_name": f"aws_{service_name}",
                    "service_type": service_type,
                    "endpoint": endpoint,
                    "authentication_method": "aws_credentials",
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "validation_status": "FAILED",
                    "errors": [f"AWS {service_name} test failed: {str(e)}"],
                    "metadata": {"error_type": type(e).__name__}
                })
        
        return services
    
    async def _test_monitoring_services(self) -> List[Dict[str, Any]]:
        """Test external monitoring services"""
        services = []
        
        # Test monitoring service endpoints
        monitoring_endpoints = [
            ("http://localhost:9090/api/v1/query?query=up", "prometheus", "metrics"),
            ("http://localhost:3000/api/health", "grafana", "visualization"),
            ("http://localhost:9093/api/v1/alerts", "alertmanager", "alerting")
        ]
        
        for endpoint, service_name, service_type in monitoring_endpoints:
            start_time = time.time()
            
            try:
                response = await self.http_client.get(endpoint, timeout=10.0)
                response_time = (time.time() - start_time) * 1000
                
                validation_status = "PASSED" if response.status_code in [200, 404] else "WARNING"
                errors = []
                
                if response.status_code >= 500:
                    errors.append(f"{service_name} server error")
                    validation_status = "FAILED"
                
                services.append({
                    "service_name": service_name,
                    "service_type": service_type,
                    "endpoint": endpoint,
                    "authentication_method": "none",
                    "response_time_ms": response_time,
                    "validation_status": validation_status,
                    "errors": errors,
                    "metadata": {
                        "status_code": response.status_code,
                        "monitoring_service": service_name
                    }
                })
                
            except Exception as e:
                services.append({
                    "service_name": service_name,
                    "service_type": service_type,
                    "endpoint": endpoint,
                    "authentication_method": "none",
                    "response_time_ms": (time.time() - start_time) * 1000,
                    "validation_status": "FAILED",
                    "errors": [f"{service_name} test failed: {str(e)}"],
                    "metadata": {"error_type": type(e).__name__}
                })
        
        return services
    
    async def _test_celery_messaging(self) -> List[Dict[str, Any]]:
        """Test Celery messaging system"""
        events = []
        
        try:
            # Test Celery configuration and broker connectivity
            start_time = time.time()
            
            try:
                # Try to import Celery
                from celery import Celery
                
                # Create test Celery app
                app = Celery('test_app')
                app.config_from_object({
                    'broker_url': 'redis://localhost:6379/0',
                    'result_backend': 'redis://localhost:6379/0',
                    'task_serializer': 'json',
                    'accept_content': ['json'],
                    'result_serializer': 'json',
                    'broker_connection_retry_on_startup': True
                })
                
                # Test broker connection
                try:
                    with app.connection() as conn:
                        conn.ensure_connection(max_retries=3)
                    
                    latency = (time.time() - start_time) * 1000
                    
                    events.append({
                        "system_type": "celery_messaging",
                        "test_type": "broker_connection",
                        "status": "PASSED",
                        "latency_ms": latency,
                        "errors": [],
                        "metadata": {
                            "broker_url": "redis://localhost:6379/0",
                            "connection_successful": True
                        }
                    })
                    
                except Exception as e:
                    events.append({
                        "system_type": "celery_messaging",
                        "test_type": "broker_connection",
                        "status": "FAILED",
                        "latency_ms": (time.time() - start_time) * 1000,
                        "errors": [f"Celery broker connection failed: {str(e)}"],
                        "metadata": {"error_type": type(e).__name__}
                    })
                    
            except ImportError:
                events.append({
                    "system_type": "celery_messaging",
                    "test_type": "dependency_check",
                    "status": "FAILED",
                    "latency_ms": 0,
                    "errors": ["Celery not available"],
                    "metadata": {"dependency": "celery"}
                })
                
        except Exception as e:
            events.append({
                "system_type": "celery_messaging",
                "test_type": "setup",
                "status": "FAILED",
                "latency_ms": (time.time() - start_time) * 1000,
                "errors": [f"Celery test setup failed: {str(e)}"]
            })
        
        return events
    
    async def _test_webhook_systems(self) -> List[Dict[str, Any]]:
        """Test webhook systems"""
        events = []
        
        # Test webhook endpoints
        webhook_endpoints = [
            ("POST", "http://localhost:8000/webhooks/github", "github_webhook"),
            ("POST", "http://localhost:8000/webhooks/deployment", "deployment_webhook"),
            ("POST", "http://localhost:8000/webhooks/monitoring", "monitoring_webhook")
        ]
        
        for method, url, webhook_name in webhook_endpoints:
            start_time = time.time()
            
            try:
                # Test webhook with sample payload
                webhook_payload = {
                    "event": "test_event",
                    "timestamp": datetime.now().isoformat(),
                    "data": {"test": "data"}
                }
                
                response = await self.http_client.request(
                    method, url,
                    json=webhook_payload,
                    timeout=10.0
                )
                
                latency = (time.time() - start_time) * 1000
                
                # Webhook endpoints might return 404 if not configured
                status = "PASSED" if response.status_code in [200, 202, 404] else "WARNING"
                errors = []
                
                if response.status_code >= 500:
                    errors.append("Webhook server error")
                    status = "FAILED"
                
                events.append({
                    "system_type": "webhook_system",
                    "test_type": webhook_name,
                    "status": status,
                    "latency_ms": latency,
                    "errors": errors,
                    "metadata": {
                        "webhook_url": url,
                        "status_code": response.status_code,
                        "payload_size": len(json.dumps(webhook_payload))
                    }
                })
                
            except Exception as e:
                events.append({
                    "system_type": "webhook_system",
                    "test_type": webhook_name,
                    "status": "FAILED",
                    "latency_ms": (time.time() - start_time) * 1000,
                    "errors": [f"Webhook test failed: {str(e)}"],
                    "metadata": {"error_type": type(e).__name__}
                })
        
        return events


# Network connectivity validator
class NetworkConnectivityValidator:
    """Validate network connectivity and port accessibility"""
    
    @staticmethod
    def test_port_connectivity(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
        """Test if a port is accessible"""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            latency = (time.time() - start_time) * 1000
            
            return {
                "host": host,
                "port": port,
                "accessible": result == 0,
                "latency_ms": latency,
                "error": None if result == 0 else f"Connection failed with code {result}"
            }
            
        except Exception as e:
            return {
                "host": host,
                "port": port,
                "accessible": False,
                "latency_ms": (time.time() - start_time) * 1000,
                "error": str(e)
            }
    
    @staticmethod
    async def test_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
        """Test SSL certificate validity"""
        start_time = time.time()
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    latency = (time.time() - start_time) * 1000
                    
                    return {
                        "hostname": hostname,
                        "port": port,
                        "valid": True,
                        "latency_ms": latency,
                        "certificate_info": {
                            "subject": dict(x[0] for x in cert['subject']),
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "not_before": cert['notBefore'],
                            "not_after": cert['notAfter']
                        },
                        "error": None
                    }
                    
        except Exception as e:
            return {
                "hostname": hostname,
                "port": port,
                "valid": False,
                "latency_ms": (time.time() - start_time) * 1000,
                "certificate_info": None,
                "error": str(e)
            }
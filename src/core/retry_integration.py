"""
Integration module for comprehensive retry patterns.

This module provides:
- Integration with existing circuit breaker system
- Unified retry and degradation management
- Configuration-driven setup
- Monitoring and metrics aggregation
- Service discovery integration
"""

import asyncio
import logging
from typing import Any, Callable, Dict, Optional, TypeVar, Union
from dataclasses import dataclass

from src.core.retry_patterns import (
    ComprehensiveRetryHandler, RetryPolicyConfig, ServiceType,
    get_retry_handler, comprehensive_retry
)
from src.core.retry_config import get_config_manager, RetryConfigManager
from src.core.retry_monitoring import get_retry_monitor, record_retry_event
from src.core.graceful_degradation import (
    get_service_mesh, ServiceMesh, FallbackStrategy, ServicePriority,
    with_degradation
)

try:
    from src.core.circuit_breaker import get_circuit_breaker_manager, CircuitBreakerConfig
    CIRCUIT_BREAKER_AVAILABLE = True
except ImportError:
    CIRCUIT_BREAKER_AVAILABLE = False

logger = logging.getLogger(__name__)

T = TypeVar('T')


@dataclass
class UnifiedServiceConfig:
    """Unified configuration for service resilience patterns."""
    service_name: str
    service_type: ServiceType = ServiceType.UNKNOWN
    
    # Retry configuration
    retry_enabled: bool = True
    retry_config: Optional[RetryPolicyConfig] = None
    
    # Circuit breaker configuration
    circuit_breaker_enabled: bool = True
    circuit_breaker_config: Optional[CircuitBreakerConfig] = None
    
    # Graceful degradation configuration
    degradation_enabled: bool = True
    fallback_strategy: Optional[FallbackStrategy] = None
    service_priority: ServicePriority = ServicePriority.MEDIUM
    
    # Monitoring configuration
    monitoring_enabled: bool = True
    metrics_enabled: bool = True


class UnifiedRetryManager:
    """Unified manager for all retry and resilience patterns."""
    
    def __init__(self):
        """Initialize unified retry manager."""
        self.config_manager = get_config_manager()
        self.service_mesh = get_service_mesh()
        self.retry_monitor = get_retry_monitor()
        self.service_configs: Dict[str, UnifiedServiceConfig] = {}
        self.initialized_services: set = set()
        
        if CIRCUIT_BREAKER_AVAILABLE:
            self.circuit_breaker_manager = get_circuit_breaker_manager()
        else:
            self.circuit_breaker_manager = None
            logger.warning("Circuit breaker manager not available")
    
    async def register_service(self, config: UnifiedServiceConfig) -> bool:
        """Register a service with unified configuration."""
        try:
            service_name = config.service_name
            
            # Register retry configuration
            if config.retry_enabled and config.retry_config:
                self.config_manager.add_service_config(service_name, config.retry_config)
            
            # Register circuit breaker if available
            if (config.circuit_breaker_enabled and 
                config.circuit_breaker_config and 
                self.circuit_breaker_manager):
                await self.circuit_breaker_manager.get_or_create(
                    service_name, config.circuit_breaker_config
                )
            
            # Register in service mesh for degradation
            if config.degradation_enabled:
                await self.service_mesh.register_service(
                    service_name,
                    fallback_strategy=config.fallback_strategy,
                    bulkhead_config={'max_concurrent': 10, 'queue_size': 50},
                    load_shedding_config=None  # Could be added based on service type
                )
            
            # Store configuration
            self.service_configs[service_name] = config
            self.initialized_services.add(service_name)
            
            logger.info(f"Successfully registered service: {service_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to register service {config.service_name}: {e}")
            return False
    
    async def call_service(
        self,
        service_name: str,
        operation: Callable[..., T],
        *args,
        **kwargs
    ) -> T:
        """Call service with all resilience patterns applied."""
        if service_name not in self.service_configs:
            # Auto-register with default configuration
            await self._auto_register_service(service_name)
        
        config = self.service_configs[service_name]
        
        # Determine which patterns to apply
        apply_retry = config.retry_enabled
        apply_degradation = config.degradation_enabled
        
        if apply_retry and apply_degradation:
            # Apply both retry and degradation patterns
            return await self._call_with_both_patterns(
                service_name, operation, config, *args, **kwargs
            )
        elif apply_retry:
            # Apply only retry patterns
            return await self._call_with_retry_only(
                service_name, operation, config, *args, **kwargs
            )
        elif apply_degradation:
            # Apply only degradation patterns
            return await self._call_with_degradation_only(
                service_name, operation, config, *args, **kwargs
            )
        else:
            # No patterns applied, direct call
            return await self._execute_operation(operation, *args, **kwargs)
    
    async def _call_with_both_patterns(
        self,
        service_name: str,
        operation: Callable[..., T],
        config: UnifiedServiceConfig,
        *args,
        **kwargs
    ) -> T:
        """Apply both retry and degradation patterns."""
        # Wrap operation with degradation patterns
        async def degraded_operation(*args, **kwargs):
            return await with_degradation(
                service_name,
                operation,
                *args,
                priority=config.service_priority,
                fallback_strategy=config.fallback_strategy,
                **kwargs
            )
        
        # Apply retry patterns to the degraded operation
        handler = await get_retry_handler(
            service_name,
            config.service_type,
            config.retry_config
        )
        
        return await handler.execute(degraded_operation, *args, **kwargs)
    
    async def _call_with_retry_only(
        self,
        service_name: str,
        operation: Callable[..., T],
        config: UnifiedServiceConfig,
        *args,
        **kwargs
    ) -> T:
        """Apply only retry patterns."""
        handler = await get_retry_handler(
            service_name,
            config.service_type,
            config.retry_config
        )
        
        return await handler.execute(operation, *args, **kwargs)
    
    async def _call_with_degradation_only(
        self,
        service_name: str,
        operation: Callable[..., T],
        config: UnifiedServiceConfig,
        *args,
        **kwargs
    ) -> T:
        """Apply only degradation patterns."""
        return await with_degradation(
            service_name,
            operation,
            *args,
            priority=config.service_priority,
            fallback_strategy=config.fallback_strategy,
            **kwargs
        )
    
    async def _execute_operation(
        self,
        operation: Callable[..., T],
        *args,
        **kwargs
    ) -> T:
        """Execute operation directly without patterns."""
        if asyncio.iscoroutinefunction(operation):
            return await operation(*args, **kwargs)
        else:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(None, operation, *args, **kwargs)
    
    async def _auto_register_service(self, service_name: str):
        """Auto-register service with default configuration."""
        # Try to infer service type from name
        service_type = self._infer_service_type(service_name)
        
        # Get default configuration from config manager
        default_retry_config = await self.config_manager.get_policy(service_name, service_type)
        
        # Create unified configuration
        unified_config = UnifiedServiceConfig(
            service_name=service_name,
            service_type=service_type,
            retry_config=default_retry_config
        )
        
        await self.register_service(unified_config)
        logger.info(f"Auto-registered service with defaults: {service_name}")
    
    def _infer_service_type(self, service_name: str) -> ServiceType:
        """Infer service type from service name."""
        name_lower = service_name.lower()
        
        if any(ai in name_lower for ai in ['claude', 'anthropic']):
            return ServiceType.AI_CLAUDE
        elif any(ai in name_lower for ai in ['openai', 'gpt']):
            return ServiceType.AI_OPENAI
        elif any(ai in name_lower for ai in ['google', 'gemini']):
            return ServiceType.AI_GOOGLE
        elif 'database' in name_lower or 'db' in name_lower or 'postgres' in name_lower:
            return ServiceType.DATABASE
        elif 'cache' in name_lower or 'redis' in name_lower:
            return ServiceType.CACHE
        elif 'api' in name_lower:
            return ServiceType.HTTP_API
        elif 'storage' in name_lower or 's3' in name_lower:
            return ServiceType.STORAGE
        else:
            return ServiceType.UNKNOWN
    
    async def get_service_status(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive status for a service."""
        if service_name not in self.service_configs:
            return None
        
        config = self.service_configs[service_name]
        status = {
            'service_name': service_name,
            'service_type': config.service_type.value,
            'patterns_enabled': {
                'retry': config.retry_enabled,
                'circuit_breaker': config.circuit_breaker_enabled,
                'degradation': config.degradation_enabled,
                'monitoring': config.monitoring_enabled
            }
        }
        
        # Get retry handler metrics
        if config.retry_enabled:
            try:
                handler = await get_retry_handler(service_name, config.service_type)
                status['retry_metrics'] = handler.get_metrics()
            except Exception as e:
                logger.warning(f"Failed to get retry metrics for {service_name}: {e}")
        
        # Get circuit breaker status
        if config.circuit_breaker_enabled and self.circuit_breaker_manager:
            try:
                circuit_breaker = self.circuit_breaker_manager.get(service_name)
                if circuit_breaker:
                    status['circuit_breaker_metrics'] = circuit_breaker.get_metrics()
            except Exception as e:
                logger.warning(f"Failed to get circuit breaker metrics for {service_name}: {e}")
        
        # Get service mesh status
        if config.degradation_enabled:
            try:
                mesh_status = await self.service_mesh.get_service_status(service_name)
                if mesh_status:
                    status['degradation_status'] = mesh_status
            except Exception as e:
                logger.warning(f"Failed to get degradation status for {service_name}: {e}")
        
        return status
    
    async def get_all_services_status(self) -> Dict[str, Any]:
        """Get status for all registered services."""
        all_status = {
            'summary': {
                'total_services': len(self.service_configs),
                'initialized_services': len(self.initialized_services)
            },
            'services': {}
        }
        
        for service_name in self.service_configs:
            try:
                status = await self.get_service_status(service_name)
                if status:
                    all_status['services'][service_name] = status
            except Exception as e:
                logger.warning(f"Failed to get status for service {service_name}: {e}")
        
        return all_status
    
    async def update_service_config(
        self,
        service_name: str,
        updates: Dict[str, Any]
    ) -> bool:
        """Update configuration for a service."""
        if service_name not in self.service_configs:
            logger.error(f"Service not registered: {service_name}")
            return False
        
        try:
            config = self.service_configs[service_name]
            
            # Update configuration fields
            for key, value in updates.items():
                if hasattr(config, key):
                    setattr(config, key, value)
                else:
                    logger.warning(f"Unknown configuration key: {key}")
            
            # Re-register service with updated configuration
            success = await self.register_service(config)
            
            if success:
                logger.info(f"Updated configuration for service: {service_name}")
            
            return success
            
        except Exception as e:
            logger.error(f"Failed to update configuration for {service_name}: {e}")
            return False
    
    async def export_comprehensive_metrics(self, filepath: str):
        """Export comprehensive metrics from all components."""
        try:
            import json
            from datetime import datetime
            
            metrics = {
                'timestamp': datetime.now().isoformat(),
                'services': await self.get_all_services_status()
            }
            
            # Add retry monitor metrics
            try:
                retry_metrics = await self.retry_monitor.get_dashboard_data()
                metrics['retry_monitoring'] = retry_metrics
            except Exception as e:
                logger.warning(f"Failed to get retry monitoring metrics: {e}")
            
            # Add service mesh overview
            try:
                mesh_overview = await self.service_mesh.get_mesh_overview()
                metrics['service_mesh'] = mesh_overview
            except Exception as e:
                logger.warning(f"Failed to get service mesh metrics: {e}")
            
            # Add circuit breaker summary
            if self.circuit_breaker_manager:
                try:
                    cb_summary = self.circuit_breaker_manager.get_summary()
                    metrics['circuit_breakers'] = cb_summary
                except Exception as e:
                    logger.warning(f"Failed to get circuit breaker metrics: {e}")
            
            with open(filepath, 'w') as f:
                json.dump(metrics, f, indent=2, default=str)
            
            logger.info(f"Exported comprehensive metrics to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to export comprehensive metrics: {e}")


# Global unified manager instance
_unified_manager = UnifiedRetryManager()


def get_unified_manager() -> UnifiedRetryManager:
    """Get the global unified retry manager."""
    return _unified_manager


async def resilient_call(
    service_name: str,
    operation: Callable[..., T],
    *args,
    **kwargs
) -> T:
    """Make a resilient service call with all patterns applied."""
    manager = get_unified_manager()
    return await manager.call_service(service_name, operation, *args, **kwargs)


def resilient_service(
    service_name: str,
    service_type: ServiceType = ServiceType.UNKNOWN,
    retry_enabled: bool = True,
    circuit_breaker_enabled: bool = True,
    degradation_enabled: bool = True,
    priority: ServicePriority = ServicePriority.MEDIUM
):
    """Decorator for making service calls resilient."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Auto-register service if not already registered
            manager = get_unified_manager()
            if service_name not in manager.service_configs:
                config = UnifiedServiceConfig(
                    service_name=service_name,
                    service_type=service_type,
                    retry_enabled=retry_enabled,
                    circuit_breaker_enabled=circuit_breaker_enabled,
                    degradation_enabled=degradation_enabled,
                    service_priority=priority
                )
                await manager.register_service(config)
            
            return await resilient_call(service_name, func, *args, **kwargs)
        
        return wrapper
    return decorator


async def initialize_from_config_file(config_file: str) -> bool:
    """Initialize all retry patterns from configuration file."""
    try:
        manager = get_unified_manager()
        
        # Load configuration
        if not manager.config_manager.load_from_file(config_file):
            logger.error(f"Failed to load configuration from {config_file}")
            return False
        
        # Register services based on configuration
        for service_name, retry_config in manager.config_manager.service_configs.items():
            unified_config = UnifiedServiceConfig(
                service_name=service_name,
                service_type=retry_config.service_type,
                retry_config=retry_config,
                retry_enabled=True,
                circuit_breaker_enabled=retry_config.enable_circuit_breaker,
                degradation_enabled=True  # Enable by default
            )
            
            await manager.register_service(unified_config)
        
        logger.info(f"Initialized {len(manager.service_configs)} services from configuration")
        return True
        
    except Exception as e:
        logger.error(f"Failed to initialize from config file {config_file}: {e}")
        return False


# Export public API
__all__ = [
    'UnifiedServiceConfig',
    'UnifiedRetryManager',
    'get_unified_manager',
    'resilient_call',
    'resilient_service',
    'initialize_from_config_file',
]
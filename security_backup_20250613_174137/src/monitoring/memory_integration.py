"""
Memory monitoring integration module.

Integrates all memory monitoring components:
- Enhanced metrics collection
- Alert handling with automated responses
- Health monitoring
- Performance baseline tracking
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from .enhanced_memory_metrics import get_enhanced_memory_metrics, record_memory_event
from .memory_response import get_memory_pressure_handler, ResponseAction
from .alerts import get_alert_manager, register_alert_handler, Alert
from ..core.log_sanitization import sanitize_for_logging, SanitizationLevel

__all__ = [
    "MemoryMonitoringIntegration",
    "get_memory_integration",
    "get_monitoring_config"
]



class MemoryMonitoringIntegration:
    """Integrated memory monitoring system."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.enhanced_metrics = get_enhanced_memory_metrics()
        self.pressure_handler = get_memory_pressure_handler()
        self.alert_manager = get_alert_manager()
        
        # Register memory alert handler
        register_alert_handler(self._handle_memory_alert, is_async=True)
        
        self.logger.info("Memory monitoring integration initialized")
        record_memory_event("monitoring_initialized")
    
    async def _handle_memory_alert(self, alert: Alert):
        """Handle memory-related alerts with automated responses."""
        try:
            # Check if this is a memory-related alert
            if not self._is_memory_alert(alert):
                return
            
            self.logger.warning(f"Memory alert received: {alert.rule.name}")
            record_memory_event(f"alert_{alert.rule.name.lower()}")
            
            # Execute automated response
            actions = await self.pressure_handler.handle_memory_alert(alert)
            
            # Log response summary
            self._log_response_actions(alert, actions)
            
            # Update metrics based on response
            self._update_response_metrics(actions)
            
        except Exception as e:
            safe_error = sanitize_for_logging(str(e), SanitizationLevel.STRICT, "alert_handler_error")
            self.logger.error(f"Error handling memory alert: {safe_error}")
            record_memory_event("alert_handler_error")
    
    def _is_memory_alert(self, alert: Alert) -> bool:
        """Check if alert is memory-related."""
        memory_keywords = [
            'memory', 'heap', 'gc', 'swap', 'rss', 'vms',
            'fragmentation', 'leak', 'pressure', 'exhaustion'
        ]
        
        alert_name_lower = alert.rule.name.lower()
        return any(keyword in alert_name_lower for keyword in memory_keywords)
    
    def _log_response_actions(self, alert: Alert, actions: list[ResponseAction]):
        """Log the response actions taken for an alert."""
        if not actions:
            self.logger.info(f"No actions taken for alert: {alert.rule.name}")
            return
        
        successful_actions = [a for a in actions if a.success]
        failed_actions = [a for a in actions if not a.success]
        
        total_memory_freed = sum(a.memory_freed_mb for a in successful_actions)
        
        log_message = (
            f"Memory alert response for {alert.rule.name}: "
            f"{len(successful_actions)}/{len(actions)} actions successful, "
            f"{total_memory_freed:.1f}MB freed"
        )
        
        if failed_actions:
            failed_names = [a.name for a in failed_actions]
            log_message += f", Failed: {', '.join(failed_names)}"
        
        if alert.rule.severity.value in ['critical', 'high']:
            self.logger.error(log_message)
        elif alert.rule.severity.value == 'medium':
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)
    
    def _update_response_metrics(self, actions: list[ResponseAction]):
        """Update metrics based on response actions."""
        for action in actions:
            # Record action event
            status = "success" if action.success else "error"
            record_memory_event(f"response_{action.name}_{status}")
            
            # Record memory freed if significant
            if action.memory_freed_mb > 1:  # More than 1MB freed
                record_memory_event(f"memory_freed_{int(action.memory_freed_mb)}mb")
    
    async def get_memory_health_status(self) -> Dict[str, Any]:
        """Get comprehensive memory health status."""
        try:
            # Get enhanced memory report
            health_report = self.enhanced_metrics.get_memory_health_report()
            
            # Get recent response history
            response_history = self.pressure_handler.get_response_history(hours=1)
            
            # Get active memory alerts
            memory_alerts = [
                alert for alert in self.alert_manager.get_active_alerts()
                if self._is_memory_alert(alert)
            ]
            
            # Compile comprehensive status
            status = {
                'timestamp': datetime.now().isoformat(),
                'health_report': health_report,
                'active_alerts': len(memory_alerts),
                'recent_responses': len(response_history),
                'emergency_mode': self.pressure_handler.emergency_mode,
                'monitoring_active': self.enhanced_metrics._monitoring_active,
                'alerts': [
                    {
                        'name': alert.rule.name,
                        'severity': alert.rule.severity.value,
                        'state': alert.state.value,
                        'started_at': alert.started_at.isoformat(),
                        'value': alert.value
                    }
                    for alert in memory_alerts
                ],
                'recent_actions': response_history[-5:] if response_history else []
            }
            
            return status
            
        except Exception as e:
            safe_error = sanitize_for_logging(str(e), SanitizationLevel.STRICT, "health_status_error")
            return {
                'error': f"Failed to get memory health status: {safe_error}",
                'timestamp': datetime.now().isoformat()
            }
    
    async def force_memory_check(self) -> Dict[str, Any]:
        """Force a comprehensive memory check and return results."""
        try:
            self.logger.info("Forcing comprehensive memory check")
            record_memory_event("manual_memory_check")
            
            # Force metrics update
            self.enhanced_metrics.update_all_metrics()
            
            # Force garbage collection and measure impact
            gc_result = self.enhanced_metrics.force_gc_and_measure()
            
            # Get current health status
            health_status = await self.get_memory_health_status()
            
            result = {
                'check_type': 'manual_comprehensive',
                'timestamp': datetime.now().isoformat(),
                'gc_result': gc_result,
                'health_status': health_status,
                'success': True
            }
            
            self.logger.info(f"Memory check completed: {gc_result.get('memory_freed_mb', 0):.1f}MB freed by GC")
            return result
            
        except Exception as e:
            safe_error = sanitize_for_logging(str(e), SanitizationLevel.STRICT, "memory_check_error")
            self.logger.error(f"Failed to perform memory check: {safe_error}")
            
            return {
                'check_type': 'manual_comprehensive',
                'timestamp': datetime.now().isoformat(),
                'error': safe_error,
                'success': False
            }
    
    async def simulate_memory_pressure(self, level: str = "medium") -> Dict[str, Any]:
        """Simulate memory pressure for testing response systems."""
        try:
            self.logger.warning(f"Simulating {level} memory pressure for testing")
            record_memory_event(f"simulate_pressure_{level}")
            
            # Create simulated alert based on level
            from .alerts import AlertRule, AlertSeverity, Alert, AlertState
            from datetime import timedelta
            
            severity_map = {
                'low': AlertSeverity.LOW,
                'medium': AlertSeverity.MEDIUM,
                'high': AlertSeverity.HIGH,
                'critical': AlertSeverity.CRITICAL
            }
            
            # Create test alert rule
            test_rule = AlertRule(
                name=f"TestMemoryPressure{level.title()}",
                expression=f"memory_usage_bytes{{type='percent'}} > {70 + (list(severity_map.keys()).index(level) * 10)}",
                duration=timedelta(minutes=1),
                severity=severity_map.get(level, AlertSeverity.MEDIUM),
                annotations={
                    'summary': f'Simulated {level} memory pressure',
                    'description': f'Testing memory pressure response system at {level} level'
                }
            )
            
            # Create test alert
            test_alert = Alert(
                rule=test_rule,
                state=AlertState.FIRING,
                started_at=datetime.now(),
                fired_at=datetime.now(),
                value=70 + (list(severity_map.keys()).index(level) * 10),
                labels={'instance': 'test', 'severity': level},
                annotations=test_rule.annotations
            )
            
            # Execute response
            actions = await self.pressure_handler.handle_memory_alert(test_alert)
            
            result = {
                'simulation_type': f'{level}_memory_pressure',
                'timestamp': datetime.now().isoformat(),
                'alert_triggered': test_rule.name,
                'actions_executed': len(actions),
                'successful_actions': len([a for a in actions if a.success]),
                'total_memory_freed_mb': sum(a.memory_freed_mb for a in actions if a.success),
                'actions': [
                    {
                        'name': action.name,
                        'description': action.description,
                        'success': action.success,
                        'memory_freed_mb': action.memory_freed_mb,
                        'execution_time_ms': action.execution_time_ms,
                        'error': action.error
                    }
                    for action in actions
                ],
                'success': True
            }
            
            self.logger.info(f"Memory pressure simulation completed: {len(actions)} actions executed")
            return result
            
        except Exception as e:
            safe_error = sanitize_for_logging(str(e), SanitizationLevel.STRICT, "simulation_error")
            self.logger.error(f"Failed to simulate memory pressure: {safe_error}")
            
            return {
                'simulation_type': f'{level}_memory_pressure',
                'timestamp': datetime.now().isoformat(),
                'error': safe_error,
                'success': False
            }
    
    def get_monitoring_configuration(self) -> Dict[str, Any]:
        """Get current monitoring configuration."""
        return {
            'enhanced_metrics_enabled': self.enhanced_metrics._monitoring_active,
            'baseline_collection_samples': len(self.enhanced_metrics._baseline_samples),
            'memory_history_samples': len(self.enhanced_metrics._memory_history),
            'response_handlers_registered': len(self.alert_manager.handlers) + len(self.alert_manager.async_handlers),
            'active_alert_rules': len(self.alert_manager.rules),
            'emergency_mode': self.pressure_handler.emergency_mode,
            'last_emergency_time': (
                self.pressure_handler.last_emergency_time.isoformat() 
                if self.pressure_handler.last_emergency_time else None
            ),
            'response_history_count': len(self.pressure_handler.action_history),
            'configuration_timestamp': datetime.now().isoformat()
        }
    
    async def shutdown(self):
        """Gracefully shutdown memory monitoring."""
        try:
            self.logger.info("Shutting down memory monitoring integration")
            record_memory_event("monitoring_shutdown")
            
            # Stop enhanced metrics monitoring
            self.enhanced_metrics.stop_monitoring()
            
            # Final memory report
            final_report = self.enhanced_metrics.get_memory_health_report()
            self.logger.info(f"Final memory report: {final_report}")
            
        except Exception as e:
            safe_error = sanitize_for_logging(str(e), SanitizationLevel.STRICT, "shutdown_error")
            self.logger.error(f"Error during memory monitoring shutdown: {safe_error}")


# Global integration instance
_memory_integration: Optional[MemoryMonitoringIntegration] = None


def get_memory_integration() -> MemoryMonitoringIntegration:
    """Get the global memory monitoring integration instance."""
    global _memory_integration
    if _memory_integration is None:
        _memory_integration = MemoryMonitoringIntegration()
    return _memory_integration


async def initialize_memory_monitoring() -> MemoryMonitoringIntegration:
    """Initialize comprehensive memory monitoring."""
    integration = get_memory_integration()
    
    # Give the monitoring system time to collect initial baseline
    await asyncio.sleep(1)
    
    return integration


# Convenience functions for external use
async def get_memory_health() -> Dict[str, Any]:
    """Get current memory health status."""
    integration = get_memory_integration()
    return await integration.get_memory_health_status()


async def force_memory_check() -> Dict[str, Any]:
    """Force a comprehensive memory check."""
    integration = get_memory_integration()
    return await integration.force_memory_check()


async def test_memory_response(level: str = "medium") -> Dict[str, Any]:
    """Test memory pressure response system."""
    integration = get_memory_integration()
    return await integration.simulate_memory_pressure(level)


def get_monitoring_config() -> Dict[str, Any]:
    """Get current monitoring configuration."""
    integration = get_memory_integration()
    return integration.get_monitoring_configuration()


async def shutdown_memory_monitoring():
    """Shutdown memory monitoring gracefully."""
    global _memory_integration
    if _memory_integration:
        await _memory_integration.shutdown()
        _memory_integration = None
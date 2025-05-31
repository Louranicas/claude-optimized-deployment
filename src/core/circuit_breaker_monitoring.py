"""
Circuit breaker monitoring and alerting system.

Provides real-time monitoring of circuit breaker states, metrics collection,
and integration with alerting systems.
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import os

from src.core.circuit_breaker import (
    get_circuit_breaker_manager,
    CircuitState,
    CircuitBreakerManager
)

logger = logging.getLogger(__name__)


@dataclass
class CircuitBreakerAlert:
    """Alert for circuit breaker state changes."""
    breaker_name: str
    old_state: CircuitState
    new_state: CircuitState
    timestamp: datetime
    failure_rate: float
    total_calls: int
    failed_calls: int
    reason: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "breaker_name": self.breaker_name,
            "old_state": self.old_state.value,
            "new_state": self.new_state.value,
            "timestamp": self.timestamp.isoformat(),
            "failure_rate": self.failure_rate,
            "total_calls": self.total_calls,
            "failed_calls": self.failed_calls,
            "reason": self.reason
        }


@dataclass
class MonitoringConfig:
    """Configuration for circuit breaker monitoring."""
    check_interval: float = 10.0  # Seconds between checks
    alert_on_open: bool = True
    alert_on_half_open: bool = True
    alert_on_close: bool = False
    failure_rate_threshold: float = 0.5  # Alert if failure rate exceeds this
    metrics_export_interval: float = 60.0  # Export metrics every minute
    metrics_export_path: Optional[str] = None
    alert_callbacks: List[Callable[[CircuitBreakerAlert], None]] = field(default_factory=list)


class CircuitBreakerMonitor:
    """
    Monitor circuit breakers and generate alerts.
    
    Example:
        ```python
        monitor = CircuitBreakerMonitor()
        
        # Add alert callback
        monitor.add_alert_callback(lambda alert: print(f"Alert: {alert.breaker_name} is {alert.new_state}"))
        
        # Start monitoring
        await monitor.start()
        
        # Get current status
        status = monitor.get_status()
        ```
    """
    
    def __init__(self, config: Optional[MonitoringConfig] = None):
        """Initialize monitor with configuration."""
        self.config = config or MonitoringConfig()
        self.manager: CircuitBreakerManager = get_circuit_breaker_manager()
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._metrics_task: Optional[asyncio.Task] = None
        self._previous_states: Dict[str, CircuitState] = {}
        self._alerts: List[CircuitBreakerAlert] = []
        
        # Set default metrics export path if not specified
        if self.config.metrics_export_path is None:
            self.config.metrics_export_path = os.path.join(
                os.getcwd(), "circuit_breaker_metrics.json"
            )
    
    def add_alert_callback(self, callback: Callable[[CircuitBreakerAlert], None]):
        """Add a callback for circuit breaker alerts."""
        self.config.alert_callbacks.append(callback)
    
    async def start(self):
        """Start monitoring circuit breakers."""
        if self._running:
            logger.warning("Circuit breaker monitor already running")
            return
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        self._metrics_task = asyncio.create_task(self._metrics_export_loop())
        logger.info("Circuit breaker monitor started")
    
    async def stop(self):
        """Stop monitoring circuit breakers."""
        self._running = False
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        if self._metrics_task:
            self._metrics_task.cancel()
            try:
                await self._metrics_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Circuit breaker monitor stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running:
            try:
                await self._check_circuit_breakers()
                await asyncio.sleep(self.config.check_interval)
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                await asyncio.sleep(self.config.check_interval)
    
    async def _metrics_export_loop(self):
        """Export metrics periodically."""
        while self._running:
            try:
                await self._export_metrics()
                await asyncio.sleep(self.config.metrics_export_interval)
            except Exception as e:
                logger.error(f"Error exporting metrics: {e}")
                await asyncio.sleep(self.config.metrics_export_interval)
    
    async def _check_circuit_breakers(self):
        """Check all circuit breakers for state changes and issues."""
        all_metrics = self.manager.get_all_metrics()
        
        for breaker_name, metrics in all_metrics.items():
            current_state = CircuitState(metrics["state"])
            breaker_metrics = metrics["metrics"]
            
            # Check for state changes
            previous_state = self._previous_states.get(breaker_name, CircuitState.CLOSED)
            if current_state != previous_state:
                await self._handle_state_change(
                    breaker_name, previous_state, current_state, breaker_metrics
                )
                self._previous_states[breaker_name] = current_state
            
            # Check failure rate threshold
            failure_rate = breaker_metrics["failure_rate"]
            if (failure_rate > self.config.failure_rate_threshold and 
                breaker_metrics["total_calls"] >= 10):
                logger.warning(
                    f"Circuit breaker '{breaker_name}' has high failure rate: "
                    f"{failure_rate:.2%} ({breaker_metrics['failed_calls']}/{breaker_metrics['total_calls']})"
                )
    
    async def _handle_state_change(
        self,
        breaker_name: str,
        old_state: CircuitState,
        new_state: CircuitState,
        metrics: Dict[str, Any]
    ):
        """Handle circuit breaker state change."""
        # Determine if we should alert
        should_alert = False
        if new_state == CircuitState.OPEN and self.config.alert_on_open:
            should_alert = True
        elif new_state == CircuitState.HALF_OPEN and self.config.alert_on_half_open:
            should_alert = True
        elif new_state == CircuitState.CLOSED and self.config.alert_on_close:
            should_alert = True
        
        if should_alert:
            # Find reason from state changes
            reason = "Unknown"
            if metrics.get("state_changes"):
                latest_change = metrics["state_changes"][-1]
                if (latest_change["to_state"] == new_state.value and 
                    latest_change["from_state"] == old_state.value):
                    reason = latest_change.get("reason", "Unknown")
            
            # Create alert
            alert = CircuitBreakerAlert(
                breaker_name=breaker_name,
                old_state=old_state,
                new_state=new_state,
                timestamp=datetime.now(),
                failure_rate=metrics["failure_rate"],
                total_calls=metrics["total_calls"],
                failed_calls=metrics["failed_calls"],
                reason=reason
            )
            
            # Store alert
            self._alerts.append(alert)
            
            # Call alert callbacks
            for callback in self.config.alert_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(alert)
                    else:
                        callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")
            
            # Log state change
            logger.warning(
                f"Circuit breaker '{breaker_name}' changed from {old_state.value} to {new_state.value}. "
                f"Failure rate: {metrics['failure_rate']:.2%}, Reason: {reason}"
            )
    
    async def _export_metrics(self):
        """Export metrics to file."""
        try:
            metrics = {
                "timestamp": datetime.now().isoformat(),
                "summary": self.manager.get_summary(),
                "breakers": self.manager.get_all_metrics(),
                "recent_alerts": [alert.to_dict() for alert in self._alerts[-50:]]
            }
            
            with open(self.config.metrics_export_path, 'w') as f:
                json.dump(metrics, f, indent=2)
            
            logger.debug(f"Exported circuit breaker metrics to {self.config.metrics_export_path}")
        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status."""
        summary = self.manager.get_summary()
        
        return {
            "monitoring": self._running,
            "total_breakers": summary["total_breakers"],
            "open_circuits": summary["open_circuits"],
            "half_open_circuits": summary["half_open_circuits"],
            "closed_circuits": summary["closed_circuits"],
            "total_calls": summary["total_calls"],
            "total_failures": summary["total_failures"],
            "overall_failure_rate": summary["overall_failure_rate"],
            "recent_alerts": len(self._alerts),
            "config": {
                "check_interval": self.config.check_interval,
                "alert_on_open": self.config.alert_on_open,
                "alert_on_half_open": self.config.alert_on_half_open,
                "alert_on_close": self.config.alert_on_close,
                "failure_rate_threshold": self.config.failure_rate_threshold
            }
        }
    
    def get_recent_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent alerts."""
        return [alert.to_dict() for alert in self._alerts[-limit:]]
    
    def clear_alerts(self):
        """Clear stored alerts."""
        self._alerts.clear()
        logger.info("Cleared circuit breaker alerts")


# Global monitor instance
_monitor: Optional[CircuitBreakerMonitor] = None


async def get_circuit_breaker_monitor() -> CircuitBreakerMonitor:
    """Get the global circuit breaker monitor."""
    global _monitor
    if _monitor is None:
        _monitor = CircuitBreakerMonitor()
        await _monitor.start()
    return _monitor


# Convenience functions for monitoring
async def start_monitoring(config: Optional[MonitoringConfig] = None):
    """Start circuit breaker monitoring."""
    global _monitor
    if _monitor is None:
        _monitor = CircuitBreakerMonitor(config)
    await _monitor.start()


async def stop_monitoring():
    """Stop circuit breaker monitoring."""
    if _monitor:
        await _monitor.stop()


def get_monitoring_status() -> Dict[str, Any]:
    """Get current monitoring status."""
    if _monitor:
        return _monitor.get_status()
    return {"monitoring": False, "message": "Monitor not initialized"}


# Example alert callbacks
def log_alert(alert: CircuitBreakerAlert):
    """Log circuit breaker alert."""
    logger.warning(f"CIRCUIT BREAKER ALERT: {alert.to_dict()}")


async def slack_alert(alert: CircuitBreakerAlert):
    """Send alert to Slack (example)."""
    # This would integrate with your Slack MCP server
    from src.mcp.manager import get_mcp_manager
    
    try:
        manager = get_mcp_manager()
        message = (
            f"🚨 Circuit Breaker Alert 🚨\n"
            f"*{alert.breaker_name}* changed from *{alert.old_state.value}* to *{alert.new_state.value}*\n"
            f"Failure Rate: {alert.failure_rate:.1%} ({alert.failed_calls}/{alert.total_calls} calls)\n"
            f"Reason: {alert.reason}"
        )
        
        await manager.call_tool("slack.send_notification", {
            "channel": "#alerts",
            "message": message,
            "level": "error" if alert.new_state == CircuitState.OPEN else "warning"
        })
    except Exception as e:
        logger.error(f"Failed to send Slack alert: {e}")


# Export public API
__all__ = [
    'CircuitBreakerMonitor',
    'CircuitBreakerAlert',
    'MonitoringConfig',
    'get_circuit_breaker_monitor',
    'start_monitoring',
    'stop_monitoring',
    'get_monitoring_status',
    'log_alert',
    'slack_alert',
]
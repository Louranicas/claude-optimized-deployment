"""
Control API for Stress Testing Framework

Provides real-time control interface for monitoring and adjusting stress tests,
including emergency controls, load adjustments, and status monitoring.
"""

import asyncio
import time
import logging
import json
from typing import Dict, List, Optional, Any, Callable
from dataclasses import asdict
from datetime import datetime
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor

try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
    from fastapi.responses import JSONResponse, StreamingResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    # Fallback base classes
    class BaseModel:
        pass

# Import our framework components
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cycle_manager import StressCycleManager, StressPhase, CycleState
from core.safety_manager import SafetyManager, SafetyLevel
from core.metrics_collector import MetricsCollector
from core.adaptive_ramping import AdaptiveRampingEngine


class ControlCommand(Enum):
    """Available control commands"""
    START_CYCLE = "start_cycle"
    STOP_CYCLE = "stop_cycle"
    PAUSE_CYCLE = "pause_cycle"
    RESUME_CYCLE = "resume_cycle"
    EMERGENCY_STOP = "emergency_stop"
    ADJUST_LOAD = "adjust_load"
    UPDATE_THRESHOLDS = "update_thresholds"
    RESET_SAFETY = "reset_safety"


# Pydantic models for API
class CycleStartRequest(BaseModel):
    phases: Optional[List[str]] = None
    custom_config: Optional[Dict[str, Any]] = None


class LoadAdjustmentRequest(BaseModel):
    phase: str
    target_load: float = Field(..., ge=0.0, le=100.0)


class ThresholdUpdateRequest(BaseModel):
    thresholds: Dict[str, float]


class ControlResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None
    timestamp: float


class SystemStatus(BaseModel):
    cycle_state: str
    current_phase: Optional[str]
    current_load: float
    target_load: float
    safety_status: str
    emergency_triggered: bool
    uptime: float


class MetricPoint(BaseModel):
    timestamp: float
    value: float
    metric_name: str


class WebSocketManager:
    """Manages WebSocket connections for real-time updates"""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.logger = logging.getLogger(f"{__name__}.WebSocketManager")
    
    async def connect(self, websocket: WebSocket):
        """Connect a new WebSocket client"""
        await websocket.accept()
        self.active_connections.append(websocket)
        self.logger.info(f"WebSocket client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Disconnect a WebSocket client"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            self.logger.info(f"WebSocket client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast message to all connected clients"""
        if not self.active_connections:
            return
        
        # Convert message to JSON
        json_message = json.dumps(message, default=str)
        
        # Send to all clients, remove disconnected ones
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json_message)
            except Exception as e:
                self.logger.error(f"Failed to send message to client: {e}")
                disconnected.append(connection)
        
        # Remove disconnected clients
        for connection in disconnected:
            self.disconnect(connection)
    
    async def send_to_client(self, websocket: WebSocket, message: Dict[str, Any]):
        """Send message to specific client"""
        try:
            json_message = json.dumps(message, default=str)
            await websocket.send_text(json_message)
        except Exception as e:
            self.logger.error(f"Failed to send message to specific client: {e}")
            self.disconnect(websocket)


class StressTestingControlAPI:
    """
    Main control API for the stress testing framework
    """
    
    def __init__(self, config_path: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.cycle_manager = StressCycleManager(config_path)
        self.websocket_manager = WebSocketManager()
        
        # API state
        self.api_active = False
        self.start_time = time.time()
        
        # Real-time streaming
        self.streaming_clients: List[Callable] = []
        self.stream_task: Optional[asyncio.Task] = None
        
        # Command history
        self.command_history: List[Dict[str, Any]] = []
        
        # Initialize FastAPI if available
        if FASTAPI_AVAILABLE:
            self.app = self._create_fastapi_app()
        else:
            self.app = None
            self.logger.warning("FastAPI not available, WebSocket features disabled")
    
    def _create_fastapi_app(self) -> FastAPI:
        """Create FastAPI application"""
        app = FastAPI(
            title="Stress Testing Control API",
            description="Real-time control interface for stress testing framework",
            version="1.0.0"
        )
        
        # Add CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Register routes
        self._register_routes(app)
        
        return app
    
    def _register_routes(self, app: FastAPI):
        """Register API routes"""
        
        @app.get("/", response_model=Dict[str, str])
        async def root():
            """API root endpoint"""
            return {
                "name": "Stress Testing Control API",
                "version": "1.0.0",
                "status": "active" if self.api_active else "inactive",
                "uptime": time.time() - self.start_time
            }
        
        @app.get("/status", response_model=SystemStatus)
        async def get_status():
            """Get current system status"""
            return await self._get_system_status()
        
        @app.post("/cycle/start", response_model=ControlResponse)
        async def start_cycle(request: CycleStartRequest):
            """Start stress testing cycle"""
            return await self._handle_start_cycle(request)
        
        @app.post("/cycle/stop", response_model=ControlResponse)
        async def stop_cycle():
            """Stop current cycle"""
            return await self._handle_stop_cycle()
        
        @app.post("/cycle/pause", response_model=ControlResponse)
        async def pause_cycle():
            """Pause current cycle"""
            return await self._handle_pause_cycle()
        
        @app.post("/cycle/resume", response_model=ControlResponse)
        async def resume_cycle():
            """Resume paused cycle"""
            return await self._handle_resume_cycle()
        
        @app.post("/emergency/stop", response_model=ControlResponse)
        async def emergency_stop():
            """Emergency stop all operations"""
            return await self._handle_emergency_stop()
        
        @app.post("/load/adjust", response_model=ControlResponse)
        async def adjust_load(request: LoadAdjustmentRequest):
            """Adjust load for current phase"""
            return await self._handle_load_adjustment(request)
        
        @app.post("/safety/thresholds", response_model=ControlResponse)
        async def update_thresholds(request: ThresholdUpdateRequest):
            """Update safety thresholds"""
            return await self._handle_threshold_update(request)
        
        @app.post("/safety/reset", response_model=ControlResponse)
        async def reset_safety():
            """Reset safety system"""
            return await self._handle_safety_reset()
        
        @app.get("/metrics/current")
        async def get_current_metrics():
            """Get current metrics"""
            return await self._get_current_metrics()
        
        @app.get("/metrics/history")
        async def get_metrics_history(
            start_time: Optional[float] = None,
            end_time: Optional[float] = None,
            metric_name: Optional[str] = None
        ):
            """Get metrics history"""
            return await self._get_metrics_history(start_time, end_time, metric_name)
        
        @app.get("/metrics/stream")
        async def stream_metrics():
            """Stream real-time metrics"""
            return StreamingResponse(
                self._metrics_stream_generator(),
                media_type="text/plain"
            )
        
        @app.get("/cycle/history")
        async def get_cycle_history():
            """Get cycle execution history"""
            return self.cycle_manager.get_cycle_history()
        
        @app.get("/commands/history")
        async def get_command_history():
            """Get command execution history"""
            return self.command_history
        
        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates"""
            await self._handle_websocket(websocket)
    
    async def start_api(self, host: str = "0.0.0.0", port: int = 8000):
        """Start the control API server"""
        if not FASTAPI_AVAILABLE:
            self.logger.error("Cannot start API server: FastAPI not available")
            return False
        
        try:
            self.logger.info(f"Starting control API server on {host}:{port}")
            self.api_active = True
            
            # Start real-time streaming
            self.stream_task = asyncio.create_task(self._real_time_stream_loop())
            
            # Register callbacks with cycle manager
            self._register_callbacks()
            
            # Start the server (this would typically be done with uvicorn)
            import uvicorn
            config = uvicorn.Config(
                self.app,
                host=host,
                port=port,
                log_level="info",
                access_log=True
            )
            server = uvicorn.Server(config)
            await server.serve()
            
        except Exception as e:
            self.logger.error(f"Failed to start API server: {e}")
            self.api_active = False
            return False
    
    async def stop_api(self):
        """Stop the control API server"""
        self.logger.info("Stopping control API server")
        self.api_active = False
        
        if self.stream_task:
            self.stream_task.cancel()
            try:
                await self.stream_task
            except asyncio.CancelledError:
                pass
    
    def _register_callbacks(self):
        """Register callbacks with framework components"""
        # Phase change callbacks
        self.cycle_manager.register_phase_change_callback(self._on_phase_change)
        self.cycle_manager.register_metrics_callback(self._on_metrics_update)
        self.cycle_manager.register_safety_callback(self._on_safety_event)
    
    # API endpoint handlers
    async def _get_system_status(self) -> SystemStatus:
        """Get current system status"""
        status = self.cycle_manager.get_status()
        
        return SystemStatus(
            cycle_state=status.state.value,
            current_phase=status.current_phase.name if status.current_phase else None,
            current_load=status.current_load_percent,
            target_load=status.target_load_percent,
            safety_status="emergency" if status.safety_triggered else "normal",
            emergency_triggered=status.safety_triggered,
            uptime=time.time() - self.start_time
        )
    
    async def _handle_start_cycle(self, request: CycleStartRequest) -> ControlResponse:
        """Handle cycle start request"""
        try:
            # Parse phases if provided
            phases = None
            if request.phases:
                phases = [StressPhase[phase.upper()] for phase in request.phases]
            
            # Start the cycle
            success = await self.cycle_manager.start_cycle(phases)
            
            # Record command
            command_record = {
                "command": ControlCommand.START_CYCLE.value,
                "timestamp": time.time(),
                "parameters": {"phases": request.phases},
                "success": success
            }
            self.command_history.append(command_record)
            
            if success:
                return ControlResponse(
                    success=True,
                    message="Stress testing cycle started successfully",
                    timestamp=time.time()
                )
            else:
                return ControlResponse(
                    success=False,
                    message="Failed to start stress testing cycle",
                    timestamp=time.time()
                )
                
        except Exception as e:
            self.logger.error(f"Error starting cycle: {e}")
            return ControlResponse(
                success=False,
                message=f"Error starting cycle: {str(e)}",
                timestamp=time.time()
            )
    
    async def _handle_stop_cycle(self) -> ControlResponse:
        """Handle cycle stop request"""
        try:
            await self.cycle_manager.stop_cycle()
            
            command_record = {
                "command": ControlCommand.STOP_CYCLE.value,
                "timestamp": time.time(),
                "success": True
            }
            self.command_history.append(command_record)
            
            return ControlResponse(
                success=True,
                message="Stress testing cycle stopped",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error stopping cycle: {e}")
            return ControlResponse(
                success=False,
                message=f"Error stopping cycle: {str(e)}",
                timestamp=time.time()
            )
    
    async def _handle_pause_cycle(self) -> ControlResponse:
        """Handle cycle pause request"""
        try:
            await self.cycle_manager.pause_cycle()
            
            command_record = {
                "command": ControlCommand.PAUSE_CYCLE.value,
                "timestamp": time.time(),
                "success": True
            }
            self.command_history.append(command_record)
            
            return ControlResponse(
                success=True,
                message="Stress testing cycle paused",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error pausing cycle: {e}")
            return ControlResponse(
                success=False,
                message=f"Error pausing cycle: {str(e)}",
                timestamp=time.time()
            )
    
    async def _handle_resume_cycle(self) -> ControlResponse:
        """Handle cycle resume request"""
        try:
            await self.cycle_manager.resume_cycle()
            
            command_record = {
                "command": ControlCommand.RESUME_CYCLE.value,
                "timestamp": time.time(),
                "success": True
            }
            self.command_history.append(command_record)
            
            return ControlResponse(
                success=True,
                message="Stress testing cycle resumed",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error resuming cycle: {e}")
            return ControlResponse(
                success=False,
                message=f"Error resuming cycle: {str(e)}",
                timestamp=time.time()
            )
    
    async def _handle_emergency_stop(self) -> ControlResponse:
        """Handle emergency stop request"""
        try:
            await self.cycle_manager.stop_cycle(emergency=True)
            
            command_record = {
                "command": ControlCommand.EMERGENCY_STOP.value,
                "timestamp": time.time(),
                "success": True
            }
            self.command_history.append(command_record)
            
            return ControlResponse(
                success=True,
                message="Emergency stop executed",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error during emergency stop: {e}")
            return ControlResponse(
                success=False,
                message=f"Error during emergency stop: {str(e)}",
                timestamp=time.time()
            )
    
    async def _handle_load_adjustment(self, request: LoadAdjustmentRequest) -> ControlResponse:
        """Handle load adjustment request"""
        try:
            phase = StressPhase[request.phase.upper()]
            await self.cycle_manager.adjust_target_load(phase, request.target_load)
            
            command_record = {
                "command": ControlCommand.ADJUST_LOAD.value,
                "timestamp": time.time(),
                "parameters": {"phase": request.phase, "target_load": request.target_load},
                "success": True
            }
            self.command_history.append(command_record)
            
            return ControlResponse(
                success=True,
                message=f"Load adjusted to {request.target_load}% for phase {request.phase}",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error adjusting load: {e}")
            return ControlResponse(
                success=False,
                message=f"Error adjusting load: {str(e)}",
                timestamp=time.time()
            )
    
    async def _handle_threshold_update(self, request: ThresholdUpdateRequest) -> ControlResponse:
        """Handle safety threshold update"""
        try:
            # This would interface with the safety manager
            # await self.cycle_manager.safety_manager.set_thresholds(request.thresholds)
            
            command_record = {
                "command": ControlCommand.UPDATE_THRESHOLDS.value,
                "timestamp": time.time(),
                "parameters": {"thresholds": request.thresholds},
                "success": True
            }
            self.command_history.append(command_record)
            
            return ControlResponse(
                success=True,
                message="Safety thresholds updated",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error updating thresholds: {e}")
            return ControlResponse(
                success=False,
                message=f"Error updating thresholds: {str(e)}",
                timestamp=time.time()
            )
    
    async def _handle_safety_reset(self) -> ControlResponse:
        """Handle safety system reset"""
        try:
            # This would interface with the safety manager
            # await self.cycle_manager.safety_manager.reset_emergency_state()
            
            command_record = {
                "command": ControlCommand.RESET_SAFETY.value,
                "timestamp": time.time(),
                "success": True
            }
            self.command_history.append(command_record)
            
            return ControlResponse(
                success=True,
                message="Safety system reset",
                timestamp=time.time()
            )
            
        except Exception as e:
            self.logger.error(f"Error resetting safety: {e}")
            return ControlResponse(
                success=False,
                message=f"Error resetting safety: {str(e)}",
                timestamp=time.time()
            )
    
    async def _get_current_metrics(self) -> Dict[str, Any]:
        """Get current metrics"""
        # This would interface with the metrics collector
        return {
            "timestamp": time.time(),
            "cpu_usage": 45.2,
            "memory_usage": 67.8,
            "load_average": 2.1,
            "temperature": 65.0
        }
    
    async def _get_metrics_history(self, start_time: Optional[float], 
                                 end_time: Optional[float], 
                                 metric_name: Optional[str]) -> Dict[str, Any]:
        """Get metrics history"""
        # This would interface with the metrics collector
        return {
            "start_time": start_time or (time.time() - 3600),
            "end_time": end_time or time.time(),
            "metric_name": metric_name or "all",
            "data_points": []
        }
    
    async def _metrics_stream_generator(self):
        """Generate real-time metrics stream"""
        while self.api_active:
            try:
                metrics = await self._get_current_metrics()
                yield f"data: {json.dumps(metrics)}\n\n"
                await asyncio.sleep(1.0)
            except Exception as e:
                self.logger.error(f"Error in metrics stream: {e}")
                break
    
    # WebSocket handling
    async def _handle_websocket(self, websocket: WebSocket):
        """Handle WebSocket connection"""
        await self.websocket_manager.connect(websocket)
        
        try:
            # Send initial status
            status = await self._get_system_status()
            await self.websocket_manager.send_to_client(websocket, {
                "type": "status",
                "data": status.dict()
            })
            
            # Listen for client messages
            while True:
                try:
                    data = await websocket.receive_text()
                    message = json.loads(data)
                    await self._handle_websocket_message(websocket, message)
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    self.logger.error(f"WebSocket error: {e}")
                    break
                    
        finally:
            self.websocket_manager.disconnect(websocket)
    
    async def _handle_websocket_message(self, websocket: WebSocket, message: Dict[str, Any]):
        """Handle incoming WebSocket message"""
        try:
            message_type = message.get("type")
            
            if message_type == "ping":
                await self.websocket_manager.send_to_client(websocket, {
                    "type": "pong",
                    "timestamp": time.time()
                })
            
            elif message_type == "subscribe":
                # Handle subscription requests
                subscription = message.get("subscription", "all")
                await self.websocket_manager.send_to_client(websocket, {
                    "type": "subscription_confirmed",
                    "subscription": subscription
                })
            
            elif message_type == "command":
                # Handle control commands via WebSocket
                await self._handle_websocket_command(websocket, message.get("command", {}))
            
        except Exception as e:
            self.logger.error(f"Error handling WebSocket message: {e}")
    
    async def _handle_websocket_command(self, websocket: WebSocket, command: Dict[str, Any]):
        """Handle control command received via WebSocket"""
        try:
            command_type = command.get("type")
            
            if command_type == "emergency_stop":
                response = await self._handle_emergency_stop()
                await self.websocket_manager.send_to_client(websocket, {
                    "type": "command_response",
                    "response": response.dict()
                })
            
            # Add other commands as needed
            
        except Exception as e:
            self.logger.error(f"Error handling WebSocket command: {e}")
    
    # Real-time streaming
    async def _real_time_stream_loop(self):
        """Real-time streaming loop for WebSocket clients"""
        while self.api_active:
            try:
                # Collect current data
                status = await self._get_system_status()
                metrics = await self._get_current_metrics()
                
                # Broadcast to all WebSocket clients
                await self.websocket_manager.broadcast({
                    "type": "real_time_update",
                    "timestamp": time.time(),
                    "status": status.dict(),
                    "metrics": metrics
                })
                
                await asyncio.sleep(1.0)  # Update every second
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in real-time stream: {e}")
                await asyncio.sleep(5.0)  # Retry after delay
    
    # Event callbacks
    async def _on_phase_change(self, phase, event, status):
        """Handle phase change events"""
        await self.websocket_manager.broadcast({
            "type": "phase_change",
            "timestamp": time.time(),
            "phase": phase.name,
            "event": event,
            "status": asdict(status)
        })
    
    async def _on_metrics_update(self, metrics, status):
        """Handle metrics update events"""
        await self.websocket_manager.broadcast({
            "type": "metrics_update",
            "timestamp": time.time(),
            "metrics": metrics,
            "status": asdict(status)
        })
    
    async def _on_safety_event(self, event, status):
        """Handle safety events"""
        await self.websocket_manager.broadcast({
            "type": "safety_event",
            "timestamp": time.time(),
            "event": event,
            "status": asdict(status),
            "priority": "high"
        })


# Standalone server function
async def run_control_api(config_path: Optional[str] = None, 
                         host: str = "0.0.0.0", 
                         port: int = 8000):
    """Run the control API server"""
    api = StressTestingControlAPI(config_path)
    
    try:
        await api.start_api(host, port)
    except KeyboardInterrupt:
        print("\nShutting down control API...")
    finally:
        await api.stop_api()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Stress Testing Control API")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    
    args = parser.parse_args()
    
    # Run the API server
    asyncio.run(run_control_api(args.config, args.host, args.port))
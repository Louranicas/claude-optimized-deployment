"""
Service Discovery - Automatic node registration and discovery for MCP distributed testing.
Implements service mesh capabilities for test node coordination.
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Callable
import socket
import struct
import hashlib
import zlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ServiceType(Enum):
    """Service type enumeration"""
    ORCHESTRATOR = "orchestrator"
    LOAD_GENERATOR = "load_generator"
    MONITOR = "monitor"
    RESOURCE_MANAGER = "resource_manager"
    COMMUNICATION_HUB = "communication_hub"
    MCP_SERVER = "mcp_server"


class ServiceStatus(Enum):
    """Service status enumeration"""
    DISCOVERING = "discovering"
    AVAILABLE = "available"
    BUSY = "busy"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    FAILED = "failed"


@dataclass
class ServiceInstance:
    """Represents a discovered service instance"""
    service_id: str
    service_type: ServiceType
    name: str
    host: str
    port: int
    protocol: str  # http, websocket, tcp, udp
    health_endpoint: Optional[str] = None
    capabilities: List[str] = None
    metadata: Dict[str, Any] = None
    status: ServiceStatus = ServiceStatus.DISCOVERING
    last_seen: datetime = None
    registration_time: datetime = None
    health_check_interval: int = 30
    tags: Set[str] = None


@dataclass
class DiscoveryConfig:
    """Service discovery configuration"""
    multicast_group: str = "239.255.255.250"
    multicast_port: int = 1900
    broadcast_interval: int = 30
    service_timeout: int = 90
    health_check_enabled: bool = True
    health_check_interval: int = 30
    auto_cleanup: bool = True
    cleanup_interval: int = 60


class ServiceRegistry:
    """Service registry for managing discovered services"""
    
    def __init__(self):
        self.services: Dict[str, ServiceInstance] = {}
        self.service_types: Dict[ServiceType, List[str]] = {}
        self.listeners: List[Callable] = []
        self.lock = asyncio.Lock()

    async def register_service(self, service: ServiceInstance):
        """Register a new service"""
        async with self.lock:
            service.registration_time = datetime.now()
            service.last_seen = datetime.now()
            
            self.services[service.service_id] = service
            
            # Index by service type
            if service.service_type not in self.service_types:
                self.service_types[service.service_type] = []
            
            if service.service_id not in self.service_types[service.service_type]:
                self.service_types[service.service_type].append(service.service_id)
            
            logger.info(f"Registered service {service.service_id} ({service.service_type})")
            
            # Notify listeners
            await self._notify_listeners("service_registered", service)

    async def update_service(self, service_id: str, updates: Dict[str, Any]):
        """Update service information"""
        async with self.lock:
            if service_id in self.services:
                service = self.services[service_id]
                
                for key, value in updates.items():
                    if hasattr(service, key):
                        setattr(service, key, value)
                
                service.last_seen = datetime.now()
                
                await self._notify_listeners("service_updated", service)

    async def deregister_service(self, service_id: str):
        """Deregister a service"""
        async with self.lock:
            if service_id in self.services:
                service = self.services[service_id]
                
                # Remove from type index
                if service.service_type in self.service_types:
                    if service_id in self.service_types[service.service_type]:
                        self.service_types[service.service_type].remove(service_id)
                
                del self.services[service_id]
                
                logger.info(f"Deregistered service {service_id}")
                
                await self._notify_listeners("service_deregistered", service)

    def get_service(self, service_id: str) -> Optional[ServiceInstance]:
        """Get service by ID"""
        return self.services.get(service_id)

    def get_services_by_type(self, service_type: ServiceType) -> List[ServiceInstance]:
        """Get all services of a specific type"""
        service_ids = self.service_types.get(service_type, [])
        return [self.services[sid] for sid in service_ids if sid in self.services]

    def get_available_services(self, service_type: ServiceType = None) -> List[ServiceInstance]:
        """Get all available services, optionally filtered by type"""
        services = self.services.values()
        
        if service_type:
            services = [s for s in services if s.service_type == service_type]
        
        return [s for s in services if s.status == ServiceStatus.AVAILABLE]

    def find_services_by_capability(self, capability: str) -> List[ServiceInstance]:
        """Find services that support a specific capability"""
        matching_services = []
        
        for service in self.services.values():
            if service.capabilities and capability in service.capabilities:
                matching_services.append(service)
        
        return matching_services

    def find_services_by_tag(self, tag: str) -> List[ServiceInstance]:
        """Find services with a specific tag"""
        matching_services = []
        
        for service in self.services.values():
            if service.tags and tag in service.tags:
                matching_services.append(service)
        
        return matching_services

    async def add_listener(self, listener: Callable):
        """Add event listener for service changes"""
        self.listeners.append(listener)

    async def remove_listener(self, listener: Callable):
        """Remove event listener"""
        if listener in self.listeners:
            self.listeners.remove(listener)

    async def _notify_listeners(self, event_type: str, service: ServiceInstance):
        """Notify all listeners of service events"""
        for listener in self.listeners:
            try:
                if asyncio.iscoroutinefunction(listener):
                    await listener(event_type, service)
                else:
                    listener(event_type, service)
            except Exception as e:
                logger.error(f"Error in service listener: {e}")


class ServiceDiscovery:
    """MCP service discovery implementation using multicast and health checks"""
    
    def __init__(self, config: DiscoveryConfig = None):
        self.config = config or DiscoveryConfig()
        self.registry = ServiceRegistry()
        self.local_services: Dict[str, ServiceInstance] = {}
        self.running = False
        
        # Network components
        self.multicast_socket: Optional[socket.socket] = None
        self.broadcast_socket: Optional[socket.socket] = None
        
        # Background tasks
        self.discovery_task: Optional[asyncio.Task] = None
        self.broadcast_task: Optional[asyncio.Task] = None
        self.health_check_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start service discovery"""
        self.running = True
        logger.info("Starting service discovery")
        
        # Setup networking
        await self.setup_networking()
        
        # Start background tasks
        self.discovery_task = asyncio.create_task(self.discovery_loop())
        self.broadcast_task = asyncio.create_task(self.broadcast_loop())
        
        if self.config.health_check_enabled:
            self.health_check_task = asyncio.create_task(self.health_check_loop())
        
        if self.config.auto_cleanup:
            self.cleanup_task = asyncio.create_task(self.cleanup_loop())
        
        logger.info("Service discovery started successfully")

    async def stop(self):
        """Stop service discovery"""
        self.running = False
        logger.info("Stopping service discovery")
        
        # Cancel background tasks
        for task in [self.discovery_task, self.broadcast_task, 
                    self.health_check_task, self.cleanup_task]:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Cleanup networking
        await self.cleanup_networking()
        
        logger.info("Service discovery stopped")

    async def setup_networking(self):
        """Setup multicast networking for service discovery"""
        try:
            # Create multicast listener socket
            self.multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.multicast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.multicast_socket.bind(('', self.config.multicast_port))
            
            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton(self.config.multicast_group), socket.INADDR_ANY)
            self.multicast_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            self.multicast_socket.setblocking(False)
            
            # Create broadcast socket
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.broadcast_socket.setblocking(False)
            
            logger.info(f"Multicast discovery setup on {self.config.multicast_group}:{self.config.multicast_port}")
            
        except Exception as e:
            logger.error(f"Failed to setup networking: {e}")
            raise

    async def cleanup_networking(self):
        """Cleanup networking resources"""
        if self.multicast_socket:
            self.multicast_socket.close()
            self.multicast_socket = None
        
        if self.broadcast_socket:
            self.broadcast_socket.close()
            self.broadcast_socket = None

    async def register_local_service(self, service: ServiceInstance):
        """Register a local service for discovery broadcasting"""
        service.service_id = service.service_id or str(uuid.uuid4())
        self.local_services[service.service_id] = service
        
        # Also add to registry
        await self.registry.register_service(service)
        
        logger.info(f"Registered local service {service.service_id} for broadcasting")

    async def deregister_local_service(self, service_id: str):
        """Deregister a local service"""
        if service_id in self.local_services:
            del self.local_services[service_id]
            await self.registry.deregister_service(service_id)
            
            # Send deregistration broadcast
            await self.broadcast_deregistration(service_id)
            
            logger.info(f"Deregistered local service {service_id}")

    async def discovery_loop(self):
        """Main discovery loop for listening to service announcements"""
        while self.running:
            try:
                if self.multicast_socket:
                    # Use asyncio to make socket non-blocking
                    loop = asyncio.get_event_loop()
                    
                    try:
                        data, addr = await loop.sock_recvfrom(self.multicast_socket, 4096)
                        await self.handle_discovery_message(data, addr)
                    except socket.error:
                        # No data available, continue
                        await asyncio.sleep(0.1)
                        continue
                
            except Exception as e:
                logger.error(f"Error in discovery loop: {e}")
                await asyncio.sleep(1)

    async def handle_discovery_message(self, data: bytes, addr: tuple):
        """Handle incoming discovery message"""
        try:
            # Decompress and decode message
            try:
                decompressed_data = zlib.decompress(data)
            except zlib.error:
                # Data might not be compressed
                decompressed_data = data
            
            message = json.loads(decompressed_data.decode('utf-8'))
            
            message_type = message.get("type")
            
            if message_type == "service_announcement":
                await self.handle_service_announcement(message, addr)
            elif message_type == "service_query":
                await self.handle_service_query(message, addr)
            elif message_type == "service_deregistration":
                await self.handle_service_deregistration(message, addr)
            else:
                logger.debug(f"Unknown discovery message type: {message_type}")
                
        except Exception as e:
            logger.debug(f"Error parsing discovery message: {e}")

    async def handle_service_announcement(self, message: Dict[str, Any], addr: tuple):
        """Handle service announcement message"""
        try:
            service_info = message["service"]
            
            # Create service instance
            service = ServiceInstance(
                service_id=service_info["service_id"],
                service_type=ServiceType(service_info["service_type"]),
                name=service_info["name"],
                host=service_info.get("host", addr[0]),
                port=service_info["port"],
                protocol=service_info.get("protocol", "http"),
                health_endpoint=service_info.get("health_endpoint"),
                capabilities=service_info.get("capabilities", []),
                metadata=service_info.get("metadata", {}),
                status=ServiceStatus.AVAILABLE,
                health_check_interval=service_info.get("health_check_interval", 30),
                tags=set(service_info.get("tags", []))
            )
            
            # Check if this is our own service
            if service.service_id in self.local_services:
                return
            
            # Register or update service
            existing_service = self.registry.get_service(service.service_id)
            if existing_service:
                await self.registry.update_service(service.service_id, {
                    "last_seen": datetime.now(),
                    "status": ServiceStatus.AVAILABLE
                })
            else:
                await self.registry.register_service(service)
            
            logger.debug(f"Discovered service {service.service_id} at {service.host}:{service.port}")
            
        except Exception as e:
            logger.error(f"Error handling service announcement: {e}")

    async def handle_service_query(self, message: Dict[str, Any], addr: tuple):
        """Handle service query message"""
        try:
            query_id = message.get("query_id")
            requested_type = message.get("service_type")
            requested_capabilities = message.get("capabilities", [])
            requested_tags = message.get("tags", [])
            
            # Find matching local services
            matching_services = []
            
            for service in self.local_services.values():
                # Check service type
                if requested_type and service.service_type.value != requested_type:
                    continue
                
                # Check capabilities
                if requested_capabilities:
                    if not service.capabilities or not all(cap in service.capabilities for cap in requested_capabilities):
                        continue
                
                # Check tags
                if requested_tags:
                    if not service.tags or not all(tag in service.tags for tag in requested_tags):
                        continue
                
                matching_services.append(service)
            
            # Send response
            if matching_services:
                await self.send_query_response(query_id, matching_services, addr)
            
        except Exception as e:
            logger.error(f"Error handling service query: {e}")

    async def handle_service_deregistration(self, message: Dict[str, Any], addr: tuple):
        """Handle service deregistration message"""
        try:
            service_id = message["service_id"]
            await self.registry.deregister_service(service_id)
            
            logger.info(f"Service {service_id} deregistered")
            
        except Exception as e:
            logger.error(f"Error handling service deregistration: {e}")

    async def broadcast_loop(self):
        """Broadcast local services periodically"""
        while self.running:
            try:
                for service in self.local_services.values():
                    await self.broadcast_service_announcement(service)
                
                await asyncio.sleep(self.config.broadcast_interval)
                
            except Exception as e:
                logger.error(f"Error in broadcast loop: {e}")
                await asyncio.sleep(self.config.broadcast_interval)

    async def broadcast_service_announcement(self, service: ServiceInstance):
        """Broadcast service announcement"""
        try:
            message = {
                "type": "service_announcement",
                "timestamp": datetime.now().isoformat(),
                "service": {
                    "service_id": service.service_id,
                    "service_type": service.service_type.value,
                    "name": service.name,
                    "host": service.host,
                    "port": service.port,
                    "protocol": service.protocol,
                    "health_endpoint": service.health_endpoint,
                    "capabilities": service.capabilities or [],
                    "metadata": service.metadata or {},
                    "health_check_interval": service.health_check_interval,
                    "tags": list(service.tags) if service.tags else []
                }
            }
            
            await self.send_multicast_message(message)
            
        except Exception as e:
            logger.error(f"Error broadcasting service announcement: {e}")

    async def broadcast_deregistration(self, service_id: str):
        """Broadcast service deregistration"""
        try:
            message = {
                "type": "service_deregistration",
                "timestamp": datetime.now().isoformat(),
                "service_id": service_id
            }
            
            await self.send_multicast_message(message)
            
        except Exception as e:
            logger.error(f"Error broadcasting deregistration: {e}")

    async def query_services(self, service_type: str = None, capabilities: List[str] = None, 
                           tags: List[str] = None, timeout: float = 5.0) -> List[ServiceInstance]:
        """Query for services with specific criteria"""
        query_id = str(uuid.uuid4())
        
        message = {
            "type": "service_query",
            "query_id": query_id,
            "timestamp": datetime.now().isoformat(),
            "service_type": service_type,
            "capabilities": capabilities or [],
            "tags": tags or []
        }
        
        # Send query
        await self.send_multicast_message(message)
        
        # Wait for responses (simplified - in real implementation, collect responses)
        await asyncio.sleep(timeout)
        
        # Return services from registry that match criteria
        services = list(self.registry.services.values())
        
        if service_type:
            services = [s for s in services if s.service_type.value == service_type]
        
        if capabilities:
            services = [s for s in services 
                       if s.capabilities and all(cap in s.capabilities for cap in capabilities)]
        
        if tags:
            services = [s for s in services 
                       if s.tags and all(tag in s.tags for tag in tags)]
        
        return services

    async def send_query_response(self, query_id: str, services: List[ServiceInstance], addr: tuple):
        """Send response to service query"""
        try:
            message = {
                "type": "service_query_response",
                "query_id": query_id,
                "timestamp": datetime.now().isoformat(),
                "services": [
                    {
                        "service_id": service.service_id,
                        "service_type": service.service_type.value,
                        "name": service.name,
                        "host": service.host,
                        "port": service.port,
                        "protocol": service.protocol,
                        "capabilities": service.capabilities or [],
                        "tags": list(service.tags) if service.tags else []
                    }
                    for service in services
                ]
            }
            
            # Send directly to requesting address
            data = json.dumps(message).encode('utf-8')
            compressed_data = zlib.compress(data)
            
            if self.broadcast_socket:
                loop = asyncio.get_event_loop()
                await loop.sock_sendto(self.broadcast_socket, compressed_data, addr)
            
        except Exception as e:
            logger.error(f"Error sending query response: {e}")

    async def send_multicast_message(self, message: Dict[str, Any]):
        """Send multicast message"""
        try:
            data = json.dumps(message).encode('utf-8')
            compressed_data = zlib.compress(data)
            
            if self.broadcast_socket:
                addr = (self.config.multicast_group, self.config.multicast_port)
                loop = asyncio.get_event_loop()
                await loop.sock_sendto(self.broadcast_socket, compressed_data, addr)
            
        except Exception as e:
            logger.error(f"Error sending multicast message: {e}")

    async def health_check_loop(self):
        """Health check loop for monitoring service availability"""
        while self.running:
            try:
                current_time = datetime.now()
                
                for service in list(self.registry.services.values()):
                    # Skip local services
                    if service.service_id in self.local_services:
                        continue
                    
                    # Check if service needs health check
                    if (service.health_endpoint and 
                        service.status == ServiceStatus.AVAILABLE and
                        current_time - service.last_seen > timedelta(seconds=service.health_check_interval)):
                        
                        await self.perform_health_check(service)
                
                await asyncio.sleep(self.config.health_check_interval)
                
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(self.config.health_check_interval)

    async def perform_health_check(self, service: ServiceInstance):
        """Perform health check on a service"""
        try:
            import aiohttp
            
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                health_url = f"{service.protocol}://{service.host}:{service.port}{service.health_endpoint}"
                
                async with session.get(health_url) as response:
                    if response.status == 200:
                        await self.registry.update_service(service.service_id, {
                            "status": ServiceStatus.AVAILABLE,
                            "last_seen": datetime.now()
                        })
                    else:
                        await self.registry.update_service(service.service_id, {
                            "status": ServiceStatus.FAILED
                        })
                        
        except Exception as e:
            logger.debug(f"Health check failed for service {service.service_id}: {e}")
            await self.registry.update_service(service.service_id, {
                "status": ServiceStatus.FAILED
            })

    async def cleanup_loop(self):
        """Cleanup stale services"""
        while self.running:
            try:
                current_time = datetime.now()
                timeout_threshold = timedelta(seconds=self.config.service_timeout)
                
                stale_services = []
                for service in self.registry.services.values():
                    # Skip local services
                    if service.service_id in self.local_services:
                        continue
                    
                    if current_time - service.last_seen > timeout_threshold:
                        stale_services.append(service.service_id)
                
                # Remove stale services
                for service_id in stale_services:
                    await self.registry.deregister_service(service_id)
                    logger.info(f"Removed stale service {service_id}")
                
                await asyncio.sleep(self.config.cleanup_interval)
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(self.config.cleanup_interval)

    def get_registry(self) -> ServiceRegistry:
        """Get the service registry"""
        return self.registry


if __name__ == "__main__":
    async def main():
        # Example usage
        discovery = ServiceDiscovery()
        
        # Register a sample service
        sample_service = ServiceInstance(
            service_id="test_service_1",
            service_type=ServiceType.LOAD_GENERATOR,
            name="Test Load Generator",
            host="localhost",
            port=8090,
            protocol="http",
            health_endpoint="/health",
            capabilities=["http_load", "stress_testing"],
            tags={"environment", "test"}
        )
        
        await discovery.start()
        await discovery.register_local_service(sample_service)
        
        try:
            # Keep running
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            await discovery.stop()
    
    asyncio.run(main())
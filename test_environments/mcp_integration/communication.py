"""
Inter-node Communication - Reliable messaging system for distributed MCP testing.
Implements message routing, reliability, and coordination protocols.
"""

import asyncio
import json
import logging
import time
import uuid
import hashlib
import hmac
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
import websockets
import aiohttp
from concurrent.futures import ThreadPoolExecutor
import zlib
import pickle

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MessageType(Enum):
    """Message type enumeration"""
    CONTROL = "control"
    DATA = "data"
    STATUS = "status"
    HEARTBEAT = "heartbeat"
    DISCOVERY = "discovery"
    COORDINATION = "coordination"
    RESULT = "result"
    ERROR = "error"


class MessagePriority(Enum):
    """Message priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class DeliveryMode(Enum):
    """Message delivery modes"""
    FIRE_AND_FORGET = "fire_and_forget"
    AT_LEAST_ONCE = "at_least_once"
    EXACTLY_ONCE = "exactly_once"
    RELIABLE = "reliable"


@dataclass
class Message:
    """Inter-node message structure"""
    message_id: str
    message_type: MessageType
    sender_id: str
    recipient_id: str
    payload: Any
    priority: MessagePriority = MessagePriority.NORMAL
    delivery_mode: DeliveryMode = DeliveryMode.RELIABLE
    timestamp: datetime = None
    ttl: Optional[timedelta] = None
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None
    headers: Dict[str, Any] = None
    retries: int = 0
    max_retries: int = 3
    checksum: Optional[str] = None


@dataclass
class MessageRoute:
    """Message routing information"""
    destination: str
    next_hop: str
    cost: int
    last_updated: datetime


@dataclass
class Connection:
    """Connection to another node"""
    node_id: str
    host: str
    port: int
    protocol: str
    websocket: Optional[websockets.WebSocketServerProtocol] = None
    status: str = "disconnected"
    last_heartbeat: datetime = None
    connection_time: datetime = None
    message_count: int = 0
    error_count: int = 0


class MessageQueue:
    """Priority message queue with reliability features"""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self.queues = {
            MessagePriority.CRITICAL: asyncio.Queue(),
            MessagePriority.HIGH: asyncio.Queue(),
            MessagePriority.NORMAL: asyncio.Queue(),
            MessagePriority.LOW: asyncio.Queue()
        }
        self.pending_acks: Dict[str, Message] = {}
        self.lock = asyncio.Lock()

    async def put(self, message: Message):
        """Add message to queue"""
        async with self.lock:
            if self.size() >= self.max_size:
                # Remove oldest low priority message
                try:
                    await asyncio.wait_for(
                        self.queues[MessagePriority.LOW].get_nowait(), 
                        timeout=0.1
                    )
                except:
                    pass
            
            await self.queues[message.priority].put(message)
            
            # Track message for acknowledgment if needed
            if message.delivery_mode in [DeliveryMode.AT_LEAST_ONCE, DeliveryMode.EXACTLY_ONCE, DeliveryMode.RELIABLE]:
                self.pending_acks[message.message_id] = message

    async def get(self) -> Optional[Message]:
        """Get next message by priority"""
        # Check queues in priority order
        for priority in [MessagePriority.CRITICAL, MessagePriority.HIGH, 
                        MessagePriority.NORMAL, MessagePriority.LOW]:
            try:
                message = self.queues[priority].get_nowait()
                return message
            except asyncio.QueueEmpty:
                continue
        
        return None

    async def acknowledge(self, message_id: str):
        """Acknowledge message delivery"""
        async with self.lock:
            if message_id in self.pending_acks:
                del self.pending_acks[message_id]

    def size(self) -> int:
        """Get total queue size"""
        return sum(queue.qsize() for queue in self.queues.values())

    def get_pending_count(self) -> int:
        """Get count of pending acknowledgments"""
        return len(self.pending_acks)


class MessageRouter:
    """Message routing and delivery system"""
    
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.routing_table: Dict[str, MessageRoute] = {}
        self.connections: Dict[str, Connection] = {}
        self.message_handlers: Dict[MessageType, List[Callable]] = {}
        self.outbound_queue = MessageQueue()
        self.inbound_queue = MessageQueue()
        self.running = False
        self.secret_key = "distributed_testing_secret"  # In production, use proper key management

    async def add_connection(self, connection: Connection):
        """Add connection to another node"""
        self.connections[connection.node_id] = connection
        connection.connection_time = datetime.now()
        connection.status = "connected"
        
        # Update routing table
        route = MessageRoute(
            destination=connection.node_id,
            next_hop=connection.node_id,
            cost=1,
            last_updated=datetime.now()
        )
        self.routing_table[connection.node_id] = route
        
        logger.info(f"Added connection to node {connection.node_id}")

    async def remove_connection(self, node_id: str):
        """Remove connection to a node"""
        if node_id in self.connections:
            connection = self.connections[node_id]
            if connection.websocket:
                await connection.websocket.close()
            
            del self.connections[node_id]
            
            # Update routing table
            if node_id in self.routing_table:
                del self.routing_table[node_id]
            
            logger.info(f"Removed connection to node {node_id}")

    def register_handler(self, message_type: MessageType, handler: Callable):
        """Register message handler"""
        if message_type not in self.message_handlers:
            self.message_handlers[message_type] = []
        
        self.message_handlers[message_type].append(handler)

    def unregister_handler(self, message_type: MessageType, handler: Callable):
        """Unregister message handler"""
        if message_type in self.message_handlers:
            if handler in self.message_handlers[message_type]:
                self.message_handlers[message_type].remove(handler)

    async def send_message(self, message: Message):
        """Send message to recipient"""
        # Set message metadata
        if not message.message_id:
            message.message_id = str(uuid.uuid4())
        
        if not message.timestamp:
            message.timestamp = datetime.now()
        
        if not message.sender_id:
            message.sender_id = self.node_id
        
        # Calculate checksum
        message.checksum = self._calculate_checksum(message)
        
        # Add to outbound queue
        await self.outbound_queue.put(message)
        
        logger.debug(f"Queued message {message.message_id} to {message.recipient_id}")

    async def broadcast_message(self, message: Message, exclude_nodes: Set[str] = None):
        """Broadcast message to all connected nodes"""
        exclude_nodes = exclude_nodes or set()
        
        for node_id in self.connections:
            if node_id not in exclude_nodes:
                # Create copy for each recipient
                msg_copy = Message(
                    message_id=str(uuid.uuid4()),
                    message_type=message.message_type,
                    sender_id=self.node_id,
                    recipient_id=node_id,
                    payload=message.payload,
                    priority=message.priority,
                    delivery_mode=message.delivery_mode,
                    timestamp=datetime.now(),
                    ttl=message.ttl,
                    correlation_id=message.correlation_id,
                    headers=message.headers
                )
                
                await self.send_message(msg_copy)

    async def process_outbound_messages(self):
        """Process outbound message queue"""
        while self.running:
            try:
                message = await self.outbound_queue.get()
                if message:
                    await self._deliver_message(message)
                else:
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Error processing outbound message: {e}")

    async def process_inbound_messages(self):
        """Process inbound message queue"""
        while self.running:
            try:
                message = await self.inbound_queue.get()
                if message:
                    await self._handle_message(message)
                else:
                    await asyncio.sleep(0.1)
                    
            except Exception as e:
                logger.error(f"Error processing inbound message: {e}")

    async def _deliver_message(self, message: Message):
        """Deliver message to recipient"""
        try:
            # Check if message has expired
            if message.ttl and message.timestamp:
                if datetime.now() - message.timestamp > message.ttl:
                    logger.warning(f"Message {message.message_id} expired, dropping")
                    return
            
            # Find route to recipient
            if message.recipient_id not in self.routing_table:
                logger.warning(f"No route to recipient {message.recipient_id}")
                await self._handle_delivery_failure(message)
                return
            
            route = self.routing_table[message.recipient_id]
            next_hop = route.next_hop
            
            # Get connection
            if next_hop not in self.connections:
                logger.warning(f"No connection to next hop {next_hop}")
                await self._handle_delivery_failure(message)
                return
            
            connection = self.connections[next_hop]
            
            if connection.status != "connected" or not connection.websocket:
                logger.warning(f"Connection to {next_hop} not available")
                await self._handle_delivery_failure(message)
                return
            
            # Serialize and send message
            serialized_message = self._serialize_message(message)
            
            try:
                await connection.websocket.send(serialized_message)
                connection.message_count += 1
                
                logger.debug(f"Delivered message {message.message_id} to {next_hop}")
                
            except Exception as e:
                logger.error(f"Failed to send message to {next_hop}: {e}")
                connection.error_count += 1
                await self._handle_delivery_failure(message)
                
        except Exception as e:
            logger.error(f"Error delivering message: {e}")
            await self._handle_delivery_failure(message)

    async def _handle_delivery_failure(self, message: Message):
        """Handle message delivery failure"""
        message.retries += 1
        
        if message.retries < message.max_retries:
            # Retry delivery
            await asyncio.sleep(min(2 ** message.retries, 30))  # Exponential backoff
            await self.outbound_queue.put(message)
            logger.debug(f"Retrying message {message.message_id} (attempt {message.retries})")
        else:
            logger.error(f"Message {message.message_id} failed after {message.retries} retries")
            
            # Send error notification if needed
            if message.reply_to:
                error_message = Message(
                    message_id=str(uuid.uuid4()),
                    message_type=MessageType.ERROR,
                    sender_id=self.node_id,
                    recipient_id=message.reply_to,
                    payload={
                        "error": "delivery_failed",
                        "original_message_id": message.message_id,
                        "reason": "max_retries_exceeded"
                    },
                    correlation_id=message.correlation_id
                )
                
                await self.send_message(error_message)

    async def receive_message(self, websocket, raw_message: str):
        """Receive message from websocket"""
        try:
            message = self._deserialize_message(raw_message)
            
            # Verify checksum
            if not self._verify_checksum(message):
                logger.warning(f"Invalid checksum for message {message.message_id}")
                return
            
            # Send acknowledgment if required
            if message.delivery_mode in [DeliveryMode.AT_LEAST_ONCE, DeliveryMode.EXACTLY_ONCE, DeliveryMode.RELIABLE]:
                ack_message = Message(
                    message_id=str(uuid.uuid4()),
                    message_type=MessageType.CONTROL,
                    sender_id=self.node_id,
                    recipient_id=message.sender_id,
                    payload={"type": "ack", "message_id": message.message_id}
                )
                
                serialized_ack = self._serialize_message(ack_message)
                await websocket.send(serialized_ack)
            
            # Check if this is an acknowledgment
            if (message.message_type == MessageType.CONTROL and 
                message.payload.get("type") == "ack"):
                
                await self.outbound_queue.acknowledge(message.payload["message_id"])
                return
            
            # Route message if not for us
            if message.recipient_id != self.node_id:
                await self._forward_message(message)
                return
            
            # Add to inbound queue for processing
            await self.inbound_queue.put(message)
            
        except Exception as e:
            logger.error(f"Error receiving message: {e}")

    async def _forward_message(self, message: Message):
        """Forward message to its destination"""
        # Implement message forwarding logic
        if message.recipient_id in self.routing_table:
            await self.outbound_queue.put(message)
        else:
            logger.warning(f"Cannot forward message to {message.recipient_id} - no route")

    async def _handle_message(self, message: Message):
        """Handle received message"""
        try:
            # Call registered handlers
            if message.message_type in self.message_handlers:
                for handler in self.message_handlers[message.message_type]:
                    try:
                        if asyncio.iscoroutinefunction(handler):
                            await handler(message)
                        else:
                            handler(message)
                    except Exception as e:
                        logger.error(f"Error in message handler: {e}")
            
            logger.debug(f"Handled message {message.message_id} of type {message.message_type}")
            
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    def _serialize_message(self, message: Message) -> str:
        """Serialize message for transmission"""
        try:
            # Convert to dictionary
            message_dict = asdict(message)
            
            # Handle datetime serialization
            if message_dict["timestamp"]:
                message_dict["timestamp"] = message_dict["timestamp"].isoformat()
            
            if message_dict["ttl"]:
                message_dict["ttl"] = message_dict["ttl"].total_seconds()
            
            # Convert enums to values
            message_dict["message_type"] = message_dict["message_type"].value
            message_dict["priority"] = message_dict["priority"].value
            message_dict["delivery_mode"] = message_dict["delivery_mode"].value
            
            # Serialize and compress
            json_data = json.dumps(message_dict)
            compressed_data = zlib.compress(json_data.encode('utf-8'))
            
            return compressed_data.hex()
            
        except Exception as e:
            logger.error(f"Error serializing message: {e}")
            raise

    def _deserialize_message(self, serialized_message: str) -> Message:
        """Deserialize message from transmission"""
        try:
            # Decompress and deserialize
            compressed_data = bytes.fromhex(serialized_message)
            json_data = zlib.decompress(compressed_data).decode('utf-8')
            message_dict = json.loads(json_data)
            
            # Convert back to proper types
            if message_dict["timestamp"]:
                message_dict["timestamp"] = datetime.fromisoformat(message_dict["timestamp"])
            
            if message_dict["ttl"]:
                message_dict["ttl"] = timedelta(seconds=message_dict["ttl"])
            
            message_dict["message_type"] = MessageType(message_dict["message_type"])
            message_dict["priority"] = MessagePriority(message_dict["priority"])
            message_dict["delivery_mode"] = DeliveryMode(message_dict["delivery_mode"])
            
            return Message(**message_dict)
            
        except Exception as e:
            logger.error(f"Error deserializing message: {e}")
            raise

    def _calculate_checksum(self, message: Message) -> str:
        """Calculate message checksum"""
        try:
            # Create message content for checksum
            content = f"{message.message_id}{message.sender_id}{message.recipient_id}"
            content += f"{message.message_type.value}{json.dumps(message.payload, sort_keys=True)}"
            
            # Calculate HMAC
            return hmac.new(
                self.secret_key.encode('utf-8'),
                content.encode('utf-8'),
                hashlib.sha256
            ).hexdigest()
            
        except Exception as e:
            logger.error(f"Error calculating checksum: {e}")
            return ""

    def _verify_checksum(self, message: Message) -> bool:
        """Verify message checksum"""
        try:
            expected_checksum = self._calculate_checksum(message)
            return hmac.compare_digest(expected_checksum, message.checksum or "")
        except Exception as e:
            logger.error(f"Error verifying checksum: {e}")
            return False


class CommunicationHub:
    """Central communication hub for coordinating distributed testing"""
    
    def __init__(self, node_id: str, host: str = "localhost", port: int = 8085):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.router = MessageRouter(node_id)
        self.websocket_server = None
        self.running = False
        
        # Register default handlers
        self.router.register_handler(MessageType.HEARTBEAT, self._handle_heartbeat)
        self.router.register_handler(MessageType.STATUS, self._handle_status)
        self.router.register_handler(MessageType.DISCOVERY, self._handle_discovery)

    async def start(self):
        """Start communication hub"""
        self.running = True
        self.router.running = True
        
        logger.info(f"Starting communication hub {self.node_id} on {self.host}:{self.port}")
        
        # Start WebSocket server
        self.websocket_server = await websockets.serve(
            self.handle_websocket_connection,
            self.host,
            self.port
        )
        
        # Start message processing tasks
        outbound_task = asyncio.create_task(self.router.process_outbound_messages())
        inbound_task = asyncio.create_task(self.router.process_inbound_messages())
        heartbeat_task = asyncio.create_task(self.send_heartbeats())
        
        try:
            await asyncio.gather(outbound_task, inbound_task, heartbeat_task)
        except Exception as e:
            logger.error(f"Error in communication hub: {e}")
        finally:
            await self.stop()

    async def stop(self):
        """Stop communication hub"""
        self.running = False
        self.router.running = False
        
        if self.websocket_server:
            self.websocket_server.close()
            await self.websocket_server.wait_closed()
        
        # Close all connections
        for connection in list(self.router.connections.values()):
            await self.router.remove_connection(connection.node_id)
        
        logger.info("Communication hub stopped")

    async def handle_websocket_connection(self, websocket, path):
        """Handle WebSocket connection from another node"""
        node_id = None
        try:
            # Wait for node identification
            initial_message = await asyncio.wait_for(websocket.recv(), timeout=30)
            message = self.router._deserialize_message(initial_message)
            
            if (message.message_type == MessageType.CONTROL and 
                message.payload.get("type") == "identify"):
                
                node_id = message.sender_id
                
                # Create connection
                connection = Connection(
                    node_id=node_id,
                    host=websocket.remote_address[0],
                    port=websocket.remote_address[1],
                    protocol="websocket",
                    websocket=websocket,
                    status="connected"
                )
                
                await self.router.add_connection(connection)
                
                # Send identification response
                response = Message(
                    message_id=str(uuid.uuid4()),
                    message_type=MessageType.CONTROL,
                    sender_id=self.node_id,
                    recipient_id=node_id,
                    payload={"type": "identify_response", "status": "connected"}
                )
                
                serialized_response = self.router._serialize_message(response)
                await websocket.send(serialized_response)
                
                logger.info(f"Node {node_id} connected via WebSocket")
                
                # Listen for messages
                async for message in websocket:
                    await self.router.receive_message(websocket, message)
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Node {node_id} disconnected")
        except Exception as e:
            logger.error(f"Error handling WebSocket connection: {e}")
        finally:
            if node_id:
                await self.router.remove_connection(node_id)

    async def connect_to_node(self, node_id: str, host: str, port: int):
        """Connect to another node"""
        try:
            uri = f"ws://{host}:{port}"
            websocket = await websockets.connect(uri)
            
            # Send identification
            identify_message = Message(
                message_id=str(uuid.uuid4()),
                message_type=MessageType.CONTROL,
                sender_id=self.node_id,
                recipient_id=node_id,
                payload={"type": "identify"}
            )
            
            serialized_message = self.router._serialize_message(identify_message)
            await websocket.send(serialized_message)
            
            # Wait for response
            response = await asyncio.wait_for(websocket.recv(), timeout=30)
            response_message = self.router._deserialize_message(response)
            
            if (response_message.payload.get("type") == "identify_response" and
                response_message.payload.get("status") == "connected"):
                
                # Create connection
                connection = Connection(
                    node_id=node_id,
                    host=host,
                    port=port,
                    protocol="websocket",
                    websocket=websocket,
                    status="connected"
                )
                
                await self.router.add_connection(connection)
                
                # Start listening for messages
                asyncio.create_task(self.listen_to_node(websocket, node_id))
                
                logger.info(f"Successfully connected to node {node_id}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to connect to node {node_id}: {e}")
            return False

    async def listen_to_node(self, websocket, node_id: str):
        """Listen for messages from a connected node"""
        try:
            async for message in websocket:
                await self.router.receive_message(websocket, message)
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Connection to node {node_id} closed")
        except Exception as e:
            logger.error(f"Error listening to node {node_id}: {e}")
        finally:
            await self.router.remove_connection(node_id)

    async def send_heartbeats(self):
        """Send periodic heartbeats to all connected nodes"""
        while self.running:
            try:
                heartbeat_message = Message(
                    message_id=str(uuid.uuid4()),
                    message_type=MessageType.HEARTBEAT,
                    sender_id=self.node_id,
                    recipient_id="all",
                    payload={
                        "timestamp": datetime.now().isoformat(),
                        "status": "healthy",
                        "connections": len(self.router.connections)
                    }
                )
                
                await self.router.broadcast_message(heartbeat_message)
                await asyncio.sleep(30)  # Send heartbeat every 30 seconds
                
            except Exception as e:
                logger.error(f"Error sending heartbeat: {e}")

    async def _handle_heartbeat(self, message: Message):
        """Handle heartbeat message"""
        # Update connection last heartbeat time
        if message.sender_id in self.router.connections:
            connection = self.router.connections[message.sender_id]
            connection.last_heartbeat = datetime.now()

    async def _handle_status(self, message: Message):
        """Handle status message"""
        logger.debug(f"Received status from {message.sender_id}: {message.payload}")

    async def _handle_discovery(self, message: Message):
        """Handle discovery message"""
        logger.debug(f"Received discovery from {message.sender_id}: {message.payload}")

    # Public API methods
    async def send_to_node(self, node_id: str, message_type: MessageType, 
                          payload: Any, priority: MessagePriority = MessagePriority.NORMAL):
        """Send message to specific node"""
        message = Message(
            message_id=str(uuid.uuid4()),
            message_type=message_type,
            sender_id=self.node_id,
            recipient_id=node_id,
            payload=payload,
            priority=priority
        )
        
        await self.router.send_message(message)

    async def broadcast(self, message_type: MessageType, payload: Any, 
                       priority: MessagePriority = MessagePriority.NORMAL,
                       exclude_nodes: Set[str] = None):
        """Broadcast message to all nodes"""
        message = Message(
            message_id=str(uuid.uuid4()),
            message_type=message_type,
            sender_id=self.node_id,
            recipient_id="all",
            payload=payload,
            priority=priority
        )
        
        await self.router.broadcast_message(message, exclude_nodes)

    def register_message_handler(self, message_type: MessageType, handler: Callable):
        """Register message handler"""
        self.router.register_handler(message_type, handler)

    def get_connected_nodes(self) -> List[str]:
        """Get list of connected node IDs"""
        return list(self.router.connections.keys())

    def get_connection_info(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get connection information for a node"""
        if node_id in self.router.connections:
            connection = self.router.connections[node_id]
            return {
                "node_id": connection.node_id,
                "host": connection.host,
                "port": connection.port,
                "status": connection.status,
                "connection_time": connection.connection_time.isoformat() if connection.connection_time else None,
                "last_heartbeat": connection.last_heartbeat.isoformat() if connection.last_heartbeat else None,
                "message_count": connection.message_count,
                "error_count": connection.error_count
            }
        return None


if __name__ == "__main__":
    async def main():
        import sys
        
        node_id = sys.argv[1] if len(sys.argv) > 1 else f"comm_hub_{uuid.uuid4().hex[:8]}"
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8085
        
        hub = CommunicationHub(node_id, port=port)
        
        try:
            await hub.start()
        except KeyboardInterrupt:
            await hub.stop()
    
    asyncio.run(main())
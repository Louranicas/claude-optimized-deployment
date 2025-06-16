"""
Persistence Layer - Efficient learning data storage and retrieval
"""

import asyncio
from typing import Dict, List, Any, Optional, AsyncGenerator
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import pickle
import sqlite3
import aiosqlite
import aiofiles
import numpy as np
import hashlib
import lz4.frame
import zstandard as zstd
from pathlib import Path

from .models import Learning, Patterns, Knowledge, Prediction


@dataclass
class StorageConfig:
    """Configuration for storage systems"""
    base_path: str = "/tmp/mcp_learning"
    time_series_db_path: str = None
    graph_db_path: str = None
    vector_db_path: str = None
    model_store_path: str = None
    compression_level: int = 3
    retention_days: int = 30
    auto_cleanup: bool = True


class LearningStorage:
    """Main storage orchestrator for learning data"""
    
    def __init__(self, config: StorageConfig = None):
        self.config = config or StorageConfig()
        self.time_series_db = TimeSeriesDB(self.config)
        self.graph_db = GraphDatabase(self.config)
        self.vector_db = VectorDatabase(self.config)
        self.model_store = ModelStore(self.config)
        self.metadata_store = MetadataStore(self.config)
        self.cache = LearningCache()
        
    async def initialize(self):
        """Initialize all storage systems"""
        await asyncio.gather(
            self.time_series_db.initialize(),
            self.graph_db.initialize(),
            self.vector_db.initialize(),
            self.model_store.initialize(),
            self.metadata_store.initialize()
        )
        
        # Start background tasks
        asyncio.create_task(self._cleanup_task())
        asyncio.create_task(self._compression_task())
    
    async def store_learning_increment(self, learning: Learning) -> str:
        """Store a learning increment efficiently"""
        learning_id = self._generate_learning_id(learning)
        
        # Store in parallel across systems
        tasks = [
            self._store_temporal_data(learning_id, learning),
            self._store_graph_data(learning_id, learning),
            self._store_vector_data(learning_id, learning),
            self._store_model_data(learning_id, learning),
            self._store_metadata(learning_id, learning)
        ]
        
        await asyncio.gather(*tasks)
        
        # Update cache
        await self.cache.store(learning_id, learning)
        
        return learning_id
    
    async def retrieve_learning(self, learning_id: str) -> Optional[Learning]:
        """Retrieve a learning by ID"""
        # Check cache first
        cached = await self.cache.get(learning_id)
        if cached:
            return cached
        
        # Retrieve from storage
        metadata = await self.metadata_store.get(learning_id)
        if not metadata:
            return None
        
        # Load components based on metadata
        loading_tasks = []
        
        if metadata.get("has_temporal_data"):
            loading_tasks.append(self.time_series_db.get(learning_id))
        else:
            loading_tasks.append(asyncio.create_task(self._return_none()))
        
        if metadata.get("has_graph_data"):
            loading_tasks.append(self.graph_db.get(learning_id))
        else:
            loading_tasks.append(asyncio.create_task(self._return_none()))
        
        if metadata.get("has_vector_data"):
            loading_tasks.append(self.vector_db.get(learning_id))
        else:
            loading_tasks.append(asyncio.create_task(self._return_none()))
        
        if metadata.get("has_model_data"):
            loading_tasks.append(self.model_store.get(learning_id))
        else:
            loading_tasks.append(asyncio.create_task(self._return_none()))
        
        results = await asyncio.gather(*loading_tasks)
        temporal_data, graph_data, vector_data, model_data = results
        
        # Reconstruct learning
        learning = self._reconstruct_learning(
            learning_id,
            metadata,
            temporal_data,
            graph_data,
            vector_data,
            model_data
        )
        
        # Cache result
        await self.cache.store(learning_id, learning)
        
        return learning
    
    async def query_learnings(self, query: Dict[str, Any]) -> AsyncGenerator[Learning, None]:
        """Query learnings based on criteria"""
        # Get matching IDs from metadata store
        learning_ids = await self.metadata_store.query(query)
        
        # Stream results
        for learning_id in learning_ids:
            learning = await self.retrieve_learning(learning_id)
            if learning:
                yield learning
    
    async def get_recent_learnings(self, count: int = 100) -> List[Learning]:
        """Get recent learnings"""
        query = {
            "order_by": "timestamp",
            "order": "desc",
            "limit": count
        }
        
        learnings = []
        async for learning in self.query_learnings(query):
            learnings.append(learning)
        
        return learnings
    
    async def get_learning_statistics(self) -> Dict[str, Any]:
        """Get storage statistics"""
        stats = await asyncio.gather(
            self.time_series_db.get_stats(),
            self.graph_db.get_stats(),
            self.vector_db.get_stats(),
            self.model_store.get_stats(),
            self.metadata_store.get_stats()
        )
        
        return {
            "time_series": stats[0],
            "graph": stats[1],
            "vector": stats[2],
            "model": stats[3],
            "metadata": stats[4],
            "cache": await self.cache.get_stats()
        }
    
    async def cleanup_old_data(self, older_than: timedelta = None):
        """Clean up old learning data"""
        if older_than is None:
            older_than = timedelta(days=self.config.retention_days)
        
        cutoff_date = datetime.utcnow() - older_than
        
        # Clean up each storage system
        await asyncio.gather(
            self.time_series_db.cleanup(cutoff_date),
            self.graph_db.cleanup(cutoff_date),
            self.vector_db.cleanup(cutoff_date),
            self.model_store.cleanup(cutoff_date),
            self.metadata_store.cleanup(cutoff_date)
        )
        
        # Clean cache
        await self.cache.cleanup()
    
    def _generate_learning_id(self, learning: Learning) -> str:
        """Generate unique ID for learning"""
        content = json.dumps({
            "type": learning.type,
            "timestamp": learning.timestamp.isoformat(),
            "source": getattr(learning.source_interaction, 'source', 'unknown') if learning.source_interaction else 'unknown'
        }, sort_keys=True)
        
        return hashlib.sha256(content.encode()).hexdigest()
    
    async def _store_temporal_data(self, learning_id: str, learning: Learning):
        """Store temporal aspects of learning"""
        if learning.patterns and hasattr(learning.patterns, 'temporal'):
            await self.time_series_db.insert(learning_id, {
                "timestamp": learning.timestamp,
                "temporal_patterns": learning.patterns.temporal,
                "metadata": learning.metadata
            })
    
    async def _store_graph_data(self, learning_id: str, learning: Learning):
        """Store graph/relationship data"""
        if learning.patterns and hasattr(learning.patterns, 'structural'):
            await self.graph_db.insert(learning_id, {
                "structural_patterns": learning.patterns.structural,
                "relationships": getattr(learning.patterns, 'correlations', []),
                "timestamp": learning.timestamp
            })
    
    async def _store_vector_data(self, learning_id: str, learning: Learning):
        """Store vector embeddings"""
        vectors = []
        
        # Extract vectors from different sources
        if learning.patterns:
            if hasattr(learning.patterns, 'clusters'):
                for cluster in learning.patterns.clusters:
                    if hasattr(cluster, 'centroid'):
                        vectors.append({
                            "type": "cluster_centroid",
                            "vector": cluster.centroid,
                            "metadata": {"confidence": cluster.confidence}
                        })
        
        if vectors:
            await self.vector_db.insert(learning_id, vectors)
    
    async def _store_model_data(self, learning_id: str, learning: Learning):
        """Store model states and predictions"""
        if learning.predictions:
            await self.model_store.insert(learning_id, {
                "predictions": learning.predictions,
                "optimization": learning.optimization,
                "timestamp": learning.timestamp
            })
    
    async def _store_metadata(self, learning_id: str, learning: Learning):
        """Store learning metadata"""
        metadata = {
            "learning_id": learning_id,
            "type": learning.type,
            "timestamp": learning.timestamp,
            "cross_instance_relevance": learning.cross_instance_relevance,
            "has_temporal_data": bool(learning.patterns and hasattr(learning.patterns, 'temporal')),
            "has_graph_data": bool(learning.patterns and hasattr(learning.patterns, 'structural')),
            "has_vector_data": bool(learning.patterns and hasattr(learning.patterns, 'clusters')),
            "has_model_data": bool(learning.predictions),
            "metadata": learning.metadata
        }
        
        await self.metadata_store.insert(learning_id, metadata)
    
    def _reconstruct_learning(self, learning_id: str, metadata: Dict,
                            temporal_data: Any, graph_data: Any,
                            vector_data: Any, model_data: Any) -> Learning:
        """Reconstruct learning from components"""
        # Create patterns
        patterns = Patterns()
        if temporal_data:
            patterns.temporal = temporal_data.get("temporal_patterns", [])
        if graph_data:
            patterns.structural = graph_data.get("structural_patterns", [])
            patterns.correlations = graph_data.get("relationships", [])
        
        # Create predictions
        predictions = None
        optimization = None
        if model_data:
            predictions = model_data.get("predictions")
            optimization = model_data.get("optimization")
        
        return Learning(
            type=metadata["type"],
            patterns=patterns,
            predictions=predictions,
            optimization=optimization,
            timestamp=metadata["timestamp"],
            cross_instance_relevance=metadata.get("cross_instance_relevance", 0.5),
            metadata=metadata.get("metadata", {})
        )
    
    async def _return_none(self):
        """Helper to return None async"""
        return None
    
    async def _cleanup_task(self):
        """Background cleanup task"""
        while True:
            try:
                if self.config.auto_cleanup:
                    await self.cleanup_old_data()
                await asyncio.sleep(3600)  # Run every hour
            except Exception as e:
                print(f"Cleanup task error: {e}")
                await asyncio.sleep(3600)
    
    async def _compression_task(self):
        """Background compression task"""
        while True:
            try:
                # Compress old data
                await asyncio.gather(
                    self.time_series_db.compress_old_data(),
                    self.vector_db.compress_old_data(),
                    self.model_store.compress_old_data()
                )
                await asyncio.sleep(7200)  # Run every 2 hours
            except Exception as e:
                print(f"Compression task error: {e}")
                await asyncio.sleep(7200)


class TimeSeriesDB:
    """Time series database for temporal learning data"""
    
    def __init__(self, config: StorageConfig):
        self.config = config
        self.db_path = config.time_series_db_path or f"{config.base_path}/timeseries.db"
        self.compressor = zstd.ZstdCompressor(level=config.compression_level)
        self.decompressor = zstd.ZstdDecompressor()
        
    async def initialize(self):
        """Initialize time series database"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS time_series_data (
                    learning_id TEXT PRIMARY KEY,
                    timestamp DATETIME,
                    data BLOB,
                    compressed BOOLEAN DEFAULT FALSE,
                    size_bytes INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON time_series_data(timestamp)
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at ON time_series_data(created_at)
            """)
            
            await db.commit()
    
    async def insert(self, learning_id: str, data: Dict[str, Any]):
        """Insert time series data"""
        # Serialize and optionally compress
        serialized = pickle.dumps(data)
        
        compressed = False
        if len(serialized) > 1024:  # Compress if larger than 1KB
            serialized = self.compressor.compress(serialized)
            compressed = True
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO time_series_data 
                (learning_id, timestamp, data, compressed, size_bytes)
                VALUES (?, ?, ?, ?, ?)
            """, (
                learning_id,
                data["timestamp"],
                serialized,
                compressed,
                len(serialized)
            ))
            await db.commit()
    
    async def get(self, learning_id: str) -> Optional[Dict[str, Any]]:
        """Get time series data by learning ID"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT data, compressed FROM time_series_data 
                WHERE learning_id = ?
            """, (learning_id,)) as cursor:
                row = await cursor.fetchone()
        
        if not row:
            return None
        
        data_blob, compressed = row
        
        # Decompress if needed
        if compressed:
            data_blob = self.decompressor.decompress(data_blob)
        
        return pickle.loads(data_blob)
    
    async def query_time_range(self, start_time: datetime, 
                              end_time: datetime) -> AsyncGenerator[Tuple[str, Dict], None]:
        """Query data in time range"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT learning_id, data, compressed FROM time_series_data 
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp
            """, (start_time, end_time)) as cursor:
                async for row in cursor:
                    learning_id, data_blob, compressed = row
                    
                    if compressed:
                        data_blob = self.decompressor.decompress(data_blob)
                    
                    data = pickle.loads(data_blob)
                    yield learning_id, data
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            # Total records
            async with db.execute("SELECT COUNT(*) FROM time_series_data") as cursor:
                total_records = (await cursor.fetchone())[0]
            
            # Total size
            async with db.execute("SELECT SUM(size_bytes) FROM time_series_data") as cursor:
                total_size = (await cursor.fetchone())[0] or 0
            
            # Compressed records
            async with db.execute("SELECT COUNT(*) FROM time_series_data WHERE compressed = TRUE") as cursor:
                compressed_records = (await cursor.fetchone())[0]
        
        return {
            "total_records": total_records,
            "total_size_bytes": total_size,
            "compressed_records": compressed_records,
            "compression_ratio": compressed_records / total_records if total_records > 0 else 0
        }
    
    async def cleanup(self, cutoff_date: datetime):
        """Clean up old data"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                DELETE FROM time_series_data 
                WHERE timestamp < ?
            """, (cutoff_date,))
            await db.commit()
    
    async def compress_old_data(self):
        """Compress old uncompressed data"""
        cutoff_date = datetime.utcnow() - timedelta(days=7)
        
        async with aiosqlite.connect(self.db_path) as db:
            # Get uncompressed old data
            async with db.execute("""
                SELECT learning_id, data FROM time_series_data 
                WHERE compressed = FALSE AND created_at < ?
            """, (cutoff_date,)) as cursor:
                rows = await cursor.fetchall()
            
            # Compress and update
            for learning_id, data_blob in rows:
                compressed_data = self.compressor.compress(data_blob)
                
                await db.execute("""
                    UPDATE time_series_data 
                    SET data = ?, compressed = TRUE, size_bytes = ?
                    WHERE learning_id = ?
                """, (compressed_data, len(compressed_data), learning_id))
            
            await db.commit()


class GraphDatabase:
    """Graph database for structural learning data"""
    
    def __init__(self, config: StorageConfig):
        self.config = config
        self.db_path = config.graph_db_path or f"{config.base_path}/graph.db"
        
    async def initialize(self):
        """Initialize graph database"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        async with aiosqlite.connect(self.db_path) as db:
            # Nodes table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS graph_nodes (
                    learning_id TEXT,
                    node_id TEXT,
                    node_type TEXT,
                    properties TEXT,
                    timestamp DATETIME,
                    PRIMARY KEY (learning_id, node_id)
                )
            """)
            
            # Edges table
            await db.execute("""
                CREATE TABLE IF NOT EXISTS graph_edges (
                    learning_id TEXT,
                    source_node TEXT,
                    target_node TEXT,
                    edge_type TEXT,
                    weight REAL,
                    properties TEXT,
                    timestamp DATETIME,
                    PRIMARY KEY (learning_id, source_node, target_node)
                )
            """)
            
            # Indexes
            await db.execute("CREATE INDEX IF NOT EXISTS idx_nodes_timestamp ON graph_nodes(timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_edges_timestamp ON graph_edges(timestamp)")
            
            await db.commit()
    
    async def insert(self, learning_id: str, data: Dict[str, Any]):
        """Insert graph data"""
        async with aiosqlite.connect(self.db_path) as db:
            timestamp = data["timestamp"]
            
            # Insert structural patterns as nodes
            for i, pattern in enumerate(data.get("structural_patterns", [])):
                await db.execute("""
                    INSERT OR REPLACE INTO graph_nodes 
                    (learning_id, node_id, node_type, properties, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    learning_id,
                    f"pattern_{i}",
                    "structural_pattern",
                    json.dumps(pattern.__dict__ if hasattr(pattern, '__dict__') else str(pattern)),
                    timestamp
                ))
            
            # Insert relationships as edges
            for i, rel in enumerate(data.get("relationships", [])):
                await db.execute("""
                    INSERT OR REPLACE INTO graph_edges 
                    (learning_id, source_node, target_node, edge_type, weight, properties, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    learning_id,
                    rel.get("source", f"unknown_{i}"),
                    rel.get("target", f"unknown_{i}"),
                    rel.get("type", "unknown"),
                    rel.get("strength", 1.0),
                    json.dumps(rel),
                    timestamp
                ))
            
            await db.commit()
    
    async def get(self, learning_id: str) -> Optional[Dict[str, Any]]:
        """Get graph data by learning ID"""
        async with aiosqlite.connect(self.db_path) as db:
            # Get nodes
            nodes = []
            async with db.execute("""
                SELECT node_id, node_type, properties FROM graph_nodes 
                WHERE learning_id = ?
            """, (learning_id,)) as cursor:
                async for row in cursor:
                    node_id, node_type, properties = row
                    nodes.append({
                        "id": node_id,
                        "type": node_type,
                        "properties": json.loads(properties)
                    })
            
            # Get edges
            edges = []
            async with db.execute("""
                SELECT source_node, target_node, edge_type, weight, properties FROM graph_edges 
                WHERE learning_id = ?
            """, (learning_id,)) as cursor:
                async for row in cursor:
                    source, target, edge_type, weight, properties = row
                    edges.append({
                        "source": source,
                        "target": target,
                        "type": edge_type,
                        "weight": weight,
                        "properties": json.loads(properties)
                    })
        
        if not nodes and not edges:
            return None
        
        return {
            "structural_patterns": nodes,
            "relationships": edges
        }
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get graph statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            # Node count
            async with db.execute("SELECT COUNT(*) FROM graph_nodes") as cursor:
                node_count = (await cursor.fetchone())[0]
            
            # Edge count
            async with db.execute("SELECT COUNT(*) FROM graph_edges") as cursor:
                edge_count = (await cursor.fetchone())[0]
            
            # Unique learning IDs
            async with db.execute("SELECT COUNT(DISTINCT learning_id) FROM graph_nodes") as cursor:
                unique_learnings = (await cursor.fetchone())[0]
        
        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "unique_learnings": unique_learnings,
            "avg_nodes_per_learning": node_count / unique_learnings if unique_learnings > 0 else 0
        }
    
    async def cleanup(self, cutoff_date: datetime):
        """Clean up old graph data"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM graph_nodes WHERE timestamp < ?", (cutoff_date,))
            await db.execute("DELETE FROM graph_edges WHERE timestamp < ?", (cutoff_date,))
            await db.commit()


class VectorDatabase:
    """Vector database for embeddings and high-dimensional data"""
    
    def __init__(self, config: StorageConfig):
        self.config = config
        self.db_path = config.vector_db_path or f"{config.base_path}/vectors.db"
        self.vectors_dir = Path(f"{config.base_path}/vectors")
        self.vectors_dir.mkdir(parents=True, exist_ok=True)
        
    async def initialize(self):
        """Initialize vector database"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS vector_metadata (
                    learning_id TEXT,
                    vector_id TEXT,
                    vector_type TEXT,
                    dimension INTEGER,
                    file_path TEXT,
                    compressed BOOLEAN DEFAULT FALSE,
                    metadata TEXT,
                    timestamp DATETIME,
                    PRIMARY KEY (learning_id, vector_id)
                )
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_vector_timestamp ON vector_metadata(timestamp)
            """)
            
            await db.commit()
    
    async def insert(self, learning_id: str, vectors: List[Dict[str, Any]]):
        """Insert vector data"""
        async with aiosqlite.connect(self.db_path) as db:
            for i, vector_data in enumerate(vectors):
                vector_id = f"vec_{i}"
                vector_array = vector_data["vector"]
                
                # Save vector to file
                file_path = self.vectors_dir / f"{learning_id}_{vector_id}.npy"
                np.save(file_path, vector_array)
                
                # Store metadata
                await db.execute("""
                    INSERT OR REPLACE INTO vector_metadata 
                    (learning_id, vector_id, vector_type, dimension, file_path, metadata, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    learning_id,
                    vector_id,
                    vector_data.get("type", "unknown"),
                    len(vector_array),
                    str(file_path),
                    json.dumps(vector_data.get("metadata", {})),
                    datetime.utcnow()
                ))
            
            await db.commit()
    
    async def get(self, learning_id: str) -> Optional[List[Dict[str, Any]]]:
        """Get vectors by learning ID"""
        async with aiosqlite.connect(self.db_path) as db:
            vectors = []
            async with db.execute("""
                SELECT vector_id, vector_type, file_path, metadata FROM vector_metadata 
                WHERE learning_id = ?
            """, (learning_id,)) as cursor:
                async for row in cursor:
                    vector_id, vector_type, file_path, metadata = row
                    
                    # Load vector from file
                    try:
                        vector_array = np.load(file_path)
                        vectors.append({
                            "id": vector_id,
                            "type": vector_type,
                            "vector": vector_array,
                            "metadata": json.loads(metadata)
                        })
                    except FileNotFoundError:
                        # File missing, skip this vector
                        continue
        
        return vectors if vectors else None
    
    async def similarity_search(self, query_vector: np.ndarray, 
                               top_k: int = 10) -> List[Tuple[str, float]]:
        """Find similar vectors"""
        results = []
        
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT learning_id, vector_id, file_path FROM vector_metadata 
                WHERE dimension = ?
            """, (len(query_vector),)) as cursor:
                async for row in cursor:
                    learning_id, vector_id, file_path = row
                    
                    try:
                        vector = np.load(file_path)
                        
                        # Calculate cosine similarity
                        similarity = np.dot(query_vector, vector) / (
                            np.linalg.norm(query_vector) * np.linalg.norm(vector)
                        )
                        
                        results.append((learning_id, similarity))
                    except:
                        continue
        
        # Sort by similarity and return top k
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get vector database statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            # Total vectors
            async with db.execute("SELECT COUNT(*) FROM vector_metadata") as cursor:
                total_vectors = (await cursor.fetchone())[0]
            
            # Average dimension
            async with db.execute("SELECT AVG(dimension) FROM vector_metadata") as cursor:
                avg_dimension = (await cursor.fetchone())[0] or 0
            
            # Unique learning IDs
            async with db.execute("SELECT COUNT(DISTINCT learning_id) FROM vector_metadata") as cursor:
                unique_learnings = (await cursor.fetchone())[0]
        
        return {
            "total_vectors": total_vectors,
            "avg_dimension": avg_dimension,
            "unique_learnings": unique_learnings,
            "avg_vectors_per_learning": total_vectors / unique_learnings if unique_learnings > 0 else 0
        }
    
    async def cleanup(self, cutoff_date: datetime):
        """Clean up old vector data"""
        async with aiosqlite.connect(self.db_path) as db:
            # Get file paths of old vectors
            async with db.execute("""
                SELECT file_path FROM vector_metadata WHERE timestamp < ?
            """, (cutoff_date,)) as cursor:
                file_paths = [row[0] for row in await cursor.fetchall()]
            
            # Delete files
            for file_path in file_paths:
                try:
                    Path(file_path).unlink(missing_ok=True)
                except:
                    pass
            
            # Delete metadata
            await db.execute("DELETE FROM vector_metadata WHERE timestamp < ?", (cutoff_date,))
            await db.commit()
    
    async def compress_old_data(self):
        """Compress old vector files"""
        cutoff_date = datetime.utcnow() - timedelta(days=7)
        
        async with aiosqlite.connect(self.db_path) as db:
            # Get old uncompressed vectors
            async with db.execute("""
                SELECT learning_id, vector_id, file_path FROM vector_metadata 
                WHERE compressed = FALSE AND timestamp < ?
            """, (cutoff_date,)) as cursor:
                rows = await cursor.fetchall()
            
            for learning_id, vector_id, file_path in rows:
                try:
                    # Load vector
                    vector = np.load(file_path)
                    
                    # Compress and save
                    compressed_data = lz4.frame.compress(vector.tobytes())
                    compressed_path = f"{file_path}.lz4"
                    
                    async with aiofiles.open(compressed_path, 'wb') as f:
                        await f.write(compressed_data)
                    
                    # Update metadata
                    await db.execute("""
                        UPDATE vector_metadata 
                        SET file_path = ?, compressed = TRUE
                        WHERE learning_id = ? AND vector_id = ?
                    """, (compressed_path, learning_id, vector_id))
                    
                    # Remove original file
                    Path(file_path).unlink(missing_ok=True)
                    
                except Exception as e:
                    print(f"Failed to compress {file_path}: {e}")
            
            await db.commit()


class ModelStore:
    """Store for model states and predictions"""
    
    def __init__(self, config: StorageConfig):
        self.config = config
        self.db_path = config.model_store_path or f"{config.base_path}/models.db"
        self.models_dir = Path(f"{config.base_path}/models")
        self.models_dir.mkdir(parents=True, exist_ok=True)
        
    async def initialize(self):
        """Initialize model store"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS model_data (
                    learning_id TEXT PRIMARY KEY,
                    model_type TEXT,
                    file_path TEXT,
                    compressed BOOLEAN DEFAULT FALSE,
                    size_bytes INTEGER,
                    performance_metrics TEXT,
                    timestamp DATETIME
                )
            """)
            
            await db.execute("""
                CREATE INDEX IF NOT EXISTS idx_model_timestamp ON model_data(timestamp)
            """)
            
            await db.commit()
    
    async def insert(self, learning_id: str, data: Dict[str, Any]):
        """Insert model data"""
        # Serialize model data
        model_data = {
            "predictions": data.get("predictions"),
            "optimization": data.get("optimization"),
            "timestamp": data["timestamp"]
        }
        
        # Save to file
        file_path = self.models_dir / f"{learning_id}.pkl"
        
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(pickle.dumps(model_data))
        
        # Store metadata
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO model_data 
                (learning_id, model_type, file_path, size_bytes, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                learning_id,
                "learning_model",
                str(file_path),
                file_path.stat().st_size,
                data["timestamp"]
            ))
            await db.commit()
    
    async def get(self, learning_id: str) -> Optional[Dict[str, Any]]:
        """Get model data by learning ID"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT file_path FROM model_data WHERE learning_id = ?
            """, (learning_id,)) as cursor:
                row = await cursor.fetchone()
        
        if not row:
            return None
        
        file_path = Path(row[0])
        
        try:
            async with aiofiles.open(file_path, 'rb') as f:
                data = await f.read()
            return pickle.loads(data)
        except FileNotFoundError:
            return None
    
    async def checkpoint(self, model_state: Dict[str, Any]) -> str:
        """Create a model checkpoint"""
        checkpoint_id = hashlib.sha256(
            json.dumps(model_state, sort_keys=True).encode()
        ).hexdigest()
        
        file_path = self.models_dir / f"checkpoint_{checkpoint_id}.pkl"
        
        async with aiofiles.open(file_path, 'wb') as f:
            await f.write(pickle.dumps(model_state))
        
        # Store metadata
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO model_data 
                (learning_id, model_type, file_path, size_bytes, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (
                checkpoint_id,
                "checkpoint",
                str(file_path),
                file_path.stat().st_size,
                datetime.utcnow()
            ))
            await db.commit()
        
        return checkpoint_id
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get model store statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            # Total models
            async with db.execute("SELECT COUNT(*) FROM model_data") as cursor:
                total_models = (await cursor.fetchone())[0]
            
            # Total size
            async with db.execute("SELECT SUM(size_bytes) FROM model_data") as cursor:
                total_size = (await cursor.fetchone())[0] or 0
            
            # Compressed models
            async with db.execute("SELECT COUNT(*) FROM model_data WHERE compressed = TRUE") as cursor:
                compressed_models = (await cursor.fetchone())[0]
        
        return {
            "total_models": total_models,
            "total_size_bytes": total_size,
            "compressed_models": compressed_models
        }
    
    async def cleanup(self, cutoff_date: datetime):
        """Clean up old model data"""
        async with aiosqlite.connect(self.db_path) as db:
            # Get file paths of old models
            async with db.execute("""
                SELECT file_path FROM model_data WHERE timestamp < ?
            """, (cutoff_date,)) as cursor:
                file_paths = [row[0] for row in await cursor.fetchall()]
            
            # Delete files
            for file_path in file_paths:
                try:
                    Path(file_path).unlink(missing_ok=True)
                except:
                    pass
            
            # Delete metadata
            await db.execute("DELETE FROM model_data WHERE timestamp < ?", (cutoff_date,))
            await db.commit()
    
    async def compress_old_data(self):
        """Compress old model files"""
        cutoff_date = datetime.utcnow() - timedelta(days=7)
        
        async with aiosqlite.connect(self.db_path) as db:
            # Get old uncompressed models
            async with db.execute("""
                SELECT learning_id, file_path FROM model_data 
                WHERE compressed = FALSE AND timestamp < ?
            """, (cutoff_date,)) as cursor:
                rows = await cursor.fetchall()
            
            for learning_id, file_path in rows:
                try:
                    # Read and compress
                    async with aiofiles.open(file_path, 'rb') as f:
                        data = await f.read()
                    
                    compressed_data = lz4.frame.compress(data)
                    compressed_path = f"{file_path}.lz4"
                    
                    async with aiofiles.open(compressed_path, 'wb') as f:
                        await f.write(compressed_data)
                    
                    # Update metadata
                    await db.execute("""
                        UPDATE model_data 
                        SET file_path = ?, compressed = TRUE, size_bytes = ?
                        WHERE learning_id = ?
                    """, (compressed_path, len(compressed_data), learning_id))
                    
                    # Remove original
                    Path(file_path).unlink(missing_ok=True)
                    
                except Exception as e:
                    print(f"Failed to compress {file_path}: {e}")
            
            await db.commit()


class MetadataStore:
    """Store for learning metadata and indexing"""
    
    def __init__(self, config: StorageConfig):
        self.config = config
        self.db_path = f"{config.base_path}/metadata.db"
        
    async def initialize(self):
        """Initialize metadata store"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                CREATE TABLE IF NOT EXISTS learning_metadata (
                    learning_id TEXT PRIMARY KEY,
                    type TEXT,
                    timestamp DATETIME,
                    cross_instance_relevance REAL,
                    has_temporal_data BOOLEAN,
                    has_graph_data BOOLEAN,
                    has_vector_data BOOLEAN,
                    has_model_data BOOLEAN,
                    metadata TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Indexes for efficient querying
            await db.execute("CREATE INDEX IF NOT EXISTS idx_type ON learning_metadata(type)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON learning_metadata(timestamp)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_relevance ON learning_metadata(cross_instance_relevance)")
            
            await db.commit()
    
    async def insert(self, learning_id: str, metadata: Dict[str, Any]):
        """Insert metadata"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("""
                INSERT OR REPLACE INTO learning_metadata 
                (learning_id, type, timestamp, cross_instance_relevance, 
                 has_temporal_data, has_graph_data, has_vector_data, has_model_data, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                learning_id,
                metadata["type"],
                metadata["timestamp"],
                metadata["cross_instance_relevance"],
                metadata["has_temporal_data"],
                metadata["has_graph_data"],
                metadata["has_vector_data"],
                metadata["has_model_data"],
                json.dumps(metadata.get("metadata", {}))
            ))
            await db.commit()
    
    async def get(self, learning_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata by learning ID"""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("""
                SELECT * FROM learning_metadata WHERE learning_id = ?
            """, (learning_id,)) as cursor:
                row = await cursor.fetchone()
        
        if not row:
            return None
        
        columns = [desc[0] for desc in cursor.description]
        metadata = dict(zip(columns, row))
        metadata["metadata"] = json.loads(metadata["metadata"])
        
        return metadata
    
    async def query(self, query_params: Dict[str, Any]) -> List[str]:
        """Query metadata with filters"""
        where_clauses = []
        params = []
        
        if "type" in query_params:
            where_clauses.append("type = ?")
            params.append(query_params["type"])
        
        if "min_relevance" in query_params:
            where_clauses.append("cross_instance_relevance >= ?")
            params.append(query_params["min_relevance"])
        
        if "start_time" in query_params:
            where_clauses.append("timestamp >= ?")
            params.append(query_params["start_time"])
        
        if "end_time" in query_params:
            where_clauses.append("timestamp <= ?")
            params.append(query_params["end_time"])
        
        # Build query
        base_query = "SELECT learning_id FROM learning_metadata"
        
        if where_clauses:
            base_query += " WHERE " + " AND ".join(where_clauses)
        
        # Add ordering
        order_by = query_params.get("order_by", "timestamp")
        order = query_params.get("order", "desc")
        base_query += f" ORDER BY {order_by} {order}"
        
        # Add limit
        if "limit" in query_params:
            base_query += " LIMIT ?"
            params.append(query_params["limit"])
        
        # Execute query
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(base_query, params) as cursor:
                return [row[0] for row in await cursor.fetchall()]
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get metadata statistics"""
        async with aiosqlite.connect(self.db_path) as db:
            # Total learnings
            async with db.execute("SELECT COUNT(*) FROM learning_metadata") as cursor:
                total_learnings = (await cursor.fetchone())[0]
            
            # By type
            type_counts = {}
            async with db.execute("SELECT type, COUNT(*) FROM learning_metadata GROUP BY type") as cursor:
                async for row in cursor:
                    type_counts[row[0]] = row[1]
            
            # Average relevance
            async with db.execute("SELECT AVG(cross_instance_relevance) FROM learning_metadata") as cursor:
                avg_relevance = (await cursor.fetchone())[0] or 0
        
        return {
            "total_learnings": total_learnings,
            "type_distribution": type_counts,
            "avg_cross_instance_relevance": avg_relevance
        }
    
    async def cleanup(self, cutoff_date: datetime):
        """Clean up old metadata"""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM learning_metadata WHERE timestamp < ?", (cutoff_date,))
            await db.commit()


class LearningCache:
    """In-memory cache for frequently accessed learnings"""
    
    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self.cache = {}
        self.access_times = {}
        self.access_counts = {}
        
    async def store(self, learning_id: str, learning: Learning):
        """Store learning in cache"""
        # LRU eviction if cache is full
        if len(self.cache) >= self.max_size:
            await self._evict_lru()
        
        self.cache[learning_id] = learning
        self.access_times[learning_id] = datetime.utcnow()
        self.access_counts[learning_id] = 1
    
    async def get(self, learning_id: str) -> Optional[Learning]:
        """Get learning from cache"""
        if learning_id in self.cache:
            # Update access tracking
            self.access_times[learning_id] = datetime.utcnow()
            self.access_counts[learning_id] += 1
            
            return self.cache[learning_id]
        
        return None
    
    async def cleanup(self):
        """Clean up old cache entries"""
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        
        to_remove = []
        for learning_id, access_time in self.access_times.items():
            if access_time < cutoff_time:
                to_remove.append(learning_id)
        
        for learning_id in to_remove:
            self._remove_entry(learning_id)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "utilization": len(self.cache) / self.max_size,
            "total_accesses": sum(self.access_counts.values())
        }
    
    async def _evict_lru(self):
        """Evict least recently used entry"""
        if not self.access_times:
            return
        
        lru_id = min(self.access_times.items(), key=lambda x: x[1])[0]
        self._remove_entry(lru_id)
    
    def _remove_entry(self, learning_id: str):
        """Remove entry from all tracking structures"""
        self.cache.pop(learning_id, None)
        self.access_times.pop(learning_id, None)
        self.access_counts.pop(learning_id, None)
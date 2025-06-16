"""
Pattern recognition and sequence analysis for MCP commands
"""

import asyncio
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
from scipy.stats import entropy
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class Pattern:
    """Represents a discovered pattern"""
    pattern_id: str
    pattern_type: str  # sequence, temporal, spatial, behavioral
    confidence: float
    support: int  # Number of occurrences
    elements: List[Any]
    metadata: Dict[str, Any] = field(default_factory=dict)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class CommandSequence:
    """Represents a sequence of commands"""
    commands: List[Dict[str, Any]]
    timestamp: datetime
    session_id: str
    user_id: Optional[str] = None
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    
    def get_pattern_hash(self) -> str:
        """Get hash representation of command sequence"""
        pattern = []
        for cmd in self.commands:
            pattern.append(f"{cmd.get('type', 'unknown')}:{cmd.get('action', 'unknown')}")
        return "->".join(pattern)
        
    def get_temporal_features(self) -> np.ndarray:
        """Extract temporal features from sequence"""
        if len(self.commands) < 2:
            return np.array([0])
            
        # Time differences between commands
        time_diffs = []
        for i in range(1, len(self.commands)):
            if "timestamp" in self.commands[i] and "timestamp" in self.commands[i-1]:
                diff = (self.commands[i]["timestamp"] - self.commands[i-1]["timestamp"]).total_seconds()
                time_diffs.append(diff)
                
        if not time_diffs:
            return np.array([0])
            
        # Statistical features
        features = [
            np.mean(time_diffs),
            np.std(time_diffs),
            np.min(time_diffs),
            np.max(time_diffs),
            np.median(time_diffs),
        ]
        
        return np.array(features)


class SequenceMiner:
    """Mine frequent sequences from command history"""
    
    def __init__(self, min_support: int = 5, max_gap: int = 3):
        self.min_support = min_support
        self.max_gap = max_gap
        self.sequences: List[CommandSequence] = []
        self.frequent_patterns: Dict[str, Pattern] = {}
        
    def add_sequence(self, sequence: CommandSequence):
        """Add sequence for mining"""
        self.sequences.append(sequence)
        
    def mine_patterns(self) -> List[Pattern]:
        """Mine frequent patterns using PrefixSpan algorithm"""
        # Build sequence database
        sequence_db = []
        for seq in self.sequences:
            items = []
            for cmd in seq.commands:
                item = f"{cmd.get('type', 'unknown')}:{cmd.get('action', 'unknown')}"
                items.append(item)
            sequence_db.append(items)
            
        # Find frequent subsequences
        patterns = self._prefix_span(sequence_db)
        
        # Convert to Pattern objects
        result = []
        for pattern, support in patterns:
            if support >= self.min_support:
                pattern_obj = Pattern(
                    pattern_id=f"seq_{hash(tuple(pattern))}",
                    pattern_type="sequence",
                    confidence=support / len(self.sequences),
                    support=support,
                    elements=pattern
                )
                result.append(pattern_obj)
                self.frequent_patterns[pattern_obj.pattern_id] = pattern_obj
                
        return result
        
    def _prefix_span(self, sequences: List[List[str]]) -> List[Tuple[List[str], int]]:
        """Simplified PrefixSpan implementation"""
        patterns = []
        
        # Count single items
        item_counts = Counter()
        for seq in sequences:
            for item in set(seq):
                item_counts[item] += 1
                
        # Start with frequent single items
        frequent_items = [(item, count) for item, count in item_counts.items() if count >= self.min_support]
        patterns.extend(([item], count) for item, count in frequent_items)
        
        # Recursively find longer patterns
        for item, _ in frequent_items:
            projected_db = self._project_database(sequences, [item])
            if projected_db:
                sub_patterns = self._prefix_span_recursive([item], projected_db)
                patterns.extend(sub_patterns)
                
        return patterns
        
    def _prefix_span_recursive(self, prefix: List[str], projected_db: List[List[str]]) -> List[Tuple[List[str], int]]:
        """Recursive PrefixSpan mining"""
        patterns = []
        
        # Count items in projected database
        item_counts = Counter()
        for seq in projected_db:
            for item in set(seq):
                item_counts[item] += 1
                
        # Find frequent items
        for item, count in item_counts.items():
            if count >= self.min_support:
                new_prefix = prefix + [item]
                patterns.append((new_prefix, count))
                
                # Project database for new prefix
                new_projected_db = self._project_database(projected_db, [item])
                if new_projected_db:
                    sub_patterns = self._prefix_span_recursive(new_prefix, new_projected_db)
                    patterns.extend(sub_patterns)
                    
        return patterns
        
    def _project_database(self, sequences: List[List[str]], pattern: List[str]) -> List[List[str]]:
        """Project database by pattern"""
        projected = []
        
        for seq in sequences:
            # Find pattern in sequence
            for i in range(len(seq) - len(pattern) + 1):
                if seq[i:i+len(pattern)] == pattern:
                    # Add suffix
                    suffix = seq[i+len(pattern):]
                    if suffix:
                        projected.append(suffix)
                    break
                    
        return projected


class TemporalPatternAnalyzer:
    """Analyze temporal patterns in command execution"""
    
    def __init__(self, time_window: timedelta = timedelta(hours=1)):
        self.time_window = time_window
        self.temporal_patterns: Dict[str, Pattern] = {}
        self.time_series_data: Dict[str, List[Tuple[datetime, float]]] = defaultdict(list)
        
    def add_event(self, command_type: str, timestamp: datetime, value: float = 1.0):
        """Add temporal event"""
        self.time_series_data[command_type].append((timestamp, value))
        
    def analyze_periodicity(self) -> List[Pattern]:
        """Detect periodic patterns in command execution"""
        patterns = []
        
        for cmd_type, time_series in self.time_series_data.items():
            if len(time_series) < 10:
                continue
                
            # Extract time differences
            times = [t[0] for t in time_series]
            values = [t[1] for t in time_series]
            
            # Detect periodicity using FFT
            if len(times) > 20:
                periods = self._detect_periods(times, values)
                
                for period, strength in periods:
                    pattern = Pattern(
                        pattern_id=f"temporal_{cmd_type}_{period}",
                        pattern_type="temporal",
                        confidence=strength,
                        support=len(times),
                        elements=[cmd_type],
                        metadata={
                            "period_seconds": period,
                            "period_human": self._format_period(period)
                        }
                    )
                    patterns.append(pattern)
                    self.temporal_patterns[pattern.pattern_id] = pattern
                    
        return patterns
        
    def _detect_periods(self, times: List[datetime], values: List[float]) -> List[Tuple[float, float]]:
        """Detect periods using Fourier analysis"""
        # Convert to uniform time series
        start_time = min(times)
        time_diffs = [(t - start_time).total_seconds() for t in times]
        
        # Interpolate to uniform sampling
        sampling_rate = 60  # 1 minute sampling
        max_time = max(time_diffs)
        uniform_times = np.arange(0, max_time, sampling_rate)
        uniform_values = np.interp(uniform_times, time_diffs, values)
        
        # Apply FFT
        fft_values = np.fft.fft(uniform_values)
        frequencies = np.fft.fftfreq(len(uniform_values), sampling_rate)
        
        # Find dominant frequencies
        magnitudes = np.abs(fft_values)
        threshold = np.mean(magnitudes) + 2 * np.std(magnitudes)
        
        periods = []
        for i, (freq, mag) in enumerate(zip(frequencies, magnitudes)):
            if freq > 0 and mag > threshold:
                period = 1 / freq
                strength = mag / np.sum(magnitudes)
                periods.append((period, strength))
                
        return sorted(periods, key=lambda x: x[1], reverse=True)[:5]
        
    def _format_period(self, seconds: float) -> str:
        """Format period in human-readable form"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        else:
            return f"{seconds/86400:.1f} days"
            
    def detect_anomalous_timing(self, command_type: str, timestamp: datetime) -> Tuple[bool, float]:
        """Detect if timing is anomalous for command type"""
        if command_type not in self.time_series_data:
            return False, 0.0
            
        time_series = self.time_series_data[command_type]
        if len(time_series) < 5:
            return False, 0.0
            
        # Calculate expected timing
        recent_times = [t[0] for t in time_series[-20:]]
        time_diffs = []
        
        for i in range(1, len(recent_times)):
            diff = (recent_times[i] - recent_times[i-1]).total_seconds()
            time_diffs.append(diff)
            
        if not time_diffs:
            return False, 0.0
            
        mean_diff = np.mean(time_diffs)
        std_diff = np.std(time_diffs)
        
        # Check if current timing is anomalous
        last_time = time_series[-1][0]
        current_diff = (timestamp - last_time).total_seconds()
        
        if std_diff > 0:
            z_score = abs(current_diff - mean_diff) / std_diff
            is_anomaly = z_score > 3
            anomaly_score = 1 - np.exp(-z_score / 3)
        else:
            is_anomaly = abs(current_diff - mean_diff) > mean_diff * 2
            anomaly_score = 1.0 if is_anomaly else 0.0
            
        return is_anomaly, anomaly_score


class BehavioralPatternDetector:
    """Detect behavioral patterns in command usage"""
    
    def __init__(self, n_clusters: int = 10):
        self.n_clusters = n_clusters
        self.behavioral_patterns: Dict[str, Pattern] = {}
        self.user_profiles: Dict[str, np.ndarray] = {}
        self.clustering_model = None
        
    def extract_behavioral_features(self, sequences: List[CommandSequence]) -> np.ndarray:
        """Extract behavioral features from command sequences"""
        features_list = []
        
        for seq in sequences:
            features = []
            
            # Command diversity
            cmd_types = [cmd.get("type", "unknown") for cmd in seq.commands]
            unique_cmds = len(set(cmd_types))
            total_cmds = len(cmd_types)
            diversity = unique_cmds / max(1, total_cmds)
            features.append(diversity)
            
            # Command frequency distribution entropy
            cmd_counts = Counter(cmd_types)
            probs = np.array(list(cmd_counts.values())) / total_cmds
            cmd_entropy = entropy(probs) if len(probs) > 1 else 0
            features.append(cmd_entropy)
            
            # Average time between commands
            temporal_features = seq.get_temporal_features()
            if len(temporal_features) > 0:
                features.append(temporal_features[0])  # Mean time diff
            else:
                features.append(0)
                
            # Performance metrics
            features.append(seq.performance_metrics.get("success_rate", 0))
            features.append(seq.performance_metrics.get("avg_execution_time", 0))
            
            # Session characteristics
            features.append(len(seq.commands))
            features.append((seq.commands[-1]["timestamp"] - seq.commands[0]["timestamp"]).total_seconds() if len(seq.commands) > 1 and "timestamp" in seq.commands[0] else 0)
            
            features_list.append(features)
            
        return np.array(features_list)
        
    def detect_user_patterns(self, sequences: List[CommandSequence]) -> List[Pattern]:
        """Detect patterns in user behavior"""
        if len(sequences) < self.n_clusters:
            return []
            
        # Extract features
        features = self.extract_behavioral_features(sequences)
        
        # Normalize features
        features_normalized = (features - np.mean(features, axis=0)) / (np.std(features, axis=0) + 1e-8)
        
        # Cluster behaviors
        self.clustering_model = KMeans(n_clusters=min(self.n_clusters, len(sequences) // 2))
        clusters = self.clustering_model.fit_predict(features_normalized)
        
        # Evaluate clustering quality
        if len(set(clusters)) > 1:
            silhouette = silhouette_score(features_normalized, clusters)
        else:
            silhouette = 0
            
        # Create patterns for each cluster
        patterns = []
        for cluster_id in range(self.n_clusters):
            cluster_indices = np.where(clusters == cluster_id)[0]
            if len(cluster_indices) < 2:
                continue
                
            cluster_sequences = [sequences[i] for i in cluster_indices]
            
            # Characterize cluster
            cluster_features = features[cluster_indices].mean(axis=0)
            
            pattern = Pattern(
                pattern_id=f"behavioral_cluster_{cluster_id}",
                pattern_type="behavioral",
                confidence=silhouette,
                support=len(cluster_indices),
                elements=[seq.session_id for seq in cluster_sequences],
                metadata={
                    "avg_diversity": float(cluster_features[0]),
                    "avg_entropy": float(cluster_features[1]),
                    "avg_time_between_cmds": float(cluster_features[2]),
                    "avg_success_rate": float(cluster_features[3]),
                    "avg_execution_time": float(cluster_features[4]),
                    "avg_session_length": float(cluster_features[5]),
                    "avg_session_duration": float(cluster_features[6]),
                }
            )
            patterns.append(pattern)
            self.behavioral_patterns[pattern.pattern_id] = pattern
            
        return patterns
        
    def classify_behavior(self, sequence: CommandSequence) -> Optional[str]:
        """Classify sequence into behavioral pattern"""
        if self.clustering_model is None:
            return None
            
        features = self.extract_behavioral_features([sequence])
        features_normalized = (features - np.mean(features, axis=0)) / (np.std(features, axis=0) + 1e-8)
        
        cluster = self.clustering_model.predict(features_normalized)[0]
        return f"behavioral_cluster_{cluster}"


class PatternMatcher:
    """Match new sequences against known patterns"""
    
    def __init__(self, similarity_threshold: float = 0.8):
        self.similarity_threshold = similarity_threshold
        self.pattern_index: Dict[str, Pattern] = {}
        
    def add_pattern(self, pattern: Pattern):
        """Add pattern to index"""
        self.pattern_index[pattern.pattern_id] = pattern
        
    def match_sequence(self, sequence: CommandSequence) -> List[Tuple[Pattern, float]]:
        """Match sequence against known patterns"""
        matches = []
        
        seq_hash = sequence.get_pattern_hash()
        seq_elements = seq_hash.split("->")
        
        for pattern in self.pattern_index.values():
            if pattern.pattern_type == "sequence":
                similarity = self._calculate_sequence_similarity(seq_elements, pattern.elements)
                if similarity >= self.similarity_threshold:
                    matches.append((pattern, similarity))
                    
        return sorted(matches, key=lambda x: x[1], reverse=True)
        
    def _calculate_sequence_similarity(self, seq1: List[str], seq2: List[str]) -> float:
        """Calculate similarity between two sequences using LCS"""
        if not seq1 or not seq2:
            return 0.0
            
        # Longest Common Subsequence
        m, n = len(seq1), len(seq2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if seq1[i-1] == seq2[j-1]:
                    dp[i][j] = dp[i-1][j-1] + 1
                else:
                    dp[i][j] = max(dp[i-1][j], dp[i][j-1])
                    
        lcs_length = dp[m][n]
        return 2 * lcs_length / (m + n)
        
    def suggest_next_commands(self, partial_sequence: List[str], patterns: List[Pattern]) -> List[Tuple[str, float]]:
        """Suggest next commands based on pattern matching"""
        suggestions = Counter()
        
        for pattern in patterns:
            if pattern.pattern_type != "sequence":
                continue
                
            # Find partial sequence in pattern
            pattern_elements = pattern.elements
            for i in range(len(pattern_elements) - len(partial_sequence)):
                if pattern_elements[i:i+len(partial_sequence)] == partial_sequence:
                    # Found match - suggest next element
                    if i + len(partial_sequence) < len(pattern_elements):
                        next_cmd = pattern_elements[i + len(partial_sequence)]
                        suggestions[next_cmd] += pattern.confidence * pattern.support
                        
        # Normalize scores
        total = sum(suggestions.values())
        if total > 0:
            return [(cmd, score/total) for cmd, score in suggestions.most_common()]
        return []


class PatternRecognizer:
    """Main pattern recognition system"""
    
    def __init__(self):
        self.sequence_miner = SequenceMiner()
        self.temporal_analyzer = TemporalPatternAnalyzer()
        self.behavioral_detector = BehavioralPatternDetector()
        self.pattern_matcher = PatternMatcher()
        self.all_patterns: Dict[str, Pattern] = {}
        self.pattern_stats = {
            "total_patterns": 0,
            "sequence_patterns": 0,
            "temporal_patterns": 0,
            "behavioral_patterns": 0,
        }
        
    def observe(self, command: Dict[str, Any], context: Optional[Dict[str, Any]] = None):
        """Observe command for pattern learning"""
        # Add to temporal analyzer
        self.temporal_analyzer.add_event(
            command.get("type", "unknown"),
            command.get("timestamp", datetime.now()),
            1.0
        )
        
        # Create sequence if we have context
        if context and "session_id" in context:
            if "current_sequence" not in context:
                context["current_sequence"] = CommandSequence(
                    commands=[],
                    timestamp=datetime.now(),
                    session_id=context["session_id"],
                    user_id=context.get("user_id")
                )
            context["current_sequence"].commands.append(command)
            
    def analyze_patterns(self) -> Dict[str, Any]:
        """Perform comprehensive pattern analysis"""
        results = {
            "sequence_patterns": [],
            "temporal_patterns": [],
            "behavioral_patterns": [],
            "summary": {}
        }
        
        # Mine sequence patterns
        seq_patterns = self.sequence_miner.mine_patterns()
        results["sequence_patterns"] = [self._pattern_to_dict(p) for p in seq_patterns]
        self.pattern_stats["sequence_patterns"] = len(seq_patterns)
        
        # Analyze temporal patterns
        temp_patterns = self.temporal_analyzer.analyze_periodicity()
        results["temporal_patterns"] = [self._pattern_to_dict(p) for p in temp_patterns]
        self.pattern_stats["temporal_patterns"] = len(temp_patterns)
        
        # Detect behavioral patterns
        if self.sequence_miner.sequences:
            behav_patterns = self.behavioral_detector.detect_user_patterns(self.sequence_miner.sequences)
            results["behavioral_patterns"] = [self._pattern_to_dict(p) for p in behav_patterns]
            self.pattern_stats["behavioral_patterns"] = len(behav_patterns)
            
        # Update pattern index
        all_patterns = seq_patterns + temp_patterns + behav_patterns
        for pattern in all_patterns:
            self.all_patterns[pattern.pattern_id] = pattern
            self.pattern_matcher.add_pattern(pattern)
            
        self.pattern_stats["total_patterns"] = len(self.all_patterns)
        
        # Generate summary
        results["summary"] = {
            **self.pattern_stats,
            "most_frequent_sequences": self._get_top_patterns(seq_patterns, 5),
            "strongest_periodicities": self._get_top_patterns(temp_patterns, 3),
            "behavioral_clusters": len(behav_patterns),
        }
        
        return results
        
    def _pattern_to_dict(self, pattern: Pattern) -> Dict[str, Any]:
        """Convert pattern to dictionary"""
        return {
            "pattern_id": pattern.pattern_id,
            "pattern_type": pattern.pattern_type,
            "confidence": pattern.confidence,
            "support": pattern.support,
            "elements": pattern.elements,
            "metadata": pattern.metadata,
            "first_seen": pattern.first_seen.isoformat(),
            "last_seen": pattern.last_seen.isoformat(),
        }
        
    def _get_top_patterns(self, patterns: List[Pattern], n: int) -> List[Dict[str, Any]]:
        """Get top N patterns by confidence and support"""
        sorted_patterns = sorted(patterns, key=lambda p: p.confidence * p.support, reverse=True)
        return [self._pattern_to_dict(p) for p in sorted_patterns[:n]]
        
    def predict_next(self, partial_sequence: CommandSequence) -> List[Dict[str, Any]]:
        """Predict next commands based on patterns"""
        # Match against known patterns
        matches = self.pattern_matcher.match_sequence(partial_sequence)
        
        # Get suggestions
        seq_elements = partial_sequence.get_pattern_hash().split("->")
        suggestions = self.pattern_matcher.suggest_next_commands(
            seq_elements,
            [m[0] for m in matches]
        )
        
        return [
            {
                "command": cmd,
                "confidence": conf,
                "based_on_patterns": len(matches)
            }
            for cmd, conf in suggestions[:10]
        ]


class SequenceLearner:
    """Learn and adapt from command sequences"""
    
    def __init__(self, learning_rate: float = 0.1):
        self.learning_rate = learning_rate
        self.sequence_memory = deque(maxlen=1000)
        self.transition_matrix: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.command_embeddings: Dict[str, np.ndarray] = {}
        
    def learn_sequence(self, sequence: CommandSequence):
        """Learn from command sequence"""
        self.sequence_memory.append(sequence)
        
        # Update transition matrix
        commands = [cmd.get("type", "unknown") for cmd in sequence.commands]
        for i in range(len(commands) - 1):
            current = commands[i]
            next_cmd = commands[i + 1]
            
            # Update transition probability
            self.transition_matrix[current][next_cmd] += self.learning_rate
            
            # Normalize
            total = sum(self.transition_matrix[current].values())
            for cmd in self.transition_matrix[current]:
                self.transition_matrix[current][cmd] /= total
                
    def get_transition_probability(self, from_cmd: str, to_cmd: str) -> float:
        """Get transition probability between commands"""
        if from_cmd in self.transition_matrix:
            return self.transition_matrix[from_cmd].get(to_cmd, 0.0)
        return 0.0
        
    def generate_embedding(self, command: str) -> np.ndarray:
        """Generate embedding for command based on usage patterns"""
        if command not in self.command_embeddings:
            # Initialize with random embedding
            self.command_embeddings[command] = np.random.randn(64)
            
        # Update embedding based on context
        context_vector = np.zeros(64)
        context_count = 0
        
        # Aggregate embeddings of commands that appear together
        for seq in list(self.sequence_memory)[-100:]:  # Last 100 sequences
            cmd_types = [cmd.get("type", "unknown") for cmd in seq.commands]
            if command in cmd_types:
                for other_cmd in cmd_types:
                    if other_cmd != command and other_cmd in self.command_embeddings:
                        context_vector += self.command_embeddings[other_cmd]
                        context_count += 1
                        
        if context_count > 0:
            context_vector /= context_count
            # Update embedding with context
            self.command_embeddings[command] = (
                (1 - self.learning_rate) * self.command_embeddings[command] +
                self.learning_rate * context_vector
            )
            
        return self.command_embeddings[command]
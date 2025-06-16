"""BASH_GOD Command Library - Template and Pattern Repository"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import re


class CommandCategory(Enum):
    FILE_OPERATIONS = "file_operations"
    PROCESS_MANAGEMENT = "process_management"
    SYSTEM_MONITORING = "system_monitoring"
    NETWORK_OPERATIONS = "network_operations"
    TEXT_PROCESSING = "text_processing"
    ARCHIVE_COMPRESSION = "archive_compression"
    CONTAINER_MANAGEMENT = "container_management"
    VERSION_CONTROL = "version_control"
    DATABASE_OPERATIONS = "database_operations"
    LOG_ANALYSIS = "log_analysis"


class SafetyLevel(Enum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"
    DESTRUCTIVE = "destructive"


@dataclass
class CommandTemplate:
    """Represents a command template with metadata"""
    name: str
    category: CommandCategory
    template: str
    description: str
    parameters: List[str]
    safety_level: SafetyLevel
    prerequisites: List[str] = field(default_factory=list)
    alternatives: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)
    optimizations: List[str] = field(default_factory=list)
    performance_notes: str = ""
    

class BashCommandLibrary:
    """Comprehensive library of bash command templates"""
    
    def __init__(self):
        self.templates: Dict[str, CommandTemplate] = {}
        self.category_index: Dict[CommandCategory, List[str]] = {}
        self.keyword_index: Dict[str, List[str]] = {}
        
        self._initialize_library()
        self._build_indices()
    
    def _initialize_library(self):
        """Initialize command library with templates"""
        
        # FILE OPERATIONS
        self.templates["find_large_files"] = CommandTemplate(
            name="find_large_files",
            category=CommandCategory.FILE_OPERATIONS,
            template="find {path} -type f -size +{size}M -printf '%s %p\\n' 2>/dev/null | sort -nr | head -{count}",
            description="Find large files in directory hierarchy",
            parameters=["path", "size", "count"],
            safety_level=SafetyLevel.SAFE,
            alternatives=[
                "du -ah {path} | sort -rh | head -{count}",
                "fd -t f -S +{size}M . {path} | head -{count}"
            ],
            examples=[
                "find . -type f -size +100M -printf '%s %p\\n' 2>/dev/null | sort -nr | head -20",
                "find /var -type f -size +50M -printf '%s %p\\n' 2>/dev/null | sort -nr | head -10"
            ],
            optimizations=[
                "Use -printf for efficiency over -exec ls",
                "Redirect stderr to avoid permission errors",
                "Sort numerically for accurate size ordering"
            ],
            performance_notes="Efficient for large directory trees, uses minimal memory"
        )
        
        self.templates["find_old_files"] = CommandTemplate(
            name="find_old_files",
            category=CommandCategory.FILE_OPERATIONS,
            template="find {path} -type f -mtime +{days} -printf '%T@ %p\\n' | sort -n | head -{count}",
            description="Find files older than specified days",
            parameters=["path", "days", "count"],
            safety_level=SafetyLevel.SAFE,
            alternatives=[
                "find {path} -type f ! -newermt '{date}' -ls",
                "fd -t f --changed-before '{date}' . {path}"
            ],
            examples=[
                "find /tmp -type f -mtime +30 -printf '%T@ %p\\n' | sort -n | head -50"
            ]
        )
        
        self.templates["safe_delete"] = CommandTemplate(
            name="safe_delete",
            category=CommandCategory.FILE_OPERATIONS,
            template="find {path} -name '{pattern}' -type f -print0 | xargs -0 -p rm",
            description="Safely delete files with confirmation",
            parameters=["path", "pattern"],
            safety_level=SafetyLevel.CAUTION,
            prerequisites=["xargs supports -p flag"],
            alternatives=[
                "find {path} -name '{pattern}' -type f -exec rm -i {} \\;",
                "find {path} -name '{pattern}' -type f | while read f; do rm -i \"$f\"; done"
            ],
            optimizations=[
                "Use -print0 and xargs -0 for filenames with spaces",
                "Always use -p for confirmation on deletion"
            ]
        )
        
        self.templates["bulk_rename"] = CommandTemplate(
            name="bulk_rename",
            category=CommandCategory.FILE_OPERATIONS,
            template="find {path} -name '{pattern}' -type f -print0 | xargs -0 -I {} sh -c 'mv \"$1\" \"${{1%/*}}/{new_pattern}\"' _ {}",
            description="Bulk rename files matching pattern",
            parameters=["path", "pattern", "new_pattern"],
            safety_level=SafetyLevel.CAUTION,
            alternatives=[
                "rename 's/{old}/{new}/g' {path}/*",
                "for f in {path}/{pattern}; do mv \"$f\" \"${f/{old}/{new}}\"; done"
            ]
        )
        
        # PROCESS MANAGEMENT
        self.templates["find_process_by_port"] = CommandTemplate(
            name="find_process_by_port",
            category=CommandCategory.PROCESS_MANAGEMENT,
            template="lsof -i :{port} -P -n | grep LISTEN || ss -tlnp | grep :{port}",
            description="Find process listening on specific port",
            parameters=["port"],
            safety_level=SafetyLevel.SAFE,
            alternatives=[
                "netstat -tlnp | grep :{port}",
                "fuser {port}/tcp 2>/dev/null"
            ],
            examples=[
                "lsof -i :8080 -P -n | grep LISTEN",
                "ss -tlnp | grep :3306"
            ]
        )
        
        self.templates["kill_by_pattern"] = CommandTemplate(
            name="kill_by_pattern",
            category=CommandCategory.PROCESS_MANAGEMENT,
            template="pgrep -f '{pattern}' | xargs -r kill -{signal}",
            description="Kill processes matching pattern",
            parameters=["pattern", "signal"],
            safety_level=SafetyLevel.DANGEROUS,
            alternatives=[
                "pkill -{signal} -f '{pattern}'",
                "killall -{signal} '{pattern}'"
            ],
            examples=[
                "pgrep -f 'node server.js' | xargs -r kill -TERM",
                "pkill -TERM -f 'python.*worker'"
            ],
            optimizations=[
                "Use pgrep + xargs for better control",
                "Always specify signal explicitly",
                "Use -r with xargs to handle empty input"
            ]
        )
        
        # SYSTEM MONITORING
        self.templates["cpu_top_processes"] = CommandTemplate(
            name="cpu_top_processes",
            category=CommandCategory.SYSTEM_MONITORING,
            template="ps aux --sort=-%cpu | head -{count} | awk '{printf \"%-10s %-8s %-8s %s\\n\", $1, $3, $4, $11}'",
            description="Show top CPU-consuming processes",
            parameters=["count"],
            safety_level=SafetyLevel.SAFE,
            alternatives=[
                "top -b -n 1 | grep -E '^[ ]*[0-9]+' | head -{count}",
                "htop -d 1 --sort-key PERCENT_CPU | head -{count}"
            ]
        )
        
        self.templates["memory_usage"] = CommandTemplate(
            name="memory_usage",
            category=CommandCategory.SYSTEM_MONITORING,
            template="ps aux --sort=-%mem | head -{count} | awk '{printf \"%-10s %-8s %-8s %s\\n\", $1, $3, $4, $11}'",
            description="Show top memory-consuming processes",
            parameters=["count"],
            safety_level=SafetyLevel.SAFE
        )
        
        self.templates["disk_usage_analysis"] = CommandTemplate(
            name="disk_usage_analysis",
            category=CommandCategory.SYSTEM_MONITORING,
            template="df -h | awk '$5+0 > {threshold} {print $0}' | sort -k5 -nr",
            description="Show disk usage above threshold",
            parameters=["threshold"],
            safety_level=SafetyLevel.SAFE,
            examples=[
                "df -h | awk '$5+0 > 80 {print $0}' | sort -k5 -nr"
            ]
        )
        
        # NETWORK OPERATIONS
        self.templates["network_connections"] = CommandTemplate(
            name="network_connections",
            category=CommandCategory.NETWORK_OPERATIONS,
            template="ss -tuln | awk 'NR>1 {print $1, $5}' | sort | uniq -c | sort -nr",
            description="Analyze network connections by type and port",
            parameters=[],
            safety_level=SafetyLevel.SAFE,
            alternatives=[
                "netstat -tuln | awk 'NR>2 {print $1, $4}' | sort | uniq -c",
                "lsof -i -P -n | awk '{print $8}' | sort | uniq -c"
            ]
        )
        
        self.templates["bandwidth_monitor"] = CommandTemplate(
            name="bandwidth_monitor",
            category=CommandCategory.NETWORK_OPERATIONS,
            template="iftop -t -s {duration} -L {limit} -o 2s",
            description="Monitor network bandwidth usage",
            parameters=["duration", "limit"],
            safety_level=SafetyLevel.SAFE,
            prerequisites=["iftop installed"],
            alternatives=[
                "nethogs -t -d {duration}",
                "nload -t {duration}"
            ]
        )
        
        # TEXT PROCESSING
        self.templates["log_error_analysis"] = CommandTemplate(
            name="log_error_analysis",
            category=CommandCategory.TEXT_PROCESSING,
            template="grep -E '(ERROR|FATAL|CRITICAL)' {logfile} | awk '{print $1, $2, $NF}' | sort | uniq -c | sort -nr",
            description="Analyze error patterns in log files",
            parameters=["logfile"],
            safety_level=SafetyLevel.SAFE,
            alternatives=[
                "rg -E '(ERROR|FATAL|CRITICAL)' {logfile} | awk '{print $1, $2, $NF}' | sort | uniq -c",
                "zgrep -E '(ERROR|FATAL|CRITICAL)' {logfile}* | awk '{print $1, $2, $NF}' | sort | uniq -c"
            ]
        )
        
        self.templates["text_frequency_analysis"] = CommandTemplate(
            name="text_frequency_analysis",
            category=CommandCategory.TEXT_PROCESSING,
            template="tr '[:space:]' '\\n' < {file} | grep -v '^$' | sort | uniq -c | sort -nr | head -{count}",
            description="Analyze word frequency in text file",
            parameters=["file", "count"],
            safety_level=SafetyLevel.SAFE
        )
        
        # CONTAINER MANAGEMENT
        self.templates["docker_cleanup"] = CommandTemplate(
            name="docker_cleanup",
            category=CommandCategory.CONTAINER_MANAGEMENT,
            template="docker system prune -a --volumes --filter 'until={hours}h' -f",
            description="Clean up Docker resources older than specified hours",
            parameters=["hours"],
            safety_level=SafetyLevel.DANGEROUS,
            prerequisites=["Docker installed and running"],
            alternatives=[
                "docker container prune -f && docker image prune -a -f && docker volume prune -f",
                "docker system df && docker system prune -a --volumes -f"
            ],
            examples=[
                "docker system prune -a --volumes --filter 'until=24h' -f"
            ]
        )
        
        self.templates["docker_resource_usage"] = CommandTemplate(
            name="docker_resource_usage",
            category=CommandCategory.CONTAINER_MANAGEMENT,
            template="docker stats --no-stream --format 'table {{.Container}}\\t{{.CPUPerc}}\\t{{.MemUsage}}\\t{{.NetIO}}\\t{{.BlockIO}}'",
            description="Show Docker container resource usage",
            parameters=[],
            safety_level=SafetyLevel.SAFE
        )
        
        # VERSION CONTROL
        self.templates["git_large_files"] = CommandTemplate(
            name="git_large_files",
            category=CommandCategory.VERSION_CONTROL,
            template="git rev-list --objects --all | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' | awk '/^blob/ {print substr($0,6)}' | sort -k2 -nr | head -{count}",
            description="Find largest files in Git history",
            parameters=["count"],
            safety_level=SafetyLevel.SAFE,
            prerequisites=["Inside Git repository"]
        )
        
        self.templates["git_cleanup"] = CommandTemplate(
            name="git_cleanup",
            category=CommandCategory.VERSION_CONTROL,
            template="git remote prune origin && git gc --aggressive --prune=now",
            description="Clean up Git repository",
            parameters=[],
            safety_level=SafetyLevel.CAUTION,
            prerequisites=["Inside Git repository with remote 'origin'"]
        )
        
        # LOG ANALYSIS
        self.templates["apache_error_analysis"] = CommandTemplate(
            name="apache_error_analysis",
            category=CommandCategory.LOG_ANALYSIS,
            template="awk '$9 >= 400 {print $1, $9, $7}' {logfile} | sort | uniq -c | sort -nr | head -{count}",
            description="Analyze Apache error logs for 4xx/5xx errors",
            parameters=["logfile", "count"],
            safety_level=SafetyLevel.SAFE
        )
        
        self.templates["syslog_analysis"] = CommandTemplate(
            name="syslog_analysis",
            category=CommandCategory.LOG_ANALYSIS,
            template="grep -E '(error|warning|critical|failed)' {logfile} | awk '{print $5}' | sort | uniq -c | sort -nr | head -{count}",
            description="Analyze system logs for errors and warnings",
            parameters=["logfile", "count"],
            safety_level=SafetyLevel.SAFE
        )
        
        # ARCHIVE AND COMPRESSION
        self.templates["smart_backup"] = CommandTemplate(
            name="smart_backup",
            category=CommandCategory.ARCHIVE_COMPRESSION,
            template="tar --exclude-vcs --exclude='*.tmp' --exclude='node_modules' -czf {output}.tar.gz {source}",
            description="Create smart backup excluding common unnecessary files",
            parameters=["output", "source"],
            safety_level=SafetyLevel.SAFE,
            alternatives=[
                "rsync -av --exclude-from=exclude.txt {source}/ {destination}/",
                "zip -r {output}.zip {source} -x '*.tmp' 'node_modules/*' '.git/*'"
            ]
        )
        
        self.templates["parallel_compression"] = CommandTemplate(
            name="parallel_compression",
            category=CommandCategory.ARCHIVE_COMPRESSION,
            template="tar -cf - {source} | pigz -p {cores} > {output}.tar.gz",
            description="Parallel compression using multiple cores",
            parameters=["source", "cores", "output"],
            safety_level=SafetyLevel.SAFE,
            prerequisites=["pigz installed"],
            alternatives=[
                "tar -cf - {source} | xz -T {cores} > {output}.tar.xz",
                "tar --use-compress-program='pigz -p {cores}' -cf {output}.tar.gz {source}"
            ]
        )
    
    def _build_indices(self):
        """Build category and keyword indices"""
        for name, template in self.templates.items():
            # Category index
            if template.category not in self.category_index:
                self.category_index[template.category] = []
            self.category_index[template.category].append(name)
            
            # Keyword index
            keywords = self._extract_keywords(template)
            for keyword in keywords:
                if keyword not in self.keyword_index:
                    self.keyword_index[keyword] = []
                self.keyword_index[keyword].append(name)
    
    def _extract_keywords(self, template: CommandTemplate) -> List[str]:
        """Extract keywords from template for indexing"""
        keywords = []
        
        # Extract from name
        keywords.extend(template.name.split('_'))
        
        # Extract from description
        desc_words = re.findall(r'\b\w+\b', template.description.lower())
        keywords.extend(desc_words)
        
        # Extract command names from template
        cmd_pattern = r'\b([a-z]+)\s+'
        commands = re.findall(cmd_pattern, template.template)
        keywords.extend(commands)
        
        return list(set(keywords))
    
    def find_templates(self, query: str, category: Optional[CommandCategory] = None) -> List[CommandTemplate]:
        """Find templates matching query"""
        query_lower = query.lower()
        matching_templates = []
        
        # Category filter
        if category:
            candidate_names = self.category_index.get(category, [])
        else:
            candidate_names = list(self.templates.keys())
        
        # Score templates
        scored_templates = []
        for name in candidate_names:
            template = self.templates[name]
            score = self._calculate_match_score(query_lower, template)
            if score > 0:
                scored_templates.append((score, template))
        
        # Sort by score and return templates
        scored_templates.sort(reverse=True)
        return [template for _, template in scored_templates]
    
    def _calculate_match_score(self, query: str, template: CommandTemplate) -> float:
        """Calculate match score for template"""
        score = 0.0
        
        # Exact name match
        if query in template.name.lower():
            score += 10.0
        
        # Description match
        if query in template.description.lower():
            score += 5.0
        
        # Keyword matches
        query_words = query.split()
        template_keywords = self._extract_keywords(template)
        
        for word in query_words:
            if word in template_keywords:
                score += 2.0
        
        # Category relevance
        category_keywords = {
            CommandCategory.FILE_OPERATIONS: ['file', 'directory', 'find', 'search'],
            CommandCategory.PROCESS_MANAGEMENT: ['process', 'kill', 'pid', 'service'],
            CommandCategory.SYSTEM_MONITORING: ['monitor', 'usage', 'performance', 'cpu', 'memory'],
            CommandCategory.NETWORK_OPERATIONS: ['network', 'port', 'connection', 'bandwidth'],
            CommandCategory.TEXT_PROCESSING: ['text', 'grep', 'awk', 'sed', 'log'],
            CommandCategory.CONTAINER_MANAGEMENT: ['docker', 'container', 'image'],
        }
        
        for word in query_words:
            if word in category_keywords.get(template.category, []):
                score += 1.0
        
        return score
    
    def get_template(self, name: str) -> Optional[CommandTemplate]:
        """Get specific template by name"""
        return self.templates.get(name)
    
    def get_templates_by_category(self, category: CommandCategory) -> List[CommandTemplate]:
        """Get all templates in category"""
        names = self.category_index.get(category, [])
        return [self.templates[name] for name in names]
    
    def get_safe_templates(self) -> List[CommandTemplate]:
        """Get only safe templates"""
        return [t for t in self.templates.values() if t.safety_level == SafetyLevel.SAFE]
    
    def get_dangerous_templates(self) -> List[CommandTemplate]:
        """Get dangerous/destructive templates"""
        return [t for t in self.templates.values() 
                if t.safety_level in [SafetyLevel.DANGEROUS, SafetyLevel.DESTRUCTIVE]]
    
    def generate_command(self, template_name: str, parameters: Dict[str, str]) -> Optional[str]:
        """Generate command from template with parameters"""
        template = self.get_template(template_name)
        if not template:
            return None
        
        command = template.template
        for param in template.parameters:
            value = parameters.get(param, f"{{{param}}}")
            command = command.replace(f"{{{param}}}", str(value))
        
        return command
    
    def validate_parameters(self, template_name: str, parameters: Dict[str, str]) -> Tuple[bool, List[str]]:
        """Validate parameters for template"""
        template = self.get_template(template_name)
        if not template:
            return False, ["Template not found"]
        
        errors = []
        for param in template.parameters:
            if param not in parameters:
                errors.append(f"Missing required parameter: {param}")
        
        return len(errors) == 0, errors
    
    def suggest_alternatives(self, template_name: str) -> List[str]:
        """Get alternative commands for template"""
        template = self.get_template(template_name)
        return template.alternatives if template else []
    
    def get_optimization_tips(self, template_name: str) -> List[str]:
        """Get optimization tips for template"""
        template = self.get_template(template_name)
        return template.optimizations if template else []
    
    def export_library(self) -> Dict[str, Any]:
        """Export entire library as JSON-serializable dict"""
        return {
            'templates': {
                name: {
                    'name': t.name,
                    'category': t.category.value,
                    'template': t.template,
                    'description': t.description,
                    'parameters': t.parameters,
                    'safety_level': t.safety_level.value,
                    'prerequisites': t.prerequisites,
                    'alternatives': t.alternatives,
                    'examples': t.examples,
                    'optimizations': t.optimizations,
                    'performance_notes': t.performance_notes,
                }
                for name, t in self.templates.items()
            },
            'categories': [cat.value for cat in CommandCategory],
            'safety_levels': [level.value for level in SafetyLevel],
        }
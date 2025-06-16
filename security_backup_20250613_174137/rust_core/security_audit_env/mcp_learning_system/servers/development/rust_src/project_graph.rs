use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use rayon::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectNode {
    pub path: PathBuf,
    pub node_type: NodeType,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub dependencies: HashSet<PathBuf>,
    pub dependents: HashSet<PathBuf>,
    pub metadata: NodeMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Module,
    Package,
    File,
    Function,
    Class,
    Interface,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetadata {
    pub size: usize,
    pub last_modified: u64,
    pub language: String,
    pub complexity: u32,
    pub test_coverage: Option<f32>,
}

pub struct ProjectGraph {
    nodes: DashMap<PathBuf, Arc<RwLock<ProjectNode>>>,
    edges: DashMap<(PathBuf, PathBuf), EdgeType>,
    root_path: PathBuf,
    index: Arc<RwLock<ProjectIndex>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    Import,
    Export,
    Inherit,
    Implement,
    Use,
    Test,
}

struct ProjectIndex {
    symbol_to_file: HashMap<String, HashSet<PathBuf>>,
    file_to_symbols: HashMap<PathBuf, HashSet<String>>,
    package_hierarchy: HashMap<String, HashSet<PathBuf>>,
}

impl ProjectGraph {
    pub fn new(root_path: PathBuf) -> Self {
        Self {
            nodes: DashMap::new(),
            edges: DashMap::new(),
            root_path,
            index: Arc::new(RwLock::new(ProjectIndex {
                symbol_to_file: HashMap::new(),
                file_to_symbols: HashMap::new(),
                package_hierarchy: HashMap::new(),
            })),
        }
    }

    pub async fn add_file(&self, path: PathBuf, content: &str, language: &str) {
        let node = self.analyze_file(&path, content, language).await;
        let node_arc = Arc::new(RwLock::new(node.clone()));
        
        self.nodes.insert(path.clone(), node_arc.clone());
        
        // Update dependencies
        for dep in &node.imports {
            if let Some(dep_path) = self.resolve_import(dep, &path).await {
                self.edges.insert((path.clone(), dep_path.clone()), EdgeType::Import);
                
                // Update dependent's dependents list
                if let Some(dep_node) = self.nodes.get(&dep_path) {
                    let mut dep_write = dep_node.write().await;
                    dep_write.dependents.insert(path.clone());
                }
            }
        }
        
        // Update index
        self.update_index(&path, &node).await;
    }

    async fn analyze_file(&self, path: &Path, content: &str, language: &str) -> ProjectNode {
        let imports = self.extract_imports(content, language);
        let exports = self.extract_exports(content, language);
        
        ProjectNode {
            path: path.to_path_buf(),
            node_type: NodeType::File,
            imports,
            exports,
            dependencies: HashSet::new(),
            dependents: HashSet::new(),
            metadata: NodeMetadata {
                size: content.len(),
                last_modified: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                language: language.to_string(),
                complexity: self.calculate_complexity(content),
                test_coverage: None,
            },
        }
    }

    fn extract_imports(&self, content: &str, language: &str) -> Vec<String> {
        match language {
            "python" => {
                content.lines()
                    .filter(|line| line.trim_start().starts_with("import ") || 
                                  line.trim_start().starts_with("from "))
                    .map(|line| line.to_string())
                    .collect()
            }
            "rust" => {
                content.lines()
                    .filter(|line| line.trim_start().starts_with("use "))
                    .map(|line| line.to_string())
                    .collect()
            }
            "javascript" | "typescript" => {
                content.lines()
                    .filter(|line| line.trim_start().starts_with("import ") || 
                                  line.trim_start().starts_with("const ") && line.contains("require"))
                    .map(|line| line.to_string())
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    fn extract_exports(&self, content: &str, language: &str) -> Vec<String> {
        match language {
            "python" => {
                content.lines()
                    .filter(|line| line.trim_start().starts_with("def ") || 
                                  line.trim_start().starts_with("class "))
                    .map(|line| line.to_string())
                    .collect()
            }
            "rust" => {
                content.lines()
                    .filter(|line| line.trim_start().starts_with("pub "))
                    .map(|line| line.to_string())
                    .collect()
            }
            "javascript" | "typescript" => {
                content.lines()
                    .filter(|line| line.trim_start().starts_with("export ") || 
                                  line.contains("module.exports"))
                    .map(|line| line.to_string())
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    fn calculate_complexity(&self, content: &str) -> u32 {
        // Simple cyclomatic complexity approximation
        let mut complexity = 1;
        
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.contains("if ") || trimmed.contains("while ") || 
               trimmed.contains("for ") || trimmed.contains("case ") ||
               trimmed.contains("catch ") || trimmed.contains("&&") || 
               trimmed.contains("||") {
                complexity += 1;
            }
        }
        
        complexity
    }

    async fn resolve_import(&self, import: &str, from_path: &Path) -> Option<PathBuf> {
        // Simple import resolution - in real implementation would be more sophisticated
        let parent = from_path.parent()?;
        
        // Extract module name from import statement
        let module = if import.starts_with("import ") {
            import.strip_prefix("import ")?.split_whitespace().next()?
        } else if import.starts_with("from ") {
            import.strip_prefix("from ")?.split_whitespace().next()?
        } else if import.starts_with("use ") {
            import.strip_prefix("use ")?.split("::").next()?
        } else {
            return None;
        };
        
        // Try common file extensions
        let extensions = ["", ".py", ".rs", ".js", ".ts", ".tsx"];
        for ext in &extensions {
            let path = parent.join(format!("{}{}", module, ext));
            if self.nodes.contains_key(&path) {
                return Some(path);
            }
        }
        
        None
    }

    async fn update_index(&self, path: &Path, node: &ProjectNode) {
        let mut index = self.index.write().await;
        
        // Update file to symbols mapping
        let symbols: HashSet<String> = node.exports.iter()
            .filter_map(|export| {
                // Extract symbol name from export
                if export.starts_with("def ") {
                    export.strip_prefix("def ")?.split('(').next()
                } else if export.starts_with("class ") {
                    export.strip_prefix("class ")?.split(':').next()?.trim().into()
                } else if export.starts_with("pub fn ") {
                    export.strip_prefix("pub fn ")?.split('(').next()
                } else {
                    None
                }
                .map(|s| s.to_string())
            })
            .collect();
        
        index.file_to_symbols.insert(path.to_path_buf(), symbols.clone());
        
        // Update symbol to file mapping
        for symbol in symbols {
            index.symbol_to_file
                .entry(symbol)
                .or_insert_with(HashSet::new)
                .insert(path.to_path_buf());
        }
    }

    pub async fn find_dependencies(&self, path: &Path) -> Vec<PathBuf> {
        self.edges.iter()
            .filter(|entry| entry.key().0 == path)
            .map(|entry| entry.key().1.clone())
            .collect()
    }

    pub async fn find_dependents(&self, path: &Path) -> Vec<PathBuf> {
        self.edges.iter()
            .filter(|entry| entry.key().1 == path)
            .map(|entry| entry.key().0.clone())
            .collect()
    }

    pub async fn find_symbol(&self, symbol: &str) -> Option<Vec<PathBuf>> {
        let index = self.index.read().await;
        index.symbol_to_file.get(symbol)
            .map(|paths| paths.iter().cloned().collect())
    }

    pub async fn get_file_symbols(&self, path: &Path) -> Option<Vec<String>> {
        let index = self.index.read().await;
        index.file_to_symbols.get(path)
            .map(|symbols| symbols.iter().cloned().collect())
    }

    pub async fn calculate_impact(&self, path: &Path) -> ImpactAnalysis {
        let mut impacted_files = HashSet::new();
        let mut to_visit = vec![path.to_path_buf()];
        let mut visited = HashSet::new();
        
        while let Some(current) = to_visit.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            
            let dependents = self.find_dependents(&current).await;
            for dependent in dependents {
                impacted_files.insert(dependent.clone());
                to_visit.push(dependent);
            }
        }
        
        ImpactAnalysis {
            directly_impacted: self.find_dependents(path).await.len(),
            transitively_impacted: impacted_files.len(),
            impacted_files: impacted_files.into_iter().collect(),
        }
    }

    pub async fn suggest_refactoring(&self, threshold: u32) -> Vec<RefactoringSuggestion> {
        let mut suggestions = Vec::new();
        
        for entry in self.nodes.iter() {
            let node = entry.value().read().await;
            
            // Suggest refactoring for high complexity
            if node.metadata.complexity > threshold {
                suggestions.push(RefactoringSuggestion {
                    file: node.path.clone(),
                    reason: RefactoringReason::HighComplexity(node.metadata.complexity),
                    priority: if node.metadata.complexity > threshold * 2 {
                        Priority::High
                    } else {
                        Priority::Medium
                    },
                });
            }
            
            // Suggest refactoring for too many dependencies
            if node.dependencies.len() > 10 {
                suggestions.push(RefactoringSuggestion {
                    file: node.path.clone(),
                    reason: RefactoringReason::TooManyDependencies(node.dependencies.len()),
                    priority: Priority::Medium,
                });
            }
        }
        
        suggestions.par_sort_by_key(|s| match s.priority {
            Priority::High => 0,
            Priority::Medium => 1,
            Priority::Low => 2,
        });
        
        suggestions
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAnalysis {
    pub directly_impacted: usize,
    pub transitively_impacted: usize,
    pub impacted_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefactoringSuggestion {
    pub file: PathBuf,
    pub reason: RefactoringReason,
    pub priority: Priority,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RefactoringReason {
    HighComplexity(u32),
    TooManyDependencies(usize),
    CircularDependency,
    LowTestCoverage(f32),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Priority {
    High,
    Medium,
    Low,
}
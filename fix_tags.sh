#\!/bin/bash
# Fix missing tags in server configs

sed -i '164s/priority: 8,/priority: 8,\n                tags: vec\!["devops".to_string(), "vcs".to_string()],/' rust_core/src/mcp_manager/config.rs
sed -i '192s/priority: 9,/priority: 9,\n                tags: vec\!["devops".to_string(), "github".to_string()],/' rust_core/src/mcp_manager/config.rs
sed -i '211s/priority: 7,/priority: 7,\n            tags: vec\!["infrastructure".to_string(), "monitoring".to_string()],/' rust_core/src/mcp_manager/config.rs
sed -i '242s/priority: 8,/priority: 8,\n                tags: vec\!["infrastructure".to_string(), "storage".to_string()],/' rust_core/src/mcp_manager/config.rs
sed -i '269s/priority: 6,/priority: 6,\n                tags: vec\!["search".to_string(), "knowledge".to_string()],/' rust_core/src/mcp_manager/config.rs
sed -i '296s/priority: 8,/priority: 8,\n                tags: vec\!["special".to_string(), "smithery".to_string()],/' rust_core/src/mcp_manager/config.rs
sed -i '316s/priority: 9,/priority: 9,\n                tags: vec\!["security".to_string(), "scanning".to_string()],/' rust_core/src/mcp_manager/config.rs
sed -i '332s/priority: 9,/priority: 9,\n                tags: vec\!["security".to_string(), "audit".to_string()],/' rust_core/src/mcp_manager/config.rs

echo "Tags added to all server configs"

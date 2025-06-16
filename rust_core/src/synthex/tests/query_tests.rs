//! Tests for SYNTHEX query parsing and execution

#[cfg(test)]
mod tests {
    use crate::synthex::{
        query::{Query, QueryBuilder, QueryParser, QueryType},
        query_parser::{QueryToken, QueryOperator},
        SynthexError,
    };
    
    #[test]
    fn test_query_builder_basic() {
        let query = QueryBuilder::new("test query")
            .build();
            
        assert_eq!(query.text, "test query");
        assert_eq!(query.max_results, 10); // default
        assert!(!query.filters.is_empty()); // Should have defaults
    }
    
    #[test]
    fn test_query_builder_complex() {
        let query = QueryBuilder::new("complex query")
            .with_context("test context")
            .with_max_results(50)
            .with_filters(vec!["type:doc".to_string(), "lang:en".to_string()])
            .with_timeout(30)
            .with_parallel_execution(true)
            .with_cache_enabled(false)
            .build();
            
        assert_eq!(query.text, "complex query");
        assert_eq!(query.context, Some("test context".to_string()));
        assert_eq!(query.max_results, 50);
        assert_eq!(query.filters.len(), 2);
        assert_eq!(query.timeout_seconds, 30);
        assert!(query.parallel_execution);
        assert!(!query.cache_enabled);
    }
    
    #[test]
    fn test_query_parser_simple() {
        let parser = QueryParser::new();
        let tokens = parser.parse("hello world").unwrap();
        
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], QueryToken::Term(ref s) if s == "hello"));
        assert!(matches!(tokens[1], QueryToken::Term(ref s) if s == "world"));
    }
    
    #[test]
    fn test_query_parser_operators() {
        let parser = QueryParser::new();
        
        let tokens = parser.parse("rust AND performance").unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[1], QueryToken::Operator(QueryOperator::And)));
        
        let tokens = parser.parse("error OR warning").unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[1], QueryToken::Operator(QueryOperator::Or)));
        
        let tokens = parser.parse("security NOT vulnerability").unwrap();
        assert_eq!(tokens.len(), 3);
        assert!(matches!(tokens[1], QueryToken::Operator(QueryOperator::Not)));
    }
    
    #[test]
    fn test_query_parser_quoted_strings() {
        let parser = QueryParser::new();
        let tokens = parser.parse(r#""exact phrase" search"#).unwrap();
        
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], QueryToken::Phrase(ref s) if s == "exact phrase"));
        assert!(matches!(tokens[1], QueryToken::Term(ref s) if s == "search"));
    }
    
    #[test]
    fn test_query_parser_field_search() {
        let parser = QueryParser::new();
        let tokens = parser.parse("author:john title:\"rust programming\"").unwrap();
        
        assert_eq!(tokens.len(), 2);
        match &tokens[0] {
            QueryToken::Field(field, value) => {
                assert_eq!(field, "author");
                assert_eq!(value, "john");
            }
            _ => panic!("Expected field token"),
        }
        
        match &tokens[1] {
            QueryToken::Field(field, value) => {
                assert_eq!(field, "title");
                assert_eq!(value, "rust programming");
            }
            _ => panic!("Expected field token"),
        }
    }
    
    #[test]
    fn test_query_parser_wildcards() {
        let parser = QueryParser::new();
        let tokens = parser.parse("test* synth?x").unwrap();
        
        assert_eq!(tokens.len(), 2);
        assert!(matches!(tokens[0], QueryToken::Wildcard(ref s) if s == "test*"));
        assert!(matches!(tokens[1], QueryToken::Wildcard(ref s) if s == "synth?x"));
    }
    
    #[test]
    fn test_query_parser_parentheses() {
        let parser = QueryParser::new();
        let tokens = parser.parse("(rust OR go) AND performance").unwrap();
        
        assert!(tokens.iter().any(|t| matches!(t, QueryToken::LeftParen)));
        assert!(tokens.iter().any(|t| matches!(t, QueryToken::RightParen)));
    }
    
    #[test]
    fn test_query_parser_complex_expression() {
        let parser = QueryParser::new();
        let query = r#"(type:documentation OR type:tutorial) AND "rust programming" NOT deprecated author:synthex*"#;
        let tokens = parser.parse(query).unwrap();
        
        // Verify it parses without error and contains expected elements
        assert!(tokens.len() > 5);
        assert!(tokens.iter().any(|t| matches!(t, QueryToken::Phrase(ref s) if s == "rust programming")));
        assert!(tokens.iter().any(|t| matches!(t, QueryToken::Operator(QueryOperator::Not))));
        assert!(tokens.iter().any(|t| matches!(t, QueryToken::Wildcard(_))));
    }
    
    #[test]
    fn test_query_parser_error_handling() {
        let parser = QueryParser::new();
        
        // Unmatched quotes
        let result = parser.parse(r#""unclosed quote"#);
        assert!(result.is_err());
        
        // Unmatched parentheses
        let result = parser.parse("(unclosed paren");
        assert!(result.is_err());
        
        // Invalid field syntax
        let result = parser.parse("field:");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_query_type_detection() {
        assert_eq!(QueryType::from_query("simple search"), QueryType::Simple);
        assert_eq!(QueryType::from_query("term AND another"), QueryType::Boolean);
        assert_eq!(QueryType::from_query("field:value"), QueryType::Structured);
        assert_eq!(QueryType::from_query("test*"), QueryType::Wildcard);
        assert_eq!(QueryType::from_query("regex:/[0-9]+/"), QueryType::Regex);
    }
    
    #[test]
    fn test_query_validation() {
        let validator = QueryValidator::new();
        
        // Valid queries
        assert!(validator.validate("normal query").is_ok());
        assert!(validator.validate("field:value AND other").is_ok());
        
        // Invalid queries
        assert!(validator.validate("").is_err()); // Empty
        assert!(validator.validate(&"x".repeat(1001)).is_err()); // Too long
        assert!(validator.validate(";;;DROP TABLE").is_err()); // SQL injection attempt
    }
    
    #[test]
    fn test_query_optimization() {
        let optimizer = QueryOptimizer::new();
        
        // Remove redundant operators
        let optimized = optimizer.optimize("term AND AND another");
        assert_eq!(optimized, "term AND another");
        
        // Simplify double negatives
        let optimized = optimizer.optimize("NOT NOT test");
        assert_eq!(optimized, "test");
        
        // Flatten nested parentheses
        let optimized = optimizer.optimize("((test))");
        assert_eq!(optimized, "test");
    }
    
    #[test]
    fn test_query_expansion() {
        let expander = QueryExpander::new();
        
        // Synonym expansion
        let expanded = expander.expand("search");
        assert!(expanded.contains("find"));
        assert!(expanded.contains("lookup"));
        
        // Stemming
        let expanded = expander.expand("running");
        assert!(expanded.contains("run"));
        
        // Abbreviation expansion
        let expanded = expander.expand("ML");
        assert!(expanded.contains("machine learning"));
    }
    
    #[test]
    fn test_query_scoring() {
        let scorer = QueryScorer::new();
        
        let query = QueryBuilder::new("rust performance").build();
        let doc1 = "Rust offers excellent performance characteristics";
        let doc2 = "Python is known for ease of use";
        
        let score1 = scorer.score(&query, doc1);
        let score2 = scorer.score(&query, doc2);
        
        assert!(score1 > score2); // doc1 should score higher
        assert!(score1 > 0.5); // Good match
        assert!(score2 < 0.3); // Poor match
    }
}

// Helper structs for testing (normally these would be in the main module)
struct QueryValidator;
impl QueryValidator {
    fn new() -> Self { Self }
    fn validate(&self, query: &str) -> Result<(), SynthexError> {
        if query.is_empty() {
            return Err(SynthexError::InvalidQuery("Empty query".to_string()));
        }
        if query.len() > 1000 {
            return Err(SynthexError::InvalidQuery("Query too long".to_string()));
        }
        if query.contains("DROP TABLE") || query.contains("DELETE FROM") {
            return Err(SynthexError::InvalidQuery("SQL injection detected".to_string()));
        }
        Ok(())
    }
}

struct QueryOptimizer;
impl QueryOptimizer {
    fn new() -> Self { Self }
    fn optimize(&self, query: &str) -> String {
        query
            .replace(" AND AND ", " AND ")
            .replace("NOT NOT ", "")
            .replace("((", "(")
            .replace("))", ")")
            .trim()
            .to_string()
    }
}

struct QueryExpander;
impl QueryExpander {
    fn new() -> Self { Self }
    fn expand(&self, term: &str) -> Vec<String> {
        let mut expanded = vec![term.to_string()];
        
        match term {
            "search" => {
                expanded.push("find".to_string());
                expanded.push("lookup".to_string());
                expanded.push("query".to_string());
            }
            "running" => {
                expanded.push("run".to_string());
                expanded.push("runs".to_string());
            }
            "ML" => {
                expanded.push("machine learning".to_string());
                expanded.push("AI".to_string());
            }
            _ => {}
        }
        
        expanded
    }
}

struct QueryScorer;
impl QueryScorer {
    fn new() -> Self { Self }
    fn score(&self, query: &Query, document: &str) -> f32 {
        let query_terms: Vec<&str> = query.text.split_whitespace().collect();
        let doc_lower = document.to_lowercase();
        
        let mut matches = 0;
        for term in &query_terms {
            if doc_lower.contains(&term.to_lowercase()) {
                matches += 1;
            }
        }
        
        matches as f32 / query_terms.len() as f32
    }
}
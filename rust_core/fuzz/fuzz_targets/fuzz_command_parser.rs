#![no_main]

use libfuzzer_sys::fuzz_target;
use claude_optimized_deployment_rust::parser::{CommandParser, ParseError};

fuzz_target!(|data: &[u8]| {
    // Convert fuzzer input to string
    if let Ok(input) = std::str::from_utf8(data) {
        // Fuzz command parsing
        let parser = CommandParser::new();
        match parser.parse(input) {
            Ok(command) => {
                // Verify parsed command is valid
                assert!(!command.executable.is_empty());
                assert!(command.timeout.unwrap_or(0) <= 86400000); // Max 24 hours
                
                // Try to execute in safe mode
                if let Ok(safe_cmd) = command.to_safe_command() {
                    // Verify safe command doesn't contain dangerous patterns
                    assert!(!safe_cmd.contains("rm -rf"));
                    assert!(!safe_cmd.contains("dd if=/dev/zero"));
                    assert!(!safe_cmd.contains("fork bomb"));
                }
            }
            Err(e) => {
                // Verify error is one of expected types
                match e {
                    ParseError::InvalidSyntax(_) => {},
                    ParseError::InvalidTimeout(_) => {},
                    ParseError::EmptyCommand => {},
                    ParseError::TooManyArguments(_) => {},
                    _ => panic!("Unexpected error type: {:?}", e),
                }
            }
        }
        
        // Fuzz command chain parsing
        match parser.parse_chain(input) {
            Ok(chain) => {
                // Verify chain properties
                assert!(chain.len() <= 100); // Reasonable chain limit
                for cmd in &chain {
                    assert!(!cmd.executable.is_empty());
                }
            }
            Err(_) => {
                // Error is expected for invalid input
            }
        }
        
        // Fuzz environment variable parsing
        match parser.parse_env_vars(input) {
            Ok(env_vars) => {
                // Verify no dangerous environment variables
                for (key, _) in &env_vars {
                    assert!(!key.starts_with("LD_"));
                    assert!(!key.starts_with("DYLD_"));
                    assert!(key != "PATH");
                }
            }
            Err(_) => {
                // Error is expected for invalid input
            }
        }
    }
});

// Additional fuzzing for command injection protection
fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let parser = CommandParser::new();
        
        // Test injection protection
        let dangerous_patterns = vec![
            "; rm -rf /",
            "| dd if=/dev/zero",
            "& kill -9 -1",
            "$(evil_command)",
            "`malicious`",
            "\n/bin/sh",
        ];
        
        for pattern in dangerous_patterns {
            let test_input = format!("{}{}", input, pattern);
            match parser.parse(&test_input) {
                Ok(cmd) => {
                    // Verify command is properly sanitized
                    let safe = cmd.to_safe_command().unwrap_or_default();
                    assert!(!safe.contains(pattern));
                }
                Err(_) => {
                    // Rejection is also acceptable
                }
            }
        }
    }
});
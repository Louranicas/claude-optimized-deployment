#![no_main]

use libfuzzer_sys::fuzz_target;
use claude_optimized_deployment_rust::mcp::{MCPHandler, MCPRequest, MCPError};
use serde_json::Value;

fuzz_target!(|data: &[u8]| {
    let handler = MCPHandler::new();
    
    // Fuzz raw MCP protocol handling
    if let Ok(input) = std::str::from_utf8(data) {
        // Try parsing as JSON-RPC
        match serde_json::from_str::<Value>(input) {
            Ok(json) => {
                // Verify it's a valid JSON-RPC request
                if json.get("jsonrpc").and_then(|v| v.as_str()) == Some("2.0") {
                    match handler.handle_raw_request(input) {
                        Ok(response) => {
                            // Verify response is valid JSON-RPC
                            if let Ok(resp_json) = serde_json::from_str::<Value>(&response) {
                                assert_eq!(
                                    resp_json.get("jsonrpc").and_then(|v| v.as_str()),
                                    Some("2.0")
                                );
                                assert!(
                                    resp_json.get("result").is_some() || 
                                    resp_json.get("error").is_some()
                                );
                            }
                        }
                        Err(e) => {
                            // Verify error is expected
                            match e {
                                MCPError::InvalidRequest(_) => {},
                                MCPError::MethodNotFound(_) => {},
                                MCPError::InvalidParams(_) => {},
                                MCPError::InternalError(_) => {},
                                _ => panic!("Unexpected error: {:?}", e),
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Invalid JSON, should be rejected
                assert!(handler.handle_raw_request(input).is_err());
            }
        }
    }
    
    // Fuzz MCP method calls
    if data.len() >= 4 {
        let method_idx = data[0] % 10;
        let methods = [
            "initialize",
            "list_tools",
            "execute_tool",
            "list_resources",
            "get_resource",
            "subscribe",
            "unsubscribe",
            "shutdown",
            "health_check",
            "get_capabilities",
        ];
        
        let method = methods[method_idx as usize];
        let param_len = u16::from_le_bytes([data[1], data[2]]) as usize;
        
        if data.len() >= 4 + param_len {
            let params = &data[4..4 + param_len];
            
            // Create MCP request
            let request = MCPRequest {
                jsonrpc: "2.0".to_string(),
                method: method.to_string(),
                params: if params.is_empty() {
                    None
                } else {
                    // Try to parse params as JSON
                    if let Ok(s) = std::str::from_utf8(params) {
                        serde_json::from_str(s).ok()
                    } else {
                        None
                    }
                },
                id: Some(serde_json::json!(1)),
            };
            
            // Handle request
            match handler.handle_request(&request) {
                Ok(response) => {
                    // Verify response structure
                    assert_eq!(response.jsonrpc, "2.0");
                    assert!(response.id.is_some());
                    assert!(response.result.is_some() || response.error.is_some());
                }
                Err(_) => {
                    // Error is acceptable for invalid requests
                }
            }
        }
    }
    
    // Fuzz WebSocket frame handling
    if data.len() >= 2 {
        let frame_type = data[0];
        let payload = &data[1..];
        
        match frame_type % 4 {
            0 => {
                // Text frame
                if let Ok(text) = std::str::from_utf8(payload) {
                    let _ = handler.handle_ws_text_frame(text);
                }
            }
            1 => {
                // Binary frame
                let _ = handler.handle_ws_binary_frame(payload);
            }
            2 => {
                // Close frame
                let code = if payload.len() >= 2 {
                    u16::from_be_bytes([payload[0], payload[1]])
                } else {
                    1000
                };
                let _ = handler.handle_ws_close(code);
            }
            3 => {
                // Ping/Pong frame
                let _ = handler.handle_ws_ping(payload);
            }
            _ => unreachable!(),
        }
    }
    
    // Fuzz concurrent MCP requests
    if data.len() >= 20 {
        use std::thread;
        use std::sync::Arc;
        
        let handler = Arc::new(handler);
        let num_threads = (data[0] % 5) as usize + 1;
        let requests_per_thread = (data[1] % 10) as usize;
        
        let mut handles = vec![];
        
        for t in 0..num_threads {
            let handler = Arc::clone(&handler);
            let thread_data = data.to_vec();
            
            let handle = thread::spawn(move || {
                for i in 0..requests_per_thread {
                    let idx = 2 + t * 2 + i * 2;
                    if idx + 1 < thread_data.len() {
                        let method_idx = thread_data[idx] % 5;
                        let methods = ["list_tools", "health_check", "get_capabilities", "list_resources", "execute_tool"];
                        
                        let request = MCPRequest {
                            jsonrpc: "2.0".to_string(),
                            method: methods[method_idx as usize].to_string(),
                            params: None,
                            id: Some(serde_json::json!(format!("{}_{}", t, i))),
                        };
                        
                        let _ = handler.handle_request(&request);
                    }
                }
            });
            
            handles.push(handle);
        }
        
        // Wait for all threads
        for handle in handles {
            let _ = handle.join();
        }
    }
    
    // Fuzz protocol negotiation
    if let Ok(input) = std::str::from_utf8(data) {
        for line in input.lines() {
            // Try parsing as protocol negotiation
            if line.starts_with("MCP/") {
                let _ = handler.negotiate_protocol(line);
            }
        }
    }
});
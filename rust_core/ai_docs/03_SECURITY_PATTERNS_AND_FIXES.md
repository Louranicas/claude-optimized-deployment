# Security Patterns and Fixes Documentation

## Table of Contents
1. [Security Patterns Implemented](#security-patterns-implemented)
2. [Security Anti-Patterns to Avoid](#security-anti-patterns-to-avoid)
3. [FFI Security Boundaries](#ffi-security-boundaries)
4. [Performance Considerations](#performance-considerations)
5. [Troubleshooting Guide](#troubleshooting-guide)

## Security Patterns Implemented

### 1. Static Nonce Fix Pattern

**Problem**: Static nonces in cryptographic operations compromise security by making encryption predictable.

**Solution**: Dynamic nonce generation with proper entropy.

```rust
use rand::{Rng, thread_rng};
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, SealingKey, UnboundKey, AES_256_GCM};
use ring::error::Unspecified;

pub struct SafeNonceSequence {
    counter: u64,
}

impl NonceSequence for SafeNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut nonce_bytes = [0u8; 12];
        
        // Use counter for uniqueness
        nonce_bytes[..8].copy_from_slice(&self.counter.to_le_bytes());
        
        // Add randomness for unpredictability
        thread_rng().fill(&mut nonce_bytes[8..]);
        
        self.counter = self.counter.wrapping_add(1);
        Nonce::try_assume_unique_for_key(&nonce_bytes)
    }
}

// Python binding example
use pyo3::prelude::*;

#[pyclass]
pub struct SecureEncryption {
    key: Vec<u8>,
}

#[pymethods]
impl SecureEncryption {
    #[new]
    pub fn new(key: Vec<u8>) -> PyResult<Self> {
        if key.len() != 32 {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Key must be 32 bytes for AES-256"
            ));
        }
        Ok(Self { key })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        let unbound_key = UnboundKey::new(&AES_256_GCM, &self.key)
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Invalid key"))?;
        
        let mut key = SealingKey::new(unbound_key, SafeNonceSequence { counter: 0 });
        
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(Aad::empty(), &mut ciphertext)
            .map_err(|_| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>("Encryption failed"))?;
        
        Ok(ciphertext)
    }
}
```

### 2. Command Injection Prevention Pattern

**Problem**: Unvalidated user input in system commands can lead to arbitrary code execution.

**Solution**: Input validation, whitelisting, and safe command execution.

```rust
use std::process::Command;
use regex::Regex;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommandError {
    #[error("Invalid characters in input")]
    InvalidInput,
    #[error("Command not in whitelist")]
    NotWhitelisted,
    #[error("Command execution failed: {0}")]
    ExecutionFailed(String),
}

pub struct SafeCommandExecutor {
    allowed_commands: Vec<String>,
    input_validator: Regex,
}

impl SafeCommandExecutor {
    pub fn new() -> Self {
        Self {
            allowed_commands: vec![
                "ls".to_string(),
                "cat".to_string(),
                "grep".to_string(),
            ],
            // Only allow alphanumeric, spaces, dots, slashes, and hyphens
            input_validator: Regex::new(r"^[a-zA-Z0-9\s./\-_]+$").unwrap(),
        }
    }

    pub fn execute(&self, command: &str, args: &[String]) -> Result<String, CommandError> {
        // Validate command is whitelisted
        if !self.allowed_commands.contains(&command.to_string()) {
            return Err(CommandError::NotWhitelisted);
        }

        // Validate all arguments
        for arg in args {
            if !self.input_validator.is_match(arg) {
                return Err(CommandError::InvalidInput);
            }
        }

        // Execute with restricted environment
        let output = Command::new(command)
            .args(args)
            .env_clear() // Clear environment variables
            .env("PATH", "/usr/bin:/bin") // Minimal PATH
            .output()
            .map_err(|e| CommandError::ExecutionFailed(e.to_string()))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(CommandError::ExecutionFailed(
                String::from_utf8_lossy(&output.stderr).to_string()
            ))
        }
    }
}

// Python binding
#[pyclass]
pub struct PyCommandExecutor {
    executor: SafeCommandExecutor,
}

#[pymethods]
impl PyCommandExecutor {
    #[new]
    pub fn new() -> Self {
        Self {
            executor: SafeCommandExecutor::new(),
        }
    }

    pub fn execute(&self, command: &str, args: Vec<String>) -> PyResult<String> {
        self.executor.execute(command, &args)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
    }
}
```

### 3. Authentication Decorator Pattern

**Problem**: Inconsistent authentication checks across endpoints.

**Solution**: Centralized authentication with decorators and middleware.

```rust
use std::sync::Arc;
use async_trait::async_trait;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub roles: Vec<String>,
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<Claims, AuthError>;
    async fn has_permission(&self, claims: &Claims, permission: &str) -> bool;
}

#[derive(Debug)]
pub enum AuthError {
    InvalidToken,
    ExpiredToken,
    InsufficientPermissions,
}

pub struct JWTAuthProvider {
    secret: String,
}

#[async_trait]
impl AuthProvider for JWTAuthProvider {
    async fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &Validation::new(Algorithm::HS256),
        ).map_err(|_| AuthError::InvalidToken)?;

        Ok(token_data.claims)
    }

    async fn has_permission(&self, claims: &Claims, permission: &str) -> bool {
        // Check role-based permissions
        match permission {
            "read" => true, // All authenticated users can read
            "write" => claims.roles.contains(&"writer".to_string()) || 
                      claims.roles.contains(&"admin".to_string()),
            "admin" => claims.roles.contains(&"admin".to_string()),
            _ => false,
        }
    }
}

// Middleware implementation
pub struct AuthMiddleware<T: AuthProvider> {
    provider: Arc<T>,
}

impl<T: AuthProvider> AuthMiddleware<T> {
    pub fn new(provider: Arc<T>) -> Self {
        Self { provider }
    }

    pub async fn authenticate(&self, token: &str) -> Result<Claims, AuthError> {
        self.provider.validate_token(token).await
    }

    pub async fn authorize(&self, claims: &Claims, permission: &str) -> Result<(), AuthError> {
        if self.provider.has_permission(claims, permission).await {
            Ok(())
        } else {
            Err(AuthError::InsufficientPermissions)
        }
    }
}

// Python integration
#[pyclass]
pub struct PyAuthMiddleware {
    middleware: Arc<AuthMiddleware<JWTAuthProvider>>,
}

#[pymethods]
impl PyAuthMiddleware {
    #[new]
    pub fn new(secret: String) -> Self {
        let provider = Arc::new(JWTAuthProvider { secret });
        let middleware = Arc::new(AuthMiddleware::new(provider));
        Self { middleware }
    }

    pub fn validate_token(&self, token: &str) -> PyResult<PyObject> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let claims = runtime.block_on(self.middleware.authenticate(token))
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyAuthenticationError, _>(
                format!("Authentication failed: {:?}", e)
            ))?;
        
        Python::with_gil(|py| {
            let dict = PyDict::new(py);
            dict.set_item("sub", claims.sub)?;
            dict.set_item("exp", claims.exp)?;
            dict.set_item("roles", claims.roles)?;
            Ok(dict.into())
        })
    }
}
```

### 4. mTLS Implementation Pattern

**Problem**: Service-to-service communication lacks mutual authentication.

**Solution**: Implement mutual TLS with certificate validation.

```rust
use rustls::{Certificate, PrivateKey, ServerConfig, ClientConfig};
use rustls::internal::pemfile::{certs, pkcs8_private_keys};
use std::io::BufReader;
use std::fs::File;
use std::sync::Arc;

pub struct MTLSConfig {
    pub ca_cert_path: String,
    pub cert_path: String,
    pub key_path: String,
}

impl MTLSConfig {
    pub fn load_certs(&self) -> Result<Vec<Certificate>, Box<dyn std::error::Error>> {
        let cert_file = File::open(&self.cert_path)?;
        let mut reader = BufReader::new(cert_file);
        certs(&mut reader)
            .map_err(|_| "Failed to load certificates".into())
    }

    pub fn load_private_key(&self) -> Result<PrivateKey, Box<dyn std::error::Error>> {
        let key_file = File::open(&self.key_path)?;
        let mut reader = BufReader::new(key_file);
        let keys = pkcs8_private_keys(&mut reader)
            .map_err(|_| "Failed to load private key")?;
        
        keys.into_iter()
            .next()
            .ok_or_else(|| "No private key found".into())
    }

    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error>> {
        let certs = self.load_certs()?;
        let key = self.load_private_key()?;
        
        let mut config = ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(
                rustls::server::AllowAnyAuthenticatedClient::new(
                    self.load_root_store()?
                )
            )
            .with_single_cert(certs, key)?;
        
        Ok(Arc::new(config))
    }

    pub fn build_client_config(&self) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error>> {
        let certs = self.load_certs()?;
        let key = self.load_private_key()?;
        
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.load_root_store()?)
            .with_single_cert(certs, key)?;
        
        Ok(Arc::new(config))
    }

    fn load_root_store(&self) -> Result<rustls::RootCertStore, Box<dyn std::error::Error>> {
        let ca_file = File::open(&self.ca_cert_path)?;
        let mut reader = BufReader::new(ca_file);
        let ca_certs = certs(&mut reader)?;
        
        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store.add(&cert)?;
        }
        
        Ok(root_store)
    }
}

// Service wrapper with mTLS
pub struct SecureService {
    mtls_config: Arc<MTLSConfig>,
}

impl SecureService {
    pub fn new(mtls_config: MTLSConfig) -> Self {
        Self {
            mtls_config: Arc::new(mtls_config),
        }
    }

    pub async fn connect_to_service(&self, addr: &str) -> Result<SecureConnection, Box<dyn std::error::Error>> {
        let client_config = self.mtls_config.build_client_config()?;
        // Implementation depends on your networking library
        // This is a conceptual example
        Ok(SecureConnection::new(addr, client_config))
    }
}

pub struct SecureConnection {
    // Connection implementation
}

impl SecureConnection {
    fn new(addr: &str, config: Arc<ClientConfig>) -> Self {
        // Implementation
        Self {}
    }
}
```

## Security Anti-Patterns to Avoid

### 1. Hardcoded Secrets
```rust
// ❌ NEVER DO THIS
const API_KEY: &str = "sk-1234567890abcdef";

// ✅ DO THIS INSTEAD
use std::env;

fn get_api_key() -> Result<String, String> {
    env::var("API_KEY").map_err(|_| "API_KEY not set".to_string())
}
```

### 2. SQL Injection via String Concatenation
```rust
// ❌ NEVER DO THIS
fn query_user(username: &str) -> String {
    format!("SELECT * FROM users WHERE username = '{}'", username)
}

// ✅ DO THIS INSTEAD
use sqlx::{query_as, PgPool};

async fn query_user(pool: &PgPool, username: &str) -> Result<User, sqlx::Error> {
    query_as!(
        User,
        "SELECT * FROM users WHERE username = $1",
        username
    )
    .fetch_one(pool)
    .await
}
```

### 3. Unvalidated Deserialization
```rust
// ❌ NEVER DO THIS
fn parse_user_input(input: &str) -> serde_json::Value {
    serde_json::from_str(input).unwrap() // No validation!
}

// ✅ DO THIS INSTEAD
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Deserialize, Validate)]
struct UserInput {
    #[validate(length(min = 1, max = 100))]
    username: String,
    #[validate(email)]
    email: String,
    #[validate(range(min = 18, max = 150))]
    age: u8,
}

fn parse_user_input(input: &str) -> Result<UserInput, ValidationError> {
    let user: UserInput = serde_json::from_str(input)?;
    user.validate()?;
    Ok(user)
}
```

### 4. Insecure Random Number Generation
```rust
// ❌ NEVER DO THIS
use std::time::{SystemTime, UNIX_EPOCH};

fn generate_token() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    format!("token_{}", timestamp) // Predictable!
}

// ✅ DO THIS INSTEAD
use rand::{Rng, thread_rng};
use rand::distributions::Alphanumeric;

fn generate_token() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}
```

### 5. Race Conditions in File Operations
```rust
// ❌ NEVER DO THIS
use std::fs;
use std::path::Path;

fn create_temp_file(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        // TOCTOU vulnerability!
        fs::write(path, b"data")?;
    }
    Ok(())
}

// ✅ DO THIS INSTEAD
use std::fs::OpenOptions;

fn create_temp_file(path: &Path) -> std::io::Result<()> {
    OpenOptions::new()
        .write(true)
        .create_new(true) // Atomic operation
        .open(path)?
        .write_all(b"data")?;
    Ok(())
}
```

## FFI Security Boundaries

### 1. Memory Safety Across FFI
```rust
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Safe string handling across FFI boundary
#[no_mangle]
pub extern "C" fn process_string(input: *const c_char) -> *mut c_char {
    // Validate pointer
    if input.is_null() {
        return std::ptr::null_mut();
    }

    // Safe conversion with error handling
    let c_str = unsafe { CStr::from_ptr(input) };
    
    match c_str.to_str() {
        Ok(s) => {
            // Process string
            let result = s.to_uppercase();
            
            // Convert back to C string
            match CString::new(result) {
                Ok(c_string) => c_string.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

// Memory cleanup function
#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        CString::from_raw(s);
        // CString is automatically dropped
    }
}
```

### 2. PyO3 Security Boundaries
```rust
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyclass]
pub struct SecureProcessor {
    max_size: usize,
}

#[pymethods]
impl SecureProcessor {
    #[new]
    pub fn new(max_size: Option<usize>) -> Self {
        Self {
            max_size: max_size.unwrap_or(1024 * 1024), // 1MB default
        }
    }

    pub fn process_data(&self, data: &PyBytes) -> PyResult<Vec<u8>> {
        let bytes = data.as_bytes();
        
        // Size validation
        if bytes.len() > self.max_size {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                format!("Data exceeds maximum size of {} bytes", self.max_size)
            ));
        }

        // Validate data structure
        self.validate_data(bytes)?;
        
        // Process safely
        Ok(self.safe_process(bytes))
    }

    fn validate_data(&self, data: &[u8]) -> PyResult<()> {
        // Add validation logic
        if data.is_empty() {
            return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
                "Empty data not allowed"
            ));
        }
        Ok(())
    }

    fn safe_process(&self, data: &[u8]) -> Vec<u8> {
        // Safe processing with bounds checking
        data.iter()
            .map(|&b| b.wrapping_add(1))
            .collect()
    }
}
```

### 3. Thread Safety Across FFI
```rust
use std::sync::{Arc, Mutex, RwLock};
use once_cell::sync::Lazy;

// Global state with thread-safe access
static GLOBAL_STATE: Lazy<Arc<RwLock<GlobalState>>> = Lazy::new(|| {
    Arc::new(RwLock::new(GlobalState::new()))
});

pub struct GlobalState {
    connections: Vec<Connection>,
    config: Config,
}

impl GlobalState {
    fn new() -> Self {
        Self {
            connections: Vec::new(),
            config: Config::default(),
        }
    }
}

// Thread-safe FFI functions
#[no_mangle]
pub extern "C" fn add_connection(host: *const c_char, port: u16) -> i32 {
    if host.is_null() {
        return -1;
    }

    let host_str = unsafe {
        match CStr::from_ptr(host).to_str() {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };

    let connection = Connection::new(host_str, port);
    
    match GLOBAL_STATE.write() {
        Ok(mut state) => {
            state.connections.push(connection);
            (state.connections.len() - 1) as i32
        }
        Err(_) => -1,
    }
}

#[no_mangle]
pub extern "C" fn get_connection_count() -> i32 {
    match GLOBAL_STATE.read() {
        Ok(state) => state.connections.len() as i32,
        Err(_) => -1,
    }
}
```

## Performance Considerations

### 1. Cryptographic Operations
```rust
use ring::aead::{Aead, AeadCtx, Algorithm};
use once_cell::sync::Lazy;

// Cache expensive operations
static CRYPTO_CONTEXT: Lazy<Arc<Mutex<CryptoCache>>> = Lazy::new(|| {
    Arc::new(Mutex::new(CryptoCache::new()))
});

pub struct CryptoCache {
    contexts: HashMap<Vec<u8>, AeadCtx>,
}

impl CryptoCache {
    fn new() -> Self {
        Self {
            contexts: HashMap::new(),
        }
    }

    fn get_or_create_context(&mut self, key: &[u8], algorithm: &'static Algorithm) -> &AeadCtx {
        self.contexts.entry(key.to_vec())
            .or_insert_with(|| AeadCtx::new(algorithm, key).unwrap())
    }
}

// Batch operations for efficiency
pub fn encrypt_batch(items: &[&[u8]], key: &[u8]) -> Vec<Vec<u8>> {
    let mut cache = CRYPTO_CONTEXT.lock().unwrap();
    let ctx = cache.get_or_create_context(key, &AES_256_GCM);
    
    items.par_iter()
        .map(|item| {
            // Encrypt in parallel
            encrypt_with_context(ctx, item)
        })
        .collect()
}
```

### 2. Authentication Caching
```rust
use lru::LruCache;
use std::time::{Duration, Instant};

pub struct AuthCache {
    cache: LruCache<String, (Claims, Instant)>,
    ttl: Duration,
}

impl AuthCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: LruCache::new(capacity),
            ttl,
        }
    }

    pub fn get(&mut self, token: &str) -> Option<Claims> {
        if let Some((claims, timestamp)) = self.cache.get(token) {
            if timestamp.elapsed() < self.ttl {
                return Some(claims.clone());
            }
        }
        None
    }

    pub fn insert(&mut self, token: String, claims: Claims) {
        self.cache.put(token, (claims, Instant::now()));
    }
}

// Use with auth middleware
impl<T: AuthProvider> AuthMiddleware<T> {
    pub async fn authenticate_cached(&self, token: &str, cache: &mut AuthCache) -> Result<Claims, AuthError> {
        // Check cache first
        if let Some(claims) = cache.get(token) {
            return Ok(claims);
        }

        // Validate token
        let claims = self.provider.validate_token(token).await?;
        
        // Cache for future requests
        cache.insert(token.to_string(), claims.clone());
        
        Ok(claims)
    }
}
```

### 3. Connection Pooling for mTLS
```rust
use deadpool::managed::{Manager, Pool, PoolConfig};
use async_trait::async_trait;

pub struct MTLSConnectionManager {
    config: Arc<MTLSConfig>,
    target_addr: String,
}

#[async_trait]
impl Manager for MTLSConnectionManager {
    type Type = SecureConnection;
    type Error = Box<dyn std::error::Error>;

    async fn create(&self) -> Result<SecureConnection, Self::Error> {
        let client_config = self.config.build_client_config()?;
        SecureConnection::connect(&self.target_addr, client_config).await
    }

    async fn recycle(&self, conn: &mut SecureConnection) -> RecycleResult<Self::Error> {
        if conn.is_healthy().await {
            Ok(())
        } else {
            Err(RecycleError::Message("Connection unhealthy".into()))
        }
    }
}

pub async fn create_mtls_pool(config: MTLSConfig, addr: String) -> Pool<MTLSConnectionManager> {
    let manager = MTLSConnectionManager {
        config: Arc::new(config),
        target_addr: addr,
    };
    
    let pool_config = PoolConfig::new(10); // 10 connections
    Pool::from_config(manager, pool_config)
}
```

## Troubleshooting Guide

### 1. Authentication Failures

**Symptom**: 401 Unauthorized errors
```rust
// Debug authentication issues
#[derive(Debug)]
pub struct AuthDebugInfo {
    pub token_present: bool,
    pub token_format_valid: bool,
    pub signature_valid: bool,
    pub claims_valid: bool,
    pub permissions_granted: bool,
}

pub async fn debug_auth_failure(token: &str, required_permission: &str) -> AuthDebugInfo {
    let mut info = AuthDebugInfo {
        token_present: !token.is_empty(),
        token_format_valid: false,
        signature_valid: false,
        claims_valid: false,
        permissions_granted: false,
    };

    // Check token format
    let parts: Vec<&str> = token.split('.').collect();
    info.token_format_valid = parts.len() == 3;

    if info.token_format_valid {
        // Attempt decode
        match decode_header(token) {
            Ok(_) => {
                // Check signature
                match validate_token(token).await {
                    Ok(claims) => {
                        info.signature_valid = true;
                        info.claims_valid = !claims.sub.is_empty();
                        info.permissions_granted = check_permission(&claims, required_permission);
                    }
                    Err(_) => {}
                }
            }
            Err(_) => {}
        }
    }

    info
}
```

### 2. mTLS Connection Issues

**Symptom**: TLS handshake failures
```rust
pub enum MTLSError {
    CertificateNotFound(String),
    CertificateExpired,
    CertificateNotTrusted,
    PrivateKeyMismatch,
    CipherSuiteMismatch,
}

pub fn diagnose_mtls_error(config: &MTLSConfig) -> Result<(), MTLSError> {
    // Check certificate exists
    if !Path::new(&config.cert_path).exists() {
        return Err(MTLSError::CertificateNotFound(config.cert_path.clone()));
    }

    // Load and validate certificate
    let cert = load_certificate(&config.cert_path)?;
    
    // Check expiration
    if cert.not_after() < SystemTime::now() {
        return Err(MTLSError::CertificateExpired);
    }

    // Verify certificate chain
    if !verify_cert_chain(&cert, &config.ca_cert_path)? {
        return Err(MTLSError::CertificateNotTrusted);
    }

    // Check private key matches certificate
    let key = load_private_key(&config.key_path)?;
    if !verify_key_cert_match(&key, &cert)? {
        return Err(MTLSError::PrivateKeyMismatch);
    }

    Ok(())
}
```

### 3. Encryption/Decryption Failures

**Symptom**: Decryption errors or corrupted data
```rust
pub struct EncryptionDiagnostics {
    pub key_size_valid: bool,
    pub nonce_unique: bool,
    pub tag_present: bool,
    pub data_integrity: bool,
}

pub fn diagnose_encryption_issue(
    key: &[u8],
    ciphertext: &[u8],
    expected_tag_size: usize,
) -> EncryptionDiagnostics {
    EncryptionDiagnostics {
        key_size_valid: key.len() == 32, // AES-256
        nonce_unique: check_nonce_uniqueness(ciphertext),
        tag_present: ciphertext.len() >= expected_tag_size,
        data_integrity: verify_data_integrity(ciphertext),
    }
}

fn check_nonce_uniqueness(ciphertext: &[u8]) -> bool {
    // Implementation depends on your nonce storage strategy
    true
}

fn verify_data_integrity(ciphertext: &[u8]) -> bool {
    // Basic checks
    !ciphertext.is_empty() && ciphertext.len() % 16 == 0
}
```

### 4. Performance Degradation

**Symptom**: Slow authentication or encryption operations
```rust
use std::time::Instant;

pub struct PerformanceMetrics {
    pub operation: String,
    pub duration: Duration,
    pub throughput: f64,
}

pub fn measure_crypto_performance<F, T>(
    operation: &str,
    data_size: usize,
    f: F,
) -> (T, PerformanceMetrics)
where
    F: FnOnce() -> T,
{
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    
    let throughput = data_size as f64 / duration.as_secs_f64() / 1_000_000.0; // MB/s
    
    let metrics = PerformanceMetrics {
        operation: operation.to_string(),
        duration,
        throughput,
    };
    
    (result, metrics)
}

// Usage
let (encrypted, metrics) = measure_crypto_performance(
    "AES-256-GCM Encryption",
    data.len(),
    || encrypt_data(&key, &data),
);

if metrics.duration > Duration::from_millis(100) {
    log::warn!(
        "Slow {} operation: {:?} for {} bytes",
        metrics.operation,
        metrics.duration,
        data.len()
    );
}
```

### 5. Memory Safety Issues

**Symptom**: Segfaults or memory corruption in FFI
```rust
// Safe memory handling patterns
use std::mem::ManuallyDrop;

#[no_mangle]
pub extern "C" fn create_secure_buffer(size: usize) -> *mut SecureBuffer {
    if size == 0 || size > MAX_BUFFER_SIZE {
        return std::ptr::null_mut();
    }

    let buffer = Box::new(SecureBuffer::new(size));
    Box::into_raw(buffer)
}

#[no_mangle]
pub extern "C" fn free_secure_buffer(ptr: *mut SecureBuffer) {
    if ptr.is_null() {
        return;
    }

    unsafe {
        let buffer = Box::from_raw(ptr);
        // Securely wipe memory before deallocation
        buffer.secure_wipe();
        // Box is automatically dropped
    }
}

pub struct SecureBuffer {
    data: Vec<u8>,
}

impl SecureBuffer {
    fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    fn secure_wipe(&self) {
        unsafe {
            std::ptr::write_volatile(self.data.as_ptr() as *mut u8, 0);
            for i in 0..self.data.len() {
                std::ptr::write_volatile(self.data.as_ptr().add(i) as *mut u8, 0);
            }
        }
    }
}
```

## Best Practices Summary

1. **Always validate input** - Never trust external data
2. **Use established cryptographic libraries** - Don't roll your own crypto
3. **Implement defense in depth** - Multiple security layers
4. **Fail securely** - Default to deny on errors
5. **Log security events** - But never log sensitive data
6. **Keep dependencies updated** - Regular security patches
7. **Use static analysis** - Catch issues before runtime
8. **Test security features** - Include security in CI/CD
9. **Document security decisions** - Future maintainers need context
10. **Review and audit regularly** - Security is not a one-time task

## References

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Rust Security Guidelines](https://anssi-fr.github.io/rust-guide/)
- [The Rustonomicon](https://doc.rust-lang.org/nomicon/) - Advanced Rust patterns
- [Ring Cryptography Library](https://github.com/briansmith/ring) - Safe crypto in Rust
- [PyO3 Documentation](https://pyo3.rs/) - Python-Rust interop

---

*Last Updated: June 2025*
*Version: 1.0.0*
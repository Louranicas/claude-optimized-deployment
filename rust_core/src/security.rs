// ============================================================================
// Security Module - High-Performance Security Operations
// ============================================================================

use pyo3::prelude::*;
use sha2::{Sha256, Sha512, Digest};
use hmac::{Hmac, Mac};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{SaltString, rand_core::OsRng};
use rayon::prelude::*;
use std::collections::HashMap;
use tracing::{info, debug};

use crate::{CoreError};

type HmacSha256 = Hmac<Sha256>;

/// Register security functions with Python module
pub fn register_module(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(hash_passwords_batch_py, m)?)?;
    m.add_function(wrap_pyfunction!(verify_passwords_batch_py, m)?)?;
    m.add_function(wrap_pyfunction!(generate_hmac_batch_py, m)?)?;
    m.add_class::<SecureVault>()?;
    m.add_class::<SecurityAuditor>()?;
    Ok(())
}

// ========================= Secure Vault =========================

#[pyclass]
pub struct SecureVault {
    cipher: Aes256Gcm,
    nonce: Vec<u8>,
}

#[pymethods]
impl SecureVault {
    #[new]
    fn new(key: &[u8]) -> PyResult<Self> {
        if key.len() != 32 {
            return Err(CoreError::Security(
                "Key must be 32 bytes for AES-256".to_string()
            ).into());
        }
        
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        
        // Generate a random nonce (in production, use a new nonce for each encryption)
        let nonce = vec![0u8; 12]; // Simplified for example
        
        Ok(Self { cipher, nonce })
    }
    
    /// Encrypt data
    fn encrypt(&self, plaintext: &[u8]) -> PyResult<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce);
        
        self.cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CoreError::Security("Encryption failed".to_string()).into())
    }
    
    /// Decrypt data
    fn decrypt(&self, ciphertext: &[u8]) -> PyResult<Vec<u8>> {
        let nonce = Nonce::from_slice(&self.nonce);
        
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CoreError::Security("Decryption failed".to_string()).into())
    }
    
    /// Encrypt multiple items in parallel
    fn encrypt_batch(&self, items: Vec<Vec<u8>>) -> PyResult<Vec<Vec<u8>>> {
        let nonce = Nonce::from_slice(&self.nonce);
        
        items
            .into_par_iter()
            .map(|plaintext| {
                self.cipher
                    .encrypt(nonce, plaintext.as_ref())
                    .map_err(|_| CoreError::Security("Batch encryption failed".to_string()).into())
            })
            .collect()
    }
}

// ========================= Security Auditor =========================

#[pyclass]
pub struct SecurityAuditor {
    checks_passed: HashMap<String, bool>,
    vulnerabilities: Vec<String>,
}

#[pymethods]
impl SecurityAuditor {
    #[new]
    fn new() -> Self {
        Self {
            checks_passed: HashMap::new(),
            vulnerabilities: Vec::new(),
        }
    }
    
    /// Check password strength
    fn check_password_strength(&mut self, password: &str) -> PyResult<bool> {
        let mut strength_score = 0;
        
        // Length check
        if password.len() >= 12 {
            strength_score += 1;
        }
        
        // Character variety checks
        if password.chars().any(|c| c.is_lowercase()) {
            strength_score += 1;
        }
        if password.chars().any(|c| c.is_uppercase()) {
            strength_score += 1;
        }
        if password.chars().any(|c| c.is_numeric()) {
            strength_score += 1;
        }
        if password.chars().any(|c| !c.is_alphanumeric()) {
            strength_score += 1;
        }
        
        let is_strong = strength_score >= 4;
        self.checks_passed.insert("password_strength".to_string(), is_strong);
        
        if !is_strong {
            self.vulnerabilities.push("Weak password detected".to_string());
        }
        
        Ok(is_strong)
    }
    
    /// Scan for common vulnerabilities
    fn scan_vulnerabilities(&mut self, config: HashMap<String, String>) -> PyResult<Vec<String>> {
        self.vulnerabilities.clear();
        
        // Check for hardcoded credentials
        for (key, value) in &config {
            if key.contains("password") || key.contains("secret") || key.contains("key") {
                if !value.starts_with("${") && !value.starts_with("env:") {
                    self.vulnerabilities.push(
                        format!("Potential hardcoded credential in: {}", key)
                    );
                }
            }
        }
        
        // Check for insecure protocols
        if let Some(url) = config.get("api_url") {
            if url.starts_with("http://") && !url.contains("localhost") {
                self.vulnerabilities.push("Insecure HTTP protocol used".to_string());
            }
        }
        
        // Check for weak encryption
        if let Some(algo) = config.get("encryption_algorithm") {
            if algo == "DES" || algo == "3DES" || algo == "RC4" {
                self.vulnerabilities.push(
                    format!("Weak encryption algorithm: {}", algo)
                );
            }
        }
        
        self.checks_passed.insert(
            "vulnerability_scan".to_string(),
            self.vulnerabilities.is_empty()
        );
        
        Ok(self.vulnerabilities.clone())
    }
    
    /// Generate security report
    fn generate_report(&self) -> PyResult<String> {
        let mut report = HashMap::new();
        
        report.insert(
            "checks_passed".to_string(),
            serde_json::to_value(&self.checks_passed)
                .map_err(|e| CoreError::Serialization(e.to_string()))?
        );
        
        report.insert(
            "vulnerabilities".to_string(),
            serde_json::to_value(&self.vulnerabilities)
                .map_err(|e| CoreError::Serialization(e.to_string()))?
        );
        
        let total_checks = self.checks_passed.len();
        let passed_checks = self.checks_passed.values().filter(|&&v| v).count();
        let security_score = if total_checks > 0 {
            (passed_checks as f64 / total_checks as f64) * 100.0
        } else {
            0.0
        };
        
        report.insert(
            "security_score".to_string(),
            serde_json::Value::Number(serde_json::Number::from_f64(security_score).unwrap())
        );
        
        // Convert report to JSON string
        serde_json::to_string_pretty(&report)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("JSON serialization error: {}", e)))
    }
}

// ========================= Batch Operations =========================

/// Hash passwords in parallel using Argon2
#[pyfunction]
#[inline]
pub fn hash_passwords_batch_py(passwords: Vec<String>) -> PyResult<Vec<String>> {
    info!("Hashing {} passwords", passwords.len());
    
    let hashes: Result<Vec<String>, CoreError> = passwords
        .par_iter()
        .map(|password| {
            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            
            argon2
                .hash_password(password.as_bytes(), &salt)
                .map(|hash| hash.to_string())
                .map_err(|e| CoreError::Security(format!("Hashing failed: {}", e)))
        })
        .collect();
    
    hashes.map_err(|e| e.into())
}

/// Verify passwords in parallel
#[pyfunction]
#[inline]
pub fn verify_passwords_batch_py(passwords: Vec<String>, hashes: Vec<String>) -> PyResult<Vec<bool>> {
    if passwords.len() != hashes.len() {
        return Err(CoreError::Security(
            "Password and hash counts must match".to_string()
        ).into());
    }
    
    let results: Vec<bool> = passwords
        .par_iter()
        .zip(hashes.par_iter())
        .map(|(password, hash)| {
            let parsed_hash = PasswordHash::new(hash).ok()?;
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed_hash)
                .ok()
                .map(|_| true)
        })
        .map(|opt| opt.unwrap_or(false))
        .collect();
    
    Ok(results)
}

/// Generate HMAC signatures in parallel
#[pyfunction]
pub fn generate_hmac_batch_py(messages: Vec<String>, key: &[u8]) -> PyResult<Vec<String>> {
    let mac = <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|_| CoreError::Security("Invalid HMAC key length".to_string()))?;
    
    let signatures: Vec<String> = messages
        .par_iter()
        .map(|msg| {
            let mut mac = mac.clone();
            mac.update(msg.as_bytes());
            format!("{:x}", mac.finalize().into_bytes())
        })
        .collect();
    
    debug!("Generated {} HMAC signatures", signatures.len());
    Ok(signatures)
}

// ========================= Utility Functions =========================

/// Generate a secure random key
pub fn generate_key(length: usize) -> Vec<u8> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.gen()).collect()
}

/// Hash data using SHA-256
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Hash data using SHA-512
pub fn sha512_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secure_vault() {
        let key = generate_key(32);
        let vault = SecureVault::new(&key).unwrap();
        
        let plaintext = b"Hello, World!";
        let ciphertext = vault.encrypt(plaintext).unwrap();
        let decrypted = vault.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_password_hashing() {
        let passwords = vec!["password123".to_string(), "secure_pass".to_string()];
        let hashes = hash_passwords_batch_py(passwords.clone()).unwrap();
        
        assert_eq!(hashes.len(), 2);
        
        // Verify the passwords
        let results = verify_passwords_batch_py(passwords, hashes).unwrap();
        assert!(results.iter().all(|&r| r));
    }
    
    #[test]
    fn test_security_auditor() {
        let mut auditor = SecurityAuditor::new();
        
        // Test password strength
        assert!(!auditor.check_password_strength("weak").unwrap());
        assert!(auditor.check_password_strength("Str0ng!P@ssw0rd").unwrap());
        
        // Test vulnerability scanning
        let mut config = HashMap::new();
        config.insert("api_url".to_string(), "http://api.example.com".to_string());
        config.insert("db_password".to_string(), "hardcoded123".to_string());
        
        let vulns = auditor.scan_vulnerabilities(config).unwrap();
        assert!(!vulns.is_empty());
    }
    
    #[test]
    fn test_hmac_generation() {
        let messages = vec!["message1".to_string(), "message2".to_string()];
        let key = b"secret_key_123";
        
        let signatures = generate_hmac_batch_py(messages, key).unwrap();
        assert_eq!(signatures.len(), 2);
        assert!(!signatures[0].is_empty());
    }
}

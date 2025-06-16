
"""
Data Encryption Module
Implements encryption at rest and in transit
"""
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

class DataEncryption:
    """Handles data encryption/decryption"""
    
    def __init__(self):
        self.key = self._get_or_generate_key()
        self.cipher = Fernet(self.key)
        
    def _get_or_generate_key(self) -> bytes:
        """Get or generate encryption key"""
        key_file = os.getenv("ENCRYPTION_KEY_FILE", ".encryption.key")
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            # Generate new key
            key = Fernet.generate_key()
            
            # Save securely
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            
            return key
            
    def encrypt(self, data: str) -> str:
        """Encrypt data"""
        return self.cipher.encrypt(data.encode()).decode()
        
    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
        
    def encrypt_pii(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt PII fields in data"""
        pii_fields = ["ssn", "email", "phone", "address", "credit_card", "password"]
        encrypted_data = data.copy()
        
        for field in pii_fields:
            if field in encrypted_data:
                encrypted_data[field] = self.encrypt(str(encrypted_data[field]))
                
        return encrypted_data

# Global encryption instance
data_encryption = DataEncryption()

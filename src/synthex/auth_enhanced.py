
"""
Enhanced Authentication Module
Implements secure authentication with MFA support
"""
import os
import secrets
import time
from typing import Optional, Dict, Any
from argon2 import PasswordHasher
import pyotp
import jwt
from datetime import datetime, timedelta

class SecureAuthenticator:
    """Secure authentication with MFA"""
    
    def __init__(self):
        self.ph = PasswordHasher()
        self.jwt_secret = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
        self.token_expiry = 3600  # 1 hour
        
    def hash_password(self, password: str) -> str:
        """Hash password using Argon2"""
        return self.ph.hash(password)
        
    def verify_password(self, password: str, hash: str) -> bool:
        """Verify password"""
        try:
            self.ph.verify(hash, password)
            return True
        except:
            return False
            
    def generate_mfa_secret(self) -> str:
        """Generate MFA secret"""
        return pyotp.random_base32()
        
    def verify_mfa_token(self, secret: str, token: str) -> bool:
        """Verify MFA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
        
    def generate_jwt(self, user_id: str, additional_claims: Dict[str, Any] = None) -> str:
        """Generate JWT token"""
        payload = {
            "user_id": user_id,
            "exp": datetime.utcnow() + timedelta(seconds=self.token_expiry),
            "iat": datetime.utcnow(),
            "jti": secrets.token_urlsafe(16)
        }
        
        if additional_claims:
            payload.update(additional_claims)
            
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
        
    def verify_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
            
    def requires_auth(self, func):
        """Decorator for requiring authentication"""
        async def wrapper(*args, **kwargs):
            # Extract token from request
            token = kwargs.get("auth_token")
            if not token:
                raise AuthenticationError("No authentication token provided")
                
            payload = self.verify_jwt(token)
            if not payload:
                raise AuthenticationError("Invalid or expired token")
                
            kwargs["user_id"] = payload["user_id"]
            return await func(*args, **kwargs)
            
        return wrapper

class AuthenticationError(Exception):
    """Authentication error"""
    pass

# Global authenticator instance
authenticator = SecureAuthenticator()

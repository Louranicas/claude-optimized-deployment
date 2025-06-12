#!/usr/bin/env python3
"""
Basic CORS Configuration Test

Tests the secure CORS configuration module functionality.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from src.core.cors_config import SecureCORSConfig, Environment, get_fastapi_cors_config
    
    def test_basic_functionality():
        """Test basic CORS configuration functionality."""
        print("🧪 Testing CORS Configuration...")
        
        # Test different environments
        environments = [Environment.DEVELOPMENT, Environment.PRODUCTION, Environment.TESTING, Environment.STAGING]
        
        for env in environments:
            print(f"\n📋 Testing {env.value} environment:")
            
            config = SecureCORSConfig(env)
            
            # Basic checks
            print(f"  Origins count: {len(config.allowed_origins)}")
            print(f"  Has wildcard: {'*' in config.allowed_origins}")
            print(f"  Allows credentials: {config.allow_credentials}")
            print(f"  Sample origins: {config.allowed_origins[:2]}")
            
            # Security checks
            if "*" in config.allowed_origins:
                print(f"  ❌ Still uses wildcard origins!")
                return False
            
            if env == Environment.PRODUCTION:
                http_origins = [o for o in config.allowed_origins if o.startswith("http://")]
                localhost_origins = [o for o in config.allowed_origins if "localhost" in o]
                
                if http_origins:
                    print(f"  ⚠️  Production allows HTTP: {http_origins}")
                if localhost_origins:
                    print(f"  ⚠️  Production allows localhost: {localhost_origins}")
            
            # Test FastAPI config
            fastapi_config = get_fastapi_cors_config(env)
            required_keys = ["allow_origins", "allow_credentials", "allow_methods", "allow_headers"]
            
            for key in required_keys:
                if key not in fastapi_config:
                    print(f"  ❌ Missing FastAPI config key: {key}")
                    return False
            
            print(f"  ✅ Configuration valid")
        
        # Test origin validation
        print(f"\n🔍 Testing origin validation:")
        
        dev_config = SecureCORSConfig(Environment.DEVELOPMENT)
        prod_config = SecureCORSConfig(Environment.PRODUCTION)
        
        test_cases = [
            (dev_config, "http://localhost:3000", True, "Development should allow localhost"),
            (prod_config, "http://localhost:3000", False, "Production should not allow localhost"),
            (prod_config, "https://claude-optimized-deployment.com", True, "Production should allow HTTPS domain"),
            (dev_config, "https://malicious-site.com", False, "Should reject unknown domains"),
            (prod_config, "*", False, "Should reject wildcard"),
        ]
        
        for config, origin, expected, description in test_cases:
            result = config.is_origin_allowed(origin)
            status = "✅" if result == expected else "❌"
            print(f"  {status} {description}: {origin} -> {result}")
            
            if result != expected:
                return False
        
        return True
    
    if __name__ == "__main__":
        print("🔒 CORS Configuration Basic Test")
        print("=" * 40)
        
        success = test_basic_functionality()
        
        if success:
            print(f"\n🎉 All CORS configuration tests PASSED!")
            sys.exit(0)
        else:
            print(f"\n❌ CORS configuration tests FAILED!")
            sys.exit(1)

except ImportError as e:
    print(f"❌ Could not import CORS configuration: {e}")
    print("This might be due to missing dependencies or import path issues.")
    sys.exit(1)
except Exception as e:
    print(f"❌ Test failed with error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
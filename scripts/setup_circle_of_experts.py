#!/usr/bin/env python3
"""
Setup script for Circle of Experts feature.

This script helps configure the Circle of Experts feature by:
1. Checking prerequisites
2. Setting up Google Drive authentication
3. Verifying folder permissions
4. Running initial tests
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Optional, Dict, Any

try:
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    print("Error: Google API client not installed.")
    print("Please run: pip install -r requirements.txt")
    sys.exit(1)


class CircleOfExpertsSetup:
    """Setup helper for Circle of Experts feature."""
    
    def __init__(self):
        self.config_path = Path.home() / ".code" / "circle_of_experts.json"
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
    
    def check_python_version(self) -> bool:
        """Check if Python version is 3.10+."""
        if sys.version_info < (3, 10):
            print(f"❌ Python 3.10+ required. Current: {sys.version}")
            return False
        print(f"✅ Python version: {sys.version.split()[0]}")
        return True
    
    def check_rust_installation(self) -> bool:
        """Check if Rust and maturin are installed."""
        try:
            # Check Rust
            result = subprocess.run(["rustc", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Rust installed: {result.stdout.strip()}")
            else:
                print("⚠️  Rust not installed (optional for performance)")
                return False
            
            # Check maturin
            result = subprocess.run(["maturin", "--version"], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ Maturin installed: {result.stdout.strip()}")
                return True
            else:
                print("⚠️  Maturin not installed. Run: pip install maturin")
                return False
                
        except FileNotFoundError:
            print("⚠️  Rust toolchain not found (optional for performance)")
            return False
    
    def setup_google_credentials(self) -> Optional[str]:
        """Set up Google Drive credentials."""
        print("\n📋 Google Drive Setup")
        print("-" * 40)
        
        # Check environment variable
        creds_path = os.getenv("GOOGLE_CREDENTIALS_PATH")
        if creds_path and Path(creds_path).exists():
            print(f"✅ Found credentials at: {creds_path}")
            return creds_path
        
        # Ask user for credentials path
        print("Please provide the path to your Google service account credentials JSON file.")
        print("You can create one at: https://console.cloud.google.com/apis/credentials")
        
        while True:
            creds_path = input("Credentials path (or 'skip' to skip): ").strip()
            
            if creds_path.lower() == 'skip':
                print("⚠️  Skipping Google Drive setup")
                return None
            
            if Path(creds_path).exists():
                # Validate credentials
                try:
                    credentials = service_account.Credentials.from_service_account_file(
                        creds_path,
                        scopes=['https://www.googleapis.com/auth/drive']
                    )
                    service = build('drive', 'v3', credentials=credentials)
                    
                    # Test API access
                    service.files().list(pageSize=1).execute()
                    
                    print("✅ Credentials validated successfully")
                    
                    # Save to config
                    config = self.load_config()
                    config['google_credentials_path'] = creds_path
                    self.save_config(config)
                    
                    # Set environment variable
                    os.environ["GOOGLE_CREDENTIALS_PATH"] = creds_path
                    print(f"✅ Set GOOGLE_CREDENTIALS_PATH environment variable")
                    
                    return creds_path
                    
                except Exception as e:
                    print(f"❌ Invalid credentials: {e}")
                    
            else:
                print(f"❌ File not found: {creds_path}")
    
    def verify_folder_access(self, credentials_path: str) -> bool:
        """Verify access to the Circle of Experts folder."""
        print("\n📁 Verifying Folder Access")
        print("-" * 40)
        
        try:
            credentials = service_account.Credentials.from_service_account_file(
                credentials_path,
                scopes=['https://www.googleapis.com/auth/drive']
            )
            service = build('drive', 'v3', credentials=credentials)
            
            # Default folder ID
            folder_id = "1ob-NYNWMXaE3oiyPzRAk2-VpNbMvfFMS"
            
            # Try to access the folder
            folder = service.files().get(fileId=folder_id, fields='name,mimeType').execute()
            
            if folder.get('mimeType') == 'application/vnd.google-apps.folder':
                print(f"✅ Found Circle of Experts folder: {folder.get('name')}")
                
                # Try to create a test file
                test_metadata = {
                    'name': 'test_access.txt',
                    'parents': [folder_id]
                }
                
                test_file = service.files().create(
                    body=test_metadata,
                    fields='id'
                ).execute()
                
                # Delete test file
                service.files().delete(fileId=test_file.get('id')).execute()
                
                print("✅ Write access confirmed")
                return True
            else:
                print("❌ Target is not a folder")
                return False
                
        except HttpError as e:
            if e.resp.status == 404:
                print("❌ Folder not found or not accessible")
                print("Please share the folder with your service account email")
            else:
                print(f"❌ API error: {e}")
            return False
            
        except Exception as e:
            print(f"❌ Error verifying folder access: {e}")
            return False
    
    def build_rust_extensions(self) -> bool:
        """Build Rust extensions for performance."""
        print("\n🦀 Building Rust Extensions")
        print("-" * 40)
        
        rust_dir = Path(__file__).parent.parent / "rust_core"
        if not rust_dir.exists():
            print("❌ Rust core directory not found")
            return False
        
        try:
            print("Building Rust extensions (this may take a moment)...")
            result = subprocess.run(
                ["maturin", "develop", "--release"],
                cwd=rust_dir,
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                print("✅ Rust extensions built successfully")
                return True
            else:
                print(f"❌ Build failed: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"⚠️  Could not build Rust extensions: {e}")
            print("The system will work without them, but with reduced performance")
            return False
    
    def run_tests(self) -> bool:
        """Run Circle of Experts tests."""
        print("\n🧪 Running Tests")
        print("-" * 40)
        
        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", 
                 "tests/circle_of_experts/test_circle_of_experts.py",
                 "-v", "--tb=short"],
                capture_output=True,
                text=True
            )
            
            print(result.stdout)
            
            if result.returncode == 0:
                print("✅ All tests passed")
                return True
            else:
                print("❌ Some tests failed")
                print(result.stderr)
                return False
                
        except Exception as e:
            print(f"❌ Could not run tests: {e}")
            return False
    
    def load_config(self) -> Dict[str, Any]:
        """Load configuration."""
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                return json.load(f)
        return {}
    
    def save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration."""
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def print_next_steps(self) -> None:
        """Print next steps for the user."""
        print("\n🎯 Next Steps")
        print("-" * 40)
        print("1. Review the example usage:")
        print("   python examples/circle_of_experts_usage.py")
        print("\n2. Read the documentation:")
        print("   src/circle_of_experts/README.md")
        print("\n3. Set up AI expert accounts:")
        print("   - Claude: via Anthropic API")
        print("   - GPT-4: via OpenAI API")
        print("   - Gemini: via Google AI API")
        print("   - Supergrok: via custom integration")
        print("\n4. Configure expert responders to monitor the Drive folder")
        print("\n5. Submit your first query!")
    
    def run(self) -> None:
        """Run the complete setup process."""
        print("🚀 Circle of Experts Setup")
        print("=" * 40)
        
        # Check Python version
        if not self.check_python_version():
            return
        
        # Check Rust (optional)
        has_rust = self.check_rust_installation()
        
        # Set up Google credentials
        creds_path = self.setup_google_credentials()
        
        if creds_path:
            # Verify folder access
            if self.verify_folder_access(creds_path):
                print("\n✅ Google Drive setup complete")
            else:
                print("\n⚠️  Could not verify folder access")
                print("Please ensure the folder is shared with your service account")
        
        # Build Rust extensions if available
        if has_rust:
            self.build_rust_extensions()
        
        # Run tests
        print("\nRunning tests to verify installation...")
        self.run_tests()
        
        # Print next steps
        self.print_next_steps()
        
        print("\n✨ Setup complete!")


if __name__ == "__main__":
    setup = CircleOfExpertsSetup()
    setup.run()

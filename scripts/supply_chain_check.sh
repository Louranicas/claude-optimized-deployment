#!/bin/bash
# Supply Chain Security Check

echo "Running supply chain security checks..."

# Check Python dependencies
echo "Checking Python dependencies..."
pip-audit --desc

# Check npm dependencies (if applicable)
if [ -f "package.json" ]; then
    echo "Checking npm dependencies..."
    npm audit
fi

# Check for known vulnerabilities
echo "Checking for known vulnerabilities..."
safety check

# Generate SBOM (Software Bill of Materials)
echo "Generating SBOM..."
pip-licenses --format=json > sbom_python.json

echo "Supply chain security check complete!"

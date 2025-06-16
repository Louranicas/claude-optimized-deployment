# Makefile for Sphinx documentation

# You can set these variables from the command line, and also
# from the environment for the first two.
SPHINXOPTS    ?= -W --keep-going
SPHINXBUILD  ?= sphinx-build
SOURCEDIR    = .
BUILDDIR     = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help clean html livehtml linkcheck doctest coverage install

# Install documentation dependencies
install:
	pip install -r requirements.txt

# Clean build directory
clean:
	@$(SPHINXBUILD) -M clean "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Build HTML documentation
html:
	@$(SPHINXBUILD) -M html "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
	@echo "Build finished. The HTML pages are in $(BUILDDIR)/html."

# Build and serve documentation with live reload
livehtml:
	@command -v sphinx-autobuild >/dev/null 2>&1 || { echo "Installing sphinx-autobuild..."; pip install sphinx-autobuild; }
	sphinx-autobuild "$(SOURCEDIR)" "$(BUILDDIR)/html" --host 0.0.0.0 --port 8080 --open-browser

# Check external links
linkcheck:
	@$(SPHINXBUILD) -M linkcheck "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Run doctests
doctest:
	@$(SPHINXBUILD) -M doctest "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Generate coverage report
coverage:
	@$(SPHINXBUILD) -M coverage "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Build PDF documentation
latexpdf:
	@$(SPHINXBUILD) -M latexpdf "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Build EPUB documentation
epub:
	@$(SPHINXBUILD) -M epub "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

# Check for warnings and errors
check:
	@$(SPHINXBUILD) -W -b html "$(SOURCEDIR)" "$(BUILDDIR)/html" $(SPHINXOPTS) $(O)

# Quick build without warnings as errors (for development)
dev:
	@$(SPHINXBUILD) -b html "$(SOURCEDIR)" "$(BUILDDIR)/html" $(SPHINXOPTS) $(O)

# Deploy to GitHub Pages (if configured)
deploy: html
	@echo "Deploying to GitHub Pages..."
	@if [ -d "$(BUILDDIR)/html/.git" ]; then \
		cd $(BUILDDIR)/html && \
		git add . && \
		git commit -m "Update documentation" && \
		git push; \
	else \
		echo "GitHub Pages not configured. Run 'make setup-deploy' first."; \
	fi

# Setup GitHub Pages deployment
setup-deploy:
	@echo "Setting up GitHub Pages deployment..."
	@cd $(BUILDDIR)/html && \
	git init && \
	git remote add origin https://github.com/your-org/claude-optimized-deployment.git && \
	git checkout -b gh-pages

# Generate OpenAPI documentation
openapi:
	@echo "Generating OpenAPI documentation..."
	@python -c "
import json
import yaml
with open('openapi.yaml', 'r') as f:
    spec = yaml.safe_load(f)
with open('_static/openapi.json', 'w') as f:
    json.dump(spec, f, indent=2)
print('OpenAPI JSON generated at _static/openapi.json')
"

# Validate OpenAPI specification
validate-openapi:
	@echo "Validating OpenAPI specification..."
	@python -c "
import yaml
import jsonschema
try:
    with open('openapi.yaml', 'r') as f:
        spec = yaml.safe_load(f)
    print('✓ OpenAPI specification is valid YAML')
    print(f'  - Title: {spec.get(\"info\", {}).get(\"title\", \"Unknown\")}')
    print(f'  - Version: {spec.get(\"info\", {}).get(\"version\", \"Unknown\")}')
    print(f'  - Paths: {len(spec.get(\"paths\", {}))}')
    print(f'  - Components: {len(spec.get(\"components\", {}).get(\"schemas\", {}))}')
except Exception as e:
    print(f'✗ OpenAPI specification validation failed: {e}')
    exit(1)
"

# Generate API client stubs
generate-clients:
	@echo "Generating API client stubs..."
	@command -v openapi-generator >/dev/null 2>&1 || { echo "OpenAPI Generator not found. Install with: npm install -g @openapitools/openapi-generator-cli"; exit 1; }
	openapi-generator generate -i openapi.yaml -g python -o clients/generated/python --additional-properties=packageName=code_client
	openapi-generator generate -i openapi.yaml -g javascript -o clients/generated/javascript
	@echo "Generated clients in clients/generated/"

# Run all quality checks
quality: validate-openapi linkcheck check
	@echo "All quality checks passed!"

# Development workflow
dev-watch: livehtml

# Production build with all checks
production: clean quality html
	@echo "Production documentation build complete!"

# Show build info
info:
	@echo "Sphinx build information:"
	@echo "  Source directory: $(SOURCEDIR)"
	@echo "  Build directory: $(BUILDDIR)"
	@echo "  Sphinx options: $(SPHINXOPTS)"
	@$(SPHINXBUILD) --version

# Create a new documentation page template
new-page:
	@read -p "Enter page name (e.g., 'advanced-usage'): " PAGE; \
	if [ -z "$$PAGE" ]; then echo "Page name cannot be empty"; exit 1; fi; \
	if [ -f "$$PAGE.rst" ]; then echo "Page $$PAGE.rst already exists"; exit 1; fi; \
	echo "Creating $$PAGE.rst..."; \
	cat > "$$PAGE.rst" << 'EOF'
# Replace this with your page title
====================
Page Title
====================

.. contents:: Table of Contents
   :depth: 2
   :local:

Introduction
============

Add your content here.

Examples
========

.. code-block:: python

   # Add code examples
   print("Hello, World!")

See Also
========

- :doc:`quickstart`
- :doc:`mcp-tools`
EOF
	echo "Created $$PAGE.rst. Don't forget to add it to index.rst!"

# Check documentation metrics
metrics:
	@echo "Documentation metrics:"
	@echo "  Total .rst files: $$(find . -name '*.rst' | wc -l)"
	@echo "  Total .md files: $$(find . -name '*.md' | wc -l)"
	@echo "  Total code blocks: $$(grep -r '.. code-block::' . | wc -l)"
	@echo "  Total images: $$(find . -name '*.png' -o -name '*.jpg' -o -name '*.svg' | wc -l)"
	@if [ -d "$(BUILDDIR)/html" ]; then \
		echo "  Generated HTML files: $$(find $(BUILDDIR)/html -name '*.html' | wc -l)"; \
		echo "  Build size: $$(du -sh $(BUILDDIR)/html | cut -f1)"; \
	fi

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
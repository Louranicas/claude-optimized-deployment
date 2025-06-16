# GitHub Actions Implementation Guide

## Overview

This guide provides detailed implementation patterns for GitHub Actions in the Claude-Optimized Deployment Engine (CODE) project.

## Workflow Structure

### 1. Basic CI Pipeline

```yaml
# .github/workflows/ci.yml
name: Continuous Integration

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  workflow_dispatch:

env:
  PYTHON_VERSION: '3.11'
  NODE_VERSION: '18'
  TERRAFORM_VERSION: '1.5.0'

jobs:
  # Job 1: Code Quality Checks
  quality:
    name: Code Quality
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for better analysis
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: ${{ env.PYTHON_VERSION }}
          cache: 'pip'
      
      - name: Cache dependencies
        uses: actions/cache@v3
        with:
          path: |
            ~/.cache/pip
            ~/.cache/pre-commit
          key: ${{ runner.os }}-pip-${{ hashFiles('**/requirements*.txt') }}
          restore-keys: |
            ${{ runner.os }}-pip-
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements-dev.txt
      
      - name: Run pre-commit hooks
        uses: pre-commit/action@v3.0.0
      
      - name: Run linting
        run: |
          # Python linting
          flake8 src/ tests/
          mypy src/
          
          # YAML linting
          yamllint .github/workflows/
      
      - name: Check code formatting
        run: |
          black --check src/ tests/
          isort --check-only src/ tests/

  # Job 2: Security Scanning
  security:
    name: Security Scan
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
          severity: 'CRITICAL,HIGH'
      
      - name: Upload Trivy scan results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
      
      - name: Run Bandit security linter
        run: |
          pip install bandit
          bandit -r src/ -f json -o bandit-report.json
      
      - name: Check for secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

  # Job 3: Testing
  test:
    name: Test Suite
    runs-on: ${{ matrix.os }}
    needs: [quality]
    
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: ['3.9', '3.10', '3.11']
        exclude:
          - os: windows-latest
            python-version: '3.9'
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python-version }}
          cache: 'pip'
      
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt
          pip install -r requirements-test.txt
      
      - name: Run unit tests
        run: |
          pytest tests/unit \
            --cov=src \
            --cov-report=xml \
            --cov-report=term-missing \
            --junit-xml=test-results.xml
      
      - name: Run integration tests
        if: matrix.os == 'ubuntu-latest'
        run: |
          pytest tests/integration \
            --cov=src \
            --cov-append \
            --cov-report=xml
      
      - name: Upload coverage reports
        if: matrix.os == 'ubuntu-latest' && matrix.python-version == '3.11'
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.xml
          flags: unittests
          name: codecov-umbrella
      
      - name: Upload test results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: test-results-${{ matrix.os }}-${{ matrix.python-version }}
          path: test-results.xml

  # Job 4: Build
  build:
    name: Build Artifacts
    runs-on: ubuntu-latest
    needs: [test, security]
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3
      
      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      
      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/${{ github.repository }}
          tags: |
            type=ref,event=branch
            type=ref,event=pr
            type=semver,pattern={{version}}
            type=sha
      
      - name: Build and push Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: ${{ github.event_name != 'pull_request' }}
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max
          build-args: |
            VERSION=${{ github.sha }}
            BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
```

### 2. Deployment Pipeline

```yaml
# .github/workflows/deploy.yml
name: Deploy to Cloud

on:
  push:
    branches: [main]
  workflow_dispatch:
    inputs:
      environment:
        description: 'Deployment environment'
        required: true
        type: choice
        options:
          - development
          - staging
          - production
      version:
        description: 'Version to deploy (leave empty for latest)'
        required: false

concurrency:
  group: deploy-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: false

jobs:
  # Job 1: Prepare Deployment
  prepare:
    name: Prepare Deployment
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.version.outputs.version }}
      environment: ${{ steps.env.outputs.environment }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Determine version
        id: version
        run: |
          if [ -n "${{ inputs.version }}" ]; then
            echo "version=${{ inputs.version }}" >> $GITHUB_OUTPUT
          else
            echo "version=${{ github.sha }}" >> $GITHUB_OUTPUT
          fi
      
      - name: Determine environment
        id: env
        run: |
          if [ -n "${{ inputs.environment }}" ]; then
            echo "environment=${{ inputs.environment }}" >> $GITHUB_OUTPUT
          elif [ "${{ github.ref }}" == "refs/heads/main" ]; then
            echo "environment=production" >> $GITHUB_OUTPUT
          else
            echo "environment=development" >> $GITHUB_OUTPUT
          fi

  # Job 2: Deploy Infrastructure
  infrastructure:
    name: Deploy Infrastructure
    runs-on: ubuntu-latest
    needs: prepare
    environment: ${{ needs.prepare.outputs.environment }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DEPLOY_ROLE }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: ${{ env.TERRAFORM_VERSION }}
          terraform_wrapper: false
      
      - name: Terraform Init
        working-directory: ./infrastructure
        run: |
          terraform init \
            -backend-config="key=${{ needs.prepare.outputs.environment }}/terraform.tfstate"
      
      - name: Terraform Plan
        id: plan
        working-directory: ./infrastructure
        run: |
          terraform plan \
            -var="environment=${{ needs.prepare.outputs.environment }}" \
            -var="version=${{ needs.prepare.outputs.version }}" \
            -out=tfplan
      
      - name: Terraform Apply
        if: github.ref == 'refs/heads/main' || github.event_name == 'workflow_dispatch'
        working-directory: ./infrastructure
        run: |
          terraform apply -auto-approve tfplan
      
      - name: Export outputs
        id: outputs
        working-directory: ./infrastructure
        run: |
          echo "cluster_endpoint=$(terraform output -raw cluster_endpoint)" >> $GITHUB_OUTPUT
          echo "app_url=$(terraform output -raw app_url)" >> $GITHUB_OUTPUT

  # Job 3: Deploy Application
  application:
    name: Deploy Application
    runs-on: ubuntu-latest
    needs: [prepare, infrastructure]
    environment: 
      name: ${{ needs.prepare.outputs.environment }}
      url: ${{ steps.deploy.outputs.app_url }}
    
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
      
      - name: Configure kubectl
        run: |
          aws eks update-kubeconfig \
            --region us-east-1 \
            --name code-${{ needs.prepare.outputs.environment }}
      
      - name: Deploy to Kubernetes
        id: deploy
        run: |
          # Apply Kubernetes manifests
          kubectl apply -k ./k8s/overlays/${{ needs.prepare.outputs.environment }}
          
          # Update image
          kubectl set image deployment/code-api \
            api=ghcr.io/${{ github.repository }}:${{ needs.prepare.outputs.version }} \
            -n code-${{ needs.prepare.outputs.environment }}
          
          # Wait for rollout
          kubectl rollout status deployment/code-api \
            -n code-${{ needs.prepare.outputs.environment }} \
            --timeout=10m
          
          # Get application URL
          APP_URL=$(kubectl get ingress code-api \
            -n code-${{ needs.prepare.outputs.environment }} \
            -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
          echo "app_url=https://${APP_URL}" >> $GITHUB_OUTPUT
      
      - name: Run smoke tests
        run: |
          # Wait for application to be ready
          for i in {1..30}; do
            if curl -s "${{ steps.deploy.outputs.app_url }}/health" | grep -q "ok"; then
              echo "Application is healthy"
              break
            fi
            echo "Waiting for application to be ready..."
            sleep 10
          done
          
          # Run smoke tests
          npm install -g newman
          newman run tests/postman/smoke-tests.json \
            --env-var "base_url=${{ steps.deploy.outputs.app_url }}"
```

### 3. Reusable Workflows

```yaml
# .github/workflows/reusable-terraform.yml
name: Reusable Terraform Workflow

on:
  workflow_call:
    inputs:
      environment:
        required: true
        type: string
      working-directory:
        required: false
        type: string
        default: './infrastructure'
      plan-only:
        required: false
        type: boolean
        default: false
    secrets:
      AWS_DEPLOY_ROLE:
        required: true

jobs:
  terraform:
    name: Terraform
    runs-on: ubuntu-latest
    environment: ${{ inputs.environment }}
    
    defaults:
      run:
        working-directory: ${{ inputs.working-directory }}
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_DEPLOY_ROLE }}
          aws-region: us-east-1
      
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
      
      - name: Terraform Init
        run: |
          terraform init \
            -backend-config="key=${{ inputs.environment }}/terraform.tfstate"
      
      - name: Terraform Validate
        run: terraform validate
      
      - name: Terraform Plan
        run: |
          terraform plan \
            -var="environment=${{ inputs.environment }}" \
            -out=tfplan
      
      - name: Terraform Apply
        if: inputs.plan-only == false
        run: terraform apply -auto-approve tfplan
```

### 4. Advanced Patterns

#### 4.1 Dynamic Matrix Generation

```yaml
# .github/workflows/dynamic-matrix.yml
name: Dynamic Matrix Build

on:
  push:
    paths:
      - 'services/**'

jobs:
  # Generate matrix based on changed services
  changes:
    name: Detect Changes
    runs-on: ubuntu-latest
    outputs:
      matrix: ${{ steps.set-matrix.outputs.matrix }}
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Get changed files
        id: changed-files
        uses: tj-actions/changed-files@v39
        with:
          dir_names: true
          dir_names_max_depth: 2
          files: |
            services/**
      
      - name: Generate matrix
        id: set-matrix
        run: |
          # Extract service names from changed directories
          services=$(echo '${{ steps.changed-files.outputs.all_changed_files }}' | \
            tr ' ' '\n' | \
            grep '^services/' | \
            cut -d'/' -f2 | \
            sort -u | \
            jq -R -s -c 'split("\n")[:-1]')
          
          echo "matrix=${services}" >> $GITHUB_OUTPUT
  
  # Build changed services
  build:
    name: Build Service
    needs: changes
    if: needs.changes.outputs.matrix != '[]'
    runs-on: ubuntu-latest
    
    strategy:
      matrix:
        service: ${{ fromJson(needs.changes.outputs.matrix) }}
    
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      
      - name: Build ${{ matrix.service }}
        run: |
          cd services/${{ matrix.service }}
          docker build -t ${{ matrix.service }}:latest .
```

#### 4.2 Approval Gates

```yaml
# .github/workflows/approval-deploy.yml
name: Production Deployment with Approval

on:
  workflow_dispatch:

jobs:
  plan:
    name: Plan Deployment
    runs-on: ubuntu-latest
    
    steps:
      - name: Generate deployment plan
        run: |
          echo "## Deployment Plan" >> $GITHUB_STEP_SUMMARY
          echo "- Version: ${{ github.sha }}" >> $GITHUB_STEP_SUMMARY
          echo "- Environment: Production" >> $GITHUB_STEP_SUMMARY
          echo "- Changes: 15 files" >> $GITHUB_STEP_SUMMARY
  
  approve:
    name: Manual Approval
    needs: plan
    runs-on: ubuntu-latest
    environment: production-approval
    
    steps:
      - name: Request approval
        run: echo "Deployment approved by ${{ github.actor }}"
  
  deploy:
    name: Deploy to Production
    needs: approve
    runs-on: ubuntu-latest
    environment: production
    
    steps:
      - name: Deploy application
        run: echo "Deploying to production..."
```

## Best Practices Implementation

### 1. Caching Strategy

```yaml
# Comprehensive caching example
- name: Cache Python dependencies
  uses: actions/cache@v3
  with:
    path: |
      ~/.cache/pip
      ~/.local/share/virtualenvs
      .venv
    key: ${{ runner.os }}-python-${{ hashFiles('**/requirements*.txt', '**/Pipfile.lock') }}
    restore-keys: |
      ${{ runner.os }}-python-

- name: Cache Node dependencies
  uses: actions/cache@v3
  with:
    path: |
      ~/.npm
      node_modules
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json', '**/yarn.lock') }}

- name: Cache Docker layers
  uses: actions/cache@v3
  with:
    path: /tmp/.buildx-cache
    key: ${{ runner.os }}-buildx-${{ github.sha }}
    restore-keys: |
      ${{ runner.os }}-buildx-
```

### 2. Error Handling

```yaml
- name: Deploy with retry
  uses: nick-invision/retry@v2
  with:
    timeout_minutes: 10
    max_attempts: 3
    retry_wait_seconds: 30
    command: |
      kubectl apply -f deployment.yaml
      kubectl rollout status deployment/myapp

- name: Rollback on failure
  if: failure()
  run: |
    echo "Deployment failed, initiating rollback..."
    kubectl rollout undo deployment/myapp
    
    # Notify team
    curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
      -H 'Content-type: application/json' \
      -d '{"text":"⚠️ Production deployment failed and was rolled back"}'
```

### 3. Notifications

```yaml
# Slack notification on failure
- name: Notify Slack on failure
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    text: |
      :x: Deployment Failed
      *Workflow:* ${{ github.workflow }}
      *Job:* ${{ github.job }}
      *Commit:* ${{ github.sha }}
      *Author:* ${{ github.actor }}
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}

# GitHub Issue on repeated failures
- name: Create issue on repeated failure
  if: failure() && github.run_attempt > 2
  uses: actions/github-script@v6
  with:
    script: |
      github.rest.issues.create({
        owner: context.repo.owner,
        repo: context.repo.repo,
        title: 'CI Pipeline Repeated Failure',
        body: `The CI pipeline has failed multiple times.
        
        **Workflow:** ${context.workflow}
        **Run:** ${context.runNumber}
        **Commit:** ${context.sha}
        
        Please investigate immediately.`,
        labels: ['bug', 'ci-failure', 'priority-high']
      })
```

---
*Implementation Guide Version: 1.0*
*Last Updated: May 30, 2025*

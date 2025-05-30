# Infrastructure Automation Commands Reference
**Purpose**: Essential commands for infrastructure deployment and monitoring  
**Context**: Adapted for CODE (Claude-Optimized Deployment Engine)

---

## 🚀 Service Health Monitoring

### Multi-Service Health Check (PowerShell)
```powershell
# Check multiple infrastructure services simultaneously
$services = @{
    8080='Web Server'
    5432='PostgreSQL'
    6379='Redis'
    9090='Prometheus'
    3000='Grafana'
    5000='API Gateway'
    8500='Consul'
}

$jobs = @()
$services.GetEnumerator() | ForEach-Object {
    $port = $_.Key
    $name = $_.Value
    $jobs += Start-Job -ScriptBlock {
        param($p,$n)
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $tcp.Connect('localhost', $p)
            $tcp.Close()
            @{Port=$p;Service=$n;Status='ACTIVE';ResponseTime='<1ms'}
        } catch {
            @{Port=$p;Service=$n;Status='DOWN';ResponseTime='N/A'}
        }
    } -ArgumentList $port,$name
}
Wait-Job $jobs | Out-Null
$results = $jobs | ForEach-Object { Receive-Job $_ }
$results | Format-Table -AutoSize

# Summary
$active = ($results | Where-Object { $_.Status -eq 'ACTIVE' }).Count
Write-Host "`nService Status: $active/$($services.Count) services active" -ForegroundColor $(if ($active -eq $services.Count) {'Green'} else {'Yellow'})
```

### Kubernetes Cluster Health (Bash)
```bash
#!/bin/bash
# Comprehensive K8s health check

echo "=== Kubernetes Cluster Health Check ==="
echo "Time: $(date)"

# Node status
echo -e "\n[Nodes]"
kubectl get nodes -o wide | grep -E "(Ready|NotReady)" | while read line; do
    if echo "$line" | grep -q "Ready"; then
        echo "✓ $line"
    else
        echo "✗ $line"
    fi
done

# Pod status by namespace
echo -e "\n[Pods by Namespace]"
for ns in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
    total=$(kubectl get pods -n $ns --no-headers 2>/dev/null | wc -l)
    running=$(kubectl get pods -n $ns --field-selector=status.phase=Running --no-headers 2>/dev/null | wc -l)
    if [ $total -gt 0 ]; then
        echo "$ns: $running/$total running"
    fi
done

# Service endpoints
echo -e "\n[Service Endpoints]"
kubectl get endpoints -A | grep -v "<none>" | tail -n +2
```

## 📊 Infrastructure Metrics Collection

### System Resource Monitoring
```powershell
# Collect infrastructure metrics for deployment decisions
function Get-InfrastructureMetrics {
    $metrics = @{}
    
    # CPU metrics
    $cpu = Get-WmiObject Win32_Processor
    $metrics['CPU'] = @{
        Cores = $cpu.NumberOfCores
        LogicalProcessors = $cpu.NumberOfLogicalProcessors
        LoadPercentage = $cpu.LoadPercentage
        MaxClockSpeed = $cpu.MaxClockSpeed
    }
    
    # Memory metrics
    $mem = Get-WmiObject Win32_OperatingSystem
    $metrics['Memory'] = @{
        TotalGB = [math]::Round($mem.TotalVisibleMemorySize/1MB,2)
        FreeGB = [math]::Round($mem.FreePhysicalMemory/1MB,2)
        UsedGB = [math]::Round(($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory)/1MB,2)
        PercentUsed = [math]::Round((($mem.TotalVisibleMemorySize - $mem.FreePhysicalMemory)/$mem.TotalVisibleMemorySize)*100,2)
    }
    
    # Disk metrics
    $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3"
    $metrics['Disks'] = $disks | ForEach-Object {
        @{
            Drive = $_.DeviceID
            TotalGB = [math]::Round($_.Size/1GB,2)
            FreeGB = [math]::Round($_.FreeSpace/1GB,2)
            PercentUsed = [math]::Round((($_.Size - $_.FreeSpace)/$_.Size)*100,2)
        }
    }
    
    # Network interfaces
    $metrics['Network'] = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name, LinkSpeed, MacAddress
    
    return $metrics
}

# Display metrics
$metrics = Get-InfrastructureMetrics
$metrics | ConvertTo-Json -Depth 3
```

## 🔧 Deployment Automation

### Parallel Deployment Script
```bash
#!/bin/bash
# Deploy multiple services in parallel

SERVICES=("web-app" "api-server" "worker-service" "cache-layer")
ENVIRONMENTS=("dev" "staging" "prod")

deploy_service() {
    local service=$1
    local env=$2
    echo "[$(date +%T)] Deploying $service to $env..."
    
    # Simulate deployment (replace with actual deployment commands)
    case $service in
        "web-app")
            kubectl apply -f k8s/$env/web-app.yaml -n $env
            ;;
        "api-server")
            kubectl apply -f k8s/$env/api-server.yaml -n $env
            ;;
        "worker-service")
            kubectl apply -f k8s/$env/worker-service.yaml -n $env
            ;;
        "cache-layer")
            kubectl apply -f k8s/$env/cache-layer.yaml -n $env
            ;;
    esac
    
    echo "[$(date +%T)] $service deployed to $env"
}

# Export function for parallel execution
export -f deploy_service

# Deploy to specific environment in parallel
deploy_to_env() {
    local env=$1
    echo "=== Deploying to $env environment ==="
    printf '%s\n' "${SERVICES[@]}" | parallel -j 4 deploy_service {} $env
}

# Main deployment
for env in "${ENVIRONMENTS[@]}"; do
    deploy_to_env $env
done
```

### Container Registry Management
```powershell
# Manage container images across registries
function Manage-ContainerImages {
    param(
        [string]$Action = "list", # list, push, pull, clean
        [string]$Registry = "localhost:5000",
        [string]$Tag = "latest"
    )
    
    switch ($Action) {
        "list" {
            # List all images in registry
            $response = Invoke-RestMethod -Uri "http://$Registry/v2/_catalog"
            $images = @()
            foreach ($repo in $response.repositories) {
                $tags = Invoke-RestMethod -Uri "http://$Registry/v2/$repo/tags/list"
                foreach ($tag in $tags.tags) {
                    $images += "$Registry/$repo:$tag"
                }
            }
            return $images
        }
        
        "push" {
            # Push images in parallel
            Get-ChildItem -Path "./docker" -Filter "Dockerfile.*" | ForEach-Object {
                $service = $_.Name -replace 'Dockerfile\.',''
                Start-Job -ScriptBlock {
                    param($svc, $reg, $tag)
                    docker build -f "docker/Dockerfile.$svc" -t "$reg/$svc:$tag" .
                    docker push "$reg/$svc:$tag"
                } -ArgumentList $service, $Registry, $Tag
            }
        }
        
        "clean" {
            # Clean old images
            docker images | Select-String $Registry | ForEach-Object {
                $image = ($_ -split '\s+')[0] + ':' + ($_ -split '\s+')[1]
                $created = [datetime]($_ -split '\s+')[4]
                if ((Get-Date) - $created -gt [timespan]::FromDays(30)) {
                    docker rmi $image
                }
            }
        }
    }
}
```

## 🔍 Infrastructure Discovery

### Service Discovery Script
```bash
#!/bin/bash
# Discover services and their dependencies

discover_services() {
    echo "=== Service Discovery ==="
    
    # Kubernetes services
    echo -e "\n[Kubernetes Services]"
    kubectl get services -A -o custom-columns=\
NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
TYPE:.spec.type,\
CLUSTER-IP:.spec.clusterIP,\
EXTERNAL-IP:.status.loadBalancer.ingress[0].ip,\
PORTS:.spec.ports[*].port
    
    # Docker containers
    echo -e "\n[Docker Containers]"
    docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}"
    
    # Network connections
    echo -e "\n[Active Network Connections]"
    netstat -tuln | grep LISTEN | grep -E ":(80|443|8080|3000|5000|9090|3306|5432|6379)\s"
}

# Dependency mapping
map_dependencies() {
    echo -e "\n=== Dependency Mapping ==="
    
    # Check service dependencies via environment variables
    for pod in $(kubectl get pods -A -o jsonpath='{.items[*].metadata.name}'); do
        ns=$(kubectl get pod $pod -A -o jsonpath='{.metadata.namespace}')
        echo -e "\nPod: $pod (namespace: $ns)"
        kubectl get pod $pod -n $ns -o jsonpath='{.spec.containers[*].env[?(@.name=~".*_SERVICE_.*")]}' | \
            jq -r '.name + "=" + .value' 2>/dev/null | sort | uniq
    done
}

discover_services
map_dependencies
```

## 📈 Performance Monitoring

### Real-time Performance Dashboard
```powershell
# Infrastructure performance monitoring
function Start-PerformanceMonitor {
    param(
        [int]$IntervalSeconds = 5,
        [int]$Duration = 60
    )
    
    $endTime = (Get-Date).AddSeconds($Duration)
    $results = @()
    
    while ((Get-Date) -lt $endTime) {
        Clear-Host
        Write-Host "=== Infrastructure Performance Monitor ===" -ForegroundColor Cyan
        Write-Host "Time: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Yellow
        
        # Collect metrics
        $metrics = @{
            Timestamp = Get-Date
            CPU = (Get-WmiObject Win32_Processor).LoadPercentage
            MemoryUsedGB = [math]::Round((Get-WmiObject Win32_OperatingSystem | ForEach-Object {($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/1MB}),2)
            DiskIOps = (Get-Counter "\PhysicalDisk(_Total)\Disk Transfers/sec").CounterSamples.CookedValue
            NetworkMbps = [math]::Round((Get-Counter "\Network Interface(*)\Bytes Total/sec" | Where-Object {$_.CounterSamples.InstanceName -notlike "*isatap*"}).CounterSamples.CookedValue / 1MB, 2)
        }
        
        # Display current metrics
        Write-Host "`nCurrent Metrics:" -ForegroundColor Green
        $metrics | Format-List
        
        # Store for analysis
        $results += $metrics
        
        # Show trend
        if ($results.Count -gt 1) {
            $avgCPU = ($results | Measure-Object -Property CPU -Average).Average
            $maxCPU = ($results | Measure-Object -Property CPU -Maximum).Maximum
            Write-Host "`nTrends:" -ForegroundColor Magenta
            Write-Host "Average CPU: $([math]::Round($avgCPU,2))%"
            Write-Host "Peak CPU: $maxCPU%"
        }
        
        Start-Sleep -Seconds $IntervalSeconds
    }
    
    return $results
}
```

## 🛡️ Security Scanning

### Infrastructure Security Audit
```bash
#!/bin/bash
# Comprehensive security audit for infrastructure

security_audit() {
    echo "=== Infrastructure Security Audit ==="
    echo "Date: $(date)"
    echo "Auditor: Automated Security Scanner"
    echo
    
    # Check for exposed services
    echo "[Exposed Services Check]"
    for port in 22 3306 5432 6379 9200 27017; do
        if netstat -tuln | grep -q ":$port "; then
            service=$(case $port in
                22) echo "SSH";;
                3306) echo "MySQL";;
                5432) echo "PostgreSQL";;
                6379) echo "Redis";;
                9200) echo "Elasticsearch";;
                27017) echo "MongoDB";;
            esac)
            echo "⚠️  $service (port $port) is exposed"
        fi
    done
    
    # Kubernetes security policies
    echo -e "\n[Kubernetes Security Policies]"
    kubectl get psp 2>/dev/null || echo "No Pod Security Policies found"
    kubectl get networkpolicies -A 2>/dev/null || echo "No Network Policies found"
    
    # Container vulnerabilities
    echo -e "\n[Container Vulnerability Scan]"
    for image in $(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v "<none>"); do
        echo "Scanning $image..."
        trivy image --severity HIGH,CRITICAL --no-progress "$image" 2>/dev/null | grep -E "(HIGH|CRITICAL)" | head -5
    done
    
    # SSL/TLS certificates
    echo -e "\n[SSL Certificate Status]"
    for domain in $(kubectl get ingress -A -o jsonpath='{.items[*].spec.rules[*].host}' 2>/dev/null); do
        echo -n "$domain: "
        echo | openssl s_client -servername $domain -connect $domain:443 2>/dev/null | \
            openssl x509 -noout -dates 2>/dev/null | grep notAfter | cut -d= -f2 || echo "No certificate found"
    done
}

security_audit
```

## 💾 Backup and Recovery

### Automated Backup Script
```powershell
# Infrastructure backup automation
function Start-InfrastructureBackup {
    param(
        [string]$BackupPath = "C:\Backups\Infrastructure",
        [string[]]$Components = @("kubernetes", "databases", "configs")
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $backupDir = Join-Path $BackupPath $timestamp
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    
    Write-Host "Starting infrastructure backup to $backupDir" -ForegroundColor Green
    
    # Parallel backup jobs
    $jobs = @()
    
    if ("kubernetes" -in $Components) {
        $jobs += Start-Job -ScriptBlock {
            param($dir)
            # Backup Kubernetes resources
            kubectl get all,cm,secret,pv,pvc -A -o yaml > "$dir\kubernetes-resources.yaml"
            # Backup etcd
            kubectl exec -n kube-system etcd-master -it -- etcdctl snapshot save /tmp/etcd-backup
            kubectl cp kube-system/etcd-master:/tmp/etcd-backup "$dir\etcd-backup.db"
        } -ArgumentList $backupDir
    }
    
    if ("databases" -in $Components) {
        $jobs += Start-Job -ScriptBlock {
            param($dir)
            # Backup PostgreSQL
            docker exec postgres pg_dumpall -U postgres > "$dir\postgres-backup.sql"
            # Backup Redis
            docker exec redis redis-cli BGSAVE
            docker cp redis:/data/dump.rdb "$dir\redis-backup.rdb"
        } -ArgumentList $backupDir
    }
    
    if ("configs" -in $Components) {
        $jobs += Start-Job -ScriptBlock {
            param($dir)
            # Backup configuration files
            Copy-Item -Path "C:\ProgramData\Docker\config" -Destination "$dir\docker-config" -Recurse
            Copy-Item -Path "$env:USERPROFILE\.kube" -Destination "$dir\kube-config" -Recurse
        } -ArgumentList $backupDir
    }
    
    # Wait for all backups to complete
    Wait-Job $jobs | Out-Null
    $jobs | ForEach-Object {
        $result = Receive-Job $_
        Remove-Job $_
    }
    
    Write-Host "Backup completed successfully!" -ForegroundColor Green
    return $backupDir
}
```

---

## 🎯 Key Takeaways for Infrastructure Automation

1. **Parallel Execution**: Always consider parallel processing for multi-target operations
2. **Health Monitoring**: Implement comprehensive health checks across all services
3. **Security First**: Regular security audits and vulnerability scanning
4. **Automation**: Script repetitive tasks for consistency and efficiency
5. **Observability**: Collect metrics to make informed deployment decisions

---

*Adapted from The Watcher's command collection for infrastructure deployment*

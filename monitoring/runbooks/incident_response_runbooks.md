# MCP Server Incident Response Runbooks

## Table of Contents

1. [Server Down Incident](#server-down-incident)
2. [Performance Degradation](#performance-degradation)
3. [Security Incident Response](#security-incident-response)
4. [Memory Leak Investigation](#memory-leak-investigation)
5. [Dependency Failure Response](#dependency-failure-response)
6. [Data Corruption Response](#data-corruption-response)

---

## Server Down Incident

### Alert: MCPServerDown
**Severity**: Critical  
**Response Time**: < 5 minutes  
**Alert Query**: `mcp_server_up == 0`

### Immediate Response (0-5 minutes)

1. **Acknowledge the Alert**
   ```bash
   # Acknowledge in monitoring system
   curl -X POST http://alertmanager:9093/api/v1/alerts \
     -H "Content-Type: application/json" \
     -d '{"status": "acknowledged", "receiver": "oncall"}'
   ```

2. **Verify Server Status**
   ```bash
   # Check if server process is running
   ps aux | grep mcp-server-${SERVER_NAME}
   
   # Check service status
   systemctl status mcp-server-${SERVER_NAME}
   
   # Test connectivity
   curl -f http://localhost:${PORT}/health || echo "Server unreachable"
   ```

3. **Quick Diagnostics**
   ```bash
   # Check system resources
   top -bn1 | head -20
   df -h
   free -h
   
   # Check recent logs
   journalctl -u mcp-server-${SERVER_NAME} -n 20 --no-pager
   tail -50 /var/log/mcp-servers/${SERVER_NAME}.log
   ```

### Investigation Phase (5-15 minutes)

4. **Analyze Failure Cause**
   ```bash
   # Check for OOM kills
   dmesg | grep -i "killed process"
   journalctl --since "30 minutes ago" | grep -i "out of memory"
   
   # Check for disk space issues
   df -h /tmp /var/log /var/lib
   
   # Check for port conflicts
   netstat -tulpn | grep ${PORT}
   
   # Examine detailed logs
   journalctl -u mcp-server-${SERVER_NAME} --since "1 hour ago" | grep -E "(ERROR|FATAL|Exception)"
   ```

5. **Check Dependencies**
   ```bash
   # Database connectivity (if applicable)
   pg_isready -h localhost -p 5432
   
   # External API connectivity
   curl -I https://api.github.com
   curl -I https://api.search.brave.com
   
   # File system permissions
   ls -la /tmp /var/log/mcp-servers
   ```

### Recovery Actions (15-30 minutes)

6. **Attempt Service Recovery**
   ```bash
   # Clear temporary files if disk space issue
   if [ $(df / | tail -1 | awk '{print $5}' | sed 's/%//') -gt 90 ]; then
     find /tmp -type f -atime +1 -delete
     find /var/log -name "*.log.*" -mtime +7 -delete
   fi
   
   # Restart the service
   systemctl restart mcp-server-${SERVER_NAME}
   
   # Wait for startup
   sleep 30
   
   # Verify recovery
   systemctl is-active mcp-server-${SERVER_NAME}
   curl -f http://localhost:${PORT}/health
   ```

7. **Post-Recovery Verification**
   ```bash
   # Run comprehensive health check
   python3 /monitoring/mcp_health_checks.py --server ${SERVER_NAME} --check-type readiness
   
   # Verify dependencies
   python3 /monitoring/mcp_health_checks.py --server ${SERVER_NAME} --check-type dependency
   
   # Check performance metrics
   python3 /monitoring/mcp_metrics_collector.py --server ${SERVER_NAME}
   ```

### Escalation Criteria

- Service fails to restart after 2 attempts
- Multiple servers affected simultaneously
- Evidence of security compromise
- Data corruption suspected

### Documentation Requirements

- Record all commands executed
- Document error messages encountered
- Note any configuration changes made
- Update incident log with timeline

---

## Performance Degradation

### Alert: MCPSlowResponseTime
**Severity**: Warning  
**Response Time**: < 15 minutes  
**Alert Query**: `histogram_quantile(0.95, rate(mcp_request_duration_seconds_bucket[5m])) > 5.0`

### Initial Assessment (0-10 minutes)

1. **Verify Performance Impact**
   ```bash
   # Check current response times
   curl -w "@curl-format.txt" -s -o /dev/null http://localhost:${PORT}/health
   
   # Check system load
   uptime
   top -bn1 | head -10
   
   # Monitor active connections
   ss -tuln | grep ${PORT}
   ```

2. **Analyze Resource Utilization**
   ```bash
   # CPU usage by process
   ps aux --sort=-%cpu | head -10
   
   # Memory usage
   ps aux --sort=-%mem | head -10
   free -h
   
   # I/O statistics
   iostat -x 1 3
   
   # Network statistics
   sar -n DEV 1 3
   ```

### Root Cause Investigation (10-30 minutes)

3. **Application-Level Analysis**
   ```bash
   # Check concurrent operations
   python3 -c "
   import requests
   r = requests.get('http://localhost:${PORT}/metrics')
   for line in r.text.split('\n'):
       if 'mcp_concurrent_operations' in line:
           print(line)
   "
   
   # Analyze request patterns
   tail -100 /var/log/mcp-servers/${SERVER_NAME}.log | grep -E "(request|response)" | tail -20
   
   # Check for blocking operations
   jstack $(pgrep -f mcp-server-${SERVER_NAME}) | grep -A 5 "BLOCKED"
   ```

4. **Database Performance (if applicable)**
   ```bash
   # Check database connections
   psql -c "SELECT count(*) FROM pg_stat_activity WHERE state = 'active';"
   
   # Identify slow queries
   psql -c "SELECT query, state, query_start FROM pg_stat_activity WHERE state != 'idle' ORDER BY query_start;"
   
   # Check locks
   psql -c "SELECT * FROM pg_locks WHERE NOT granted;"
   ```

5. **Cache Performance Analysis**
   ```bash
   # Check cache hit rates
   python3 -c "
   import requests
   r = requests.get('http://localhost:${PORT}/metrics')
   for line in r.text.split('\n'):
       if 'cache_hit_rate' in line:
           print(line)
   "
   
   # Memory cache usage
   free -h
   cat /proc/meminfo | grep -E "(Cached|Buffers)"
   ```

### Optimization Actions (30-60 minutes)

6. **Immediate Performance Improvements**
   ```bash
   # Increase JVM heap if memory constrained
   if [ $(free | grep Mem | awk '{print $3/$2 * 100.0}' | cut -d. -f1) -gt 80 ]; then
     echo "Considering memory optimization"
     # Update JVM settings in service configuration
   fi
   
   # Clear unnecessary processes
   pkill -f "defunct"
   
   # Optimize kernel parameters
   echo 'vm.swappiness=10' >> /etc/sysctl.conf
   sysctl -p
   ```

7. **Application Tuning**
   ```bash
   # Restart service with optimized settings
   systemctl stop mcp-server-${SERVER_NAME}
   
   # Update configuration for better performance
   # (This would involve editing service-specific config files)
   
   systemctl start mcp-server-${SERVER_NAME}
   
   # Monitor improvement
   for i in {1..10}; do
     curl -w "Response time: %{time_total}s\n" -s -o /dev/null http://localhost:${PORT}/health
     sleep 5
   done
   ```

### Monitoring and Follow-up

8. **Continuous Monitoring**
   ```bash
   # Set up enhanced monitoring
   python3 /monitoring/mcp_metrics_collector.py --server ${SERVER_NAME} --continuous --interval 10 &
   
   # Monitor for 30 minutes
   sleep 1800
   
   # Generate performance report
   python3 /monitoring/mcp_metrics_collector.py --server ${SERVER_NAME} --output summary
   ```

---

## Security Incident Response

### Alert: MCPSecurityIncident
**Severity**: Critical  
**Response Time**: < 2 minutes  
**Alert Query**: `increase(mcp_server_errors_total{error_type="security"}[5m]) > 0`

### Immediate Response (0-5 minutes)

1. **Alert Acknowledgment and Initial Assessment**
   ```bash
   # Acknowledge critical security alert
   echo "$(date): Security incident detected on ${SERVER_NAME}" >> /var/log/security-incidents.log
   
   # Check for active threats
   netstat -an | grep ESTABLISHED | grep ${PORT}
   
   # Check recent authentication attempts
   journalctl --since "10 minutes ago" | grep -E "(auth|login|fail)"
   ```

2. **Immediate Containment**
   ```bash
   # Block suspicious connections if identified
   # (Replace ${SUSPICIOUS_IP} with actual IP)
   # iptables -A INPUT -s ${SUSPICIOUS_IP} -j DROP
   
   # Monitor active connections
   ss -tuln | grep ${PORT}
   lsof -i :${PORT}
   
   # Check for unusual processes
   ps aux | grep -v grep | grep -E "(nc|ncat|netcat|bash|sh)" | grep -v normal_processes
   ```

### Evidence Collection (5-20 minutes)

3. **Log Collection**
   ```bash
   # Create incident directory
   INCIDENT_DIR="/var/log/security-incidents/$(date +%Y%m%d_%H%M%S)_${SERVER_NAME}"
   mkdir -p ${INCIDENT_DIR}
   
   # Collect system logs
   journalctl --since "1 hour ago" > ${INCIDENT_DIR}/system_logs.log
   
   # Collect application logs
   cp /var/log/mcp-servers/${SERVER_NAME}.log ${INCIDENT_DIR}/
   
   # Collect security logs
   python3 /monitoring/mcp_logging.py --search "security" --level ERROR > ${INCIDENT_DIR}/security_events.json
   
   # Network connections
   netstat -tulpn > ${INCIDENT_DIR}/network_connections.txt
   ss -tuln > ${INCIDENT_DIR}/socket_stats.txt
   ```

4. **System State Capture**
   ```bash
   # Running processes
   ps auxf > ${INCIDENT_DIR}/process_list.txt
   
   # Open files
   lsof > ${INCIDENT_DIR}/open_files.txt
   
   # Memory dump (if necessary and feasible)
   # gcore $(pgrep mcp-server-${SERVER_NAME})
   
   # File system integrity check
   find /etc -type f -name "*.conf" -newer $(date -d "1 hour ago" +%Y%m%d%H%M) > ${INCIDENT_DIR}/recent_config_changes.txt
   ```

### Analysis Phase (20-60 minutes)

5. **Attack Vector Analysis**
   ```bash
   # Analyze authentication logs
   grep -E "(Failed|failed|FAILED)" ${INCIDENT_DIR}/system_logs.log > ${INCIDENT_DIR}/auth_failures.txt
   
   # Check for privilege escalation
   grep -E "(sudo|su |elevation)" ${INCIDENT_DIR}/system_logs.log > ${INCIDENT_DIR}/privilege_events.txt
   
   # Analyze network traffic patterns
   # (If network monitoring is available)
   # tcpdump -r /var/log/network/capture.pcap -nn | grep ${PORT} > ${INCIDENT_DIR}/network_analysis.txt
   ```

6. **Impact Assessment**
   ```bash
   # Check file modifications
   find /var/lib/mcp-servers -type f -newer $(date -d "1 hour ago" +%Y%m%d%H%M) > ${INCIDENT_DIR}/modified_files.txt
   
   # Check for data exfiltration signs
   du -sh /var/lib/mcp-servers/* | sort -hr > ${INCIDENT_DIR}/data_sizes.txt
   
   # Verify data integrity
   # (Run checksums if available)
   # md5sum /var/lib/mcp-servers/critical_files/* > ${INCIDENT_DIR}/file_checksums.txt
   ```

### Recovery and Remediation (1-4 hours)

7. **System Hardening**
   ```bash
   # Update passwords and keys
   # (Following organization's security procedures)
   
   # Apply security patches
   apt update && apt upgrade -y
   
   # Restart with enhanced security
   systemctl stop mcp-server-${SERVER_NAME}
   
   # Update security configuration
   # (Edit configuration files to enhance security)
   
   systemctl start mcp-server-${SERVER_NAME}
   ```

8. **Monitoring Enhancement**
   ```bash
   # Enable additional security logging
   echo "security.audit=enhanced" >> /etc/mcp-server/${SERVER_NAME}.conf
   
   # Set up intrusion detection
   # (Configure IDS rules specific to the attack vector)
   
   # Increase monitoring frequency
   python3 /monitoring/mcp_health_checks.py --continuous --interval 10 &
   ```

### Post-Incident Activities

9. **Documentation and Reporting**
   ```bash
   # Generate incident report
   cat > ${INCIDENT_DIR}/incident_report.md << EOF
   # Security Incident Report
   
   **Date**: $(date)
   **Server**: ${SERVER_NAME}
   **Severity**: Critical
   **Status**: Resolved
   
   ## Timeline
   - $(date): Incident detected
   - $(date): Containment implemented
   - $(date): Analysis completed
   - $(date): System restored
   
   ## Impact Assessment
   [To be filled based on analysis]
   
   ## Root Cause
   [To be determined]
   
   ## Remediation Actions
   [List all actions taken]
   
   ## Lessons Learned
   [To be completed in post-mortem]
   EOF
   ```

---

## Memory Leak Investigation

### Alert: MCPHighMemoryUsage
**Severity**: Warning  
**Response Time**: < 30 minutes  
**Alert Query**: `mcp_server_memory_usage_bytes / 1024 / 1024 / 1024 > 2.0`

### Initial Memory Analysis (0-15 minutes)

1. **Memory Usage Baseline**
   ```bash
   # Current memory usage
   free -h
   cat /proc/meminfo | grep -E "(MemTotal|MemAvailable|MemFree)"
   
   # Process-specific memory usage
   ps aux --sort=-%mem | head -20
   pmap -x $(pgrep mcp-server-${SERVER_NAME})
   
   # Memory usage history
   sar -r 1 5
   ```

2. **Application Memory Analysis**
   ```bash
   # JVM heap usage (if Java application)
   PID=$(pgrep mcp-server-${SERVER_NAME})
   if [ ! -z "$PID" ]; then
     jstat -gc $PID
     jmap -histo $PID | head -30
   fi
   
   # Memory maps
   cat /proc/$PID/smaps | grep -E "(Size|Rss|Pss)"
   
   # Check for memory growth pattern
   for i in {1..10}; do
     echo "$(date): $(ps -o pid,vsz,rss,comm -p $PID)"
     sleep 60
   done
   ```

### Memory Leak Detection (15-45 minutes)

3. **Heap Analysis**
   ```bash
   # Generate heap dump
   PID=$(pgrep mcp-server-${SERVER_NAME})
   jmap -dump:format=b,file=/tmp/heapdump_$(date +%Y%m%d_%H%M%S).hprof $PID
   
   # Analyze heap usage patterns
   jstat -gccapacity $PID
   jstat -gcutil $PID 5s 12
   
   # Check for memory pools
   jcmd $PID VM.memory_pools
   ```

4. **Memory Growth Analysis**
   ```bash
   # Monitor memory growth over time
   cat > /tmp/memory_monitor.sh << 'EOF'
   #!/bin/bash
   PID=$1
   for i in {1..60}; do
     RSS=$(ps -o rss= -p $PID)
     VSZ=$(ps -o vsz= -p $PID)
     echo "$(date +%H:%M:%S): RSS=${RSS}KB VSZ=${VSZ}KB"
     sleep 60
   done
   EOF
   
   chmod +x /tmp/memory_monitor.sh
   /tmp/memory_monitor.sh $(pgrep mcp-server-${SERVER_NAME}) > /tmp/memory_growth.log &
   ```

### Investigation and Mitigation (45-90 minutes)

5. **Identify Memory Consumers**
   ```bash
   # Analyze application logs for memory-related events
   grep -E "(OutOfMemory|memory|heap|GC)" /var/log/mcp-servers/${SERVER_NAME}.log | tail -50
   
   # Check for large object allocations
   jstat -gccause $(pgrep mcp-server-${SERVER_NAME})
   
   # Monitor garbage collection
   jstat -gc $(pgrep mcp-server-${SERVER_NAME}) 5s | head -20
   ```

6. **Temporary Mitigation**
   ```bash
   # Force garbage collection (if applicable)
   PID=$(pgrep mcp-server-${SERVER_NAME})
   jcmd $PID GC.run_finalization
   jcmd $PID GC.run
   
   # Clear application caches if safe
   curl -X POST http://localhost:${PORT}/admin/clear-cache
   
   # Monitor improvement
   sleep 30
   free -h
   ps aux | grep mcp-server-${SERVER_NAME}
   ```

7. **Long-term Solution**
   ```bash
   # Increase JVM heap size temporarily
   systemctl stop mcp-server-${SERVER_NAME}
   
   # Edit service configuration to increase memory
   sed -i 's/-Xmx[0-9]*[gG]/-Xmx4g/' /etc/systemd/system/mcp-server-${SERVER_NAME}.service
   
   systemctl daemon-reload
   systemctl start mcp-server-${SERVER_NAME}
   
   # Monitor memory usage post-restart
   watch -n 30 "ps aux | grep mcp-server-${SERVER_NAME}"
   ```

---

## Dependency Failure Response

### Alert: MCPDependencyDown
**Severity**: Critical  
**Response Time**: < 10 minutes  
**Alert Query**: `mcp_server_dependency_status == 0`

### Dependency Identification (0-5 minutes)

1. **Identify Failed Dependency**
   ```bash
   # Check dependency status
   python3 /monitoring/mcp_health_checks.py --server ${SERVER_NAME} --check-type dependency
   
   # List all dependencies for server
   python3 -c "
   import json
   with open('/monitoring/mcp_health_checks.py') as f:
       # Extract dependency configuration
       pass
   "
   ```

2. **Quick Dependency Tests**
   ```bash
   # Database dependency
   if [[ "${DEPENDENCY}" == *"postgres"* ]]; then
     pg_isready -h localhost -p 5432
     psql -c 'SELECT 1;' 2>/dev/null && echo "DB OK" || echo "DB FAILED"
   fi
   
   # HTTP API dependency
   if [[ "${DEPENDENCY}" == *"api"* ]]; then
     curl -I --max-time 10 ${API_ENDPOINT}
   fi
   
   # File system dependency
   if [[ "${DEPENDENCY}" == *"file"* ]]; then
     ls -la ${FILE_PATH}
     df -h ${MOUNT_POINT}
   fi
   ```

### Dependency Recovery (5-20 minutes)

3. **Database Recovery**
   ```bash
   # PostgreSQL recovery
   if [[ "${DEPENDENCY}" == *"postgres"* ]]; then
     systemctl status postgresql
     
     # Restart if not running
     if ! systemctl is-active postgresql; then
       systemctl restart postgresql
       sleep 10
       pg_isready -h localhost -p 5432
     fi
     
     # Check disk space
     df -h /var/lib/postgresql
     
     # Check connections
     psql -c "SELECT count(*) FROM pg_stat_activity;"
   fi
   ```

4. **External API Recovery**
   ```bash
   # API dependency recovery
   if [[ "${DEPENDENCY}" == *"api"* ]]; then
     # Check network connectivity
     ping -c 3 $(echo ${API_ENDPOINT} | cut -d'/' -f3)
     
     # Check DNS resolution
     nslookup $(echo ${API_ENDPOINT} | cut -d'/' -f3)
     
     # Test with different endpoints
     curl -I --max-time 10 ${BACKUP_ENDPOINT}
     
     # Check for rate limiting
     curl -I ${API_ENDPOINT} | grep -i "rate\|limit"
   fi
   ```

5. **File System Recovery**
   ```bash
   # File system dependency recovery
   if [[ "${DEPENDENCY}" == *"file"* ]]; then
     # Check mount status
     mount | grep ${MOUNT_POINT}
     
     # Check permissions
     ls -la ${FILE_PATH}
     
     # Check disk space
     df -h ${MOUNT_POINT}
     
     # Attempt to remount if needed
     if ! mount | grep -q ${MOUNT_POINT}; then
       mount ${MOUNT_POINT}
     fi
     
     # Create missing directories
     mkdir -p ${REQUIRED_DIRECTORIES}
     chown mcp-user:mcp-group ${REQUIRED_DIRECTORIES}
   fi
   ```

### Service Recovery (20-30 minutes)

6. **MCP Server Recovery**
   ```bash
   # Restart MCP server after dependency recovery
   systemctl restart mcp-server-${SERVER_NAME}
   
   # Wait for startup
   sleep 30
   
   # Verify health
   curl -f http://localhost:${PORT}/health
   
   # Run full dependency check
   python3 /monitoring/mcp_health_checks.py --server ${SERVER_NAME} --check-type readiness
   ```

7. **Monitoring and Verification**
   ```bash
   # Enhanced monitoring for next hour
   python3 /monitoring/mcp_health_checks.py --continuous --interval 30 &
   MONITOR_PID=$!
   
   # Monitor for 1 hour then stop
   sleep 3600
   kill $MONITOR_PID
   
   # Generate recovery report
   python3 /monitoring/mcp_metrics_collector.py --server ${SERVER_NAME} --output summary
   ```

---

## Data Corruption Response

### Alert: Data integrity check failed
**Severity**: Critical  
**Response Time**: < 5 minutes

### Immediate Assessment (0-10 minutes)

1. **Stop Data Modifications**
   ```bash
   # Put server in read-only mode if possible
   curl -X POST http://localhost:${PORT}/admin/readonly-mode
   
   # Stop write operations
   systemctl stop mcp-server-${SERVER_NAME}
   ```

2. **Assess Corruption Scope**
   ```bash
   # Check file system integrity
   fsck -n /dev/${DATA_DEVICE}
   
   # Check database integrity (if applicable)
   if [[ "${SERVER_NAME}" == *"postgres"* ]]; then
     su - postgres -c "pg_dump --schema-only ${DATABASE_NAME} > /tmp/schema_check.sql"
   fi
   
   # Verify backup integrity
   ls -la /backup/${SERVER_NAME}/*
   ```

### Data Recovery (10-60 minutes)

3. **Restore from Backup**
   ```bash
   # Identify latest good backup
   LATEST_BACKUP=$(ls -t /backup/${SERVER_NAME}/ | head -1)
   echo "Latest backup: ${LATEST_BACKUP}"
   
   # Verify backup integrity
   if [[ "${LATEST_BACKUP}" == *.tar.gz ]]; then
     tar -tzf /backup/${SERVER_NAME}/${LATEST_BACKUP} > /dev/null
   fi
   
   # Stop all services accessing the data
   systemctl stop mcp-server-${SERVER_NAME}
   
   # Restore data
   cd /var/lib/mcp-servers/${SERVER_NAME}
   cp -r data data.corrupted.$(date +%Y%m%d_%H%M%S)
   tar -xzf /backup/${SERVER_NAME}/${LATEST_BACKUP}
   ```

4. **Data Validation**
   ```bash
   # Validate restored data
   if [[ "${SERVER_NAME}" == *"postgres"* ]]; then
     systemctl start postgresql
     su - postgres -c "psql -c '\dt' ${DATABASE_NAME}"
   fi
   
   # Check file integrity
   find /var/lib/mcp-servers/${SERVER_NAME} -type f -exec file {} \; | grep -v "ASCII\|UTF-8\|data"
   
   # Verify checksums if available
   if [ -f /backup/${SERVER_NAME}/checksums.md5 ]; then
     cd /var/lib/mcp-servers/${SERVER_NAME}
     md5sum -c /backup/${SERVER_NAME}/checksums.md5
   fi
   ```

### Service Restoration (60-90 minutes)

5. **Gradual Service Restoration**
   ```bash
   # Start in safe mode
   systemctl start mcp-server-${SERVER_NAME}
   
   # Verify basic functionality
   curl -f http://localhost:${PORT}/health
   
   # Test read operations
   curl -f http://localhost:${PORT}/api/test-read
   
   # Enable write operations gradually
   curl -X POST http://localhost:${PORT}/admin/enable-writes
   ```

6. **Data Integrity Monitoring**
   ```bash
   # Set up enhanced monitoring
   python3 /monitoring/data_integrity_monitor.py --server ${SERVER_NAME} &
   
   # Schedule regular integrity checks
   echo "0 */6 * * * /monitoring/data_integrity_check.sh ${SERVER_NAME}" | crontab -
   
   # Generate recovery report
   cat > /var/log/data-recovery-$(date +%Y%m%d_%H%M%S).log << EOF
   Data corruption incident for ${SERVER_NAME}
   Detected: $(date)
   Backup used: ${LATEST_BACKUP}
   Data loss: [To be assessed]
   Recovery time: [To be calculated]
   EOF
   ```

---

## Common Commands Reference

### System Status Commands
```bash
# System health
uptime
free -h
df -h
iostat -x 1 3

# Process monitoring
ps aux --sort=-%cpu | head -10
ps aux --sort=-%mem | head -10
top -bn1

# Network monitoring
netstat -tulpn
ss -tuln
sar -n DEV 1 3
```

### MCP-Specific Commands
```bash
# Health checks
python3 /monitoring/mcp_health_checks.py --server ${SERVER_NAME}

# Metrics collection
python3 /monitoring/mcp_metrics_collector.py --server ${SERVER_NAME}

# Log analysis
python3 /monitoring/mcp_logging.py --search "${QUERY}" --server ${SERVER_NAME}

# Tracing
python3 /monitoring/mcp_tracing.py --demo
```

### Emergency Contacts
- **Primary On-Call**: [PagerDuty/Phone]
- **Security Team**: security@company.com
- **Database Team**: dba@company.com
- **Network Operations**: netops@company.com

---

**Document Version**: 1.0  
**Last Updated**: $(date)  
**Review Schedule**: Monthly  
**Owner**: DevOps Team
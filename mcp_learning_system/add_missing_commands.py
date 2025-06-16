#!/usr/bin/env python3
"""
Add missing commands to reach 850+ total commands
Focus on security_monitoring and devops_pipeline categories
"""

import re

# Define the additional commands to add
ADDITIONAL_COMMANDS = """
            # SECURITY MONITORING COMMANDS (100+ commands)
            {
                "id": "sec_audit_login_attempts",
                "name": "Audit Failed Login Attempts",
                "description": "Monitor and analyze failed login attempts from auth logs",
                "command_template": "grep 'Failed password' /var/log/auth.log | tail -n {count} | awk '{{print $1,$2,$3,$11}}'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "count", "type": "int", "default": 50}],
                "examples": ["grep 'Failed password' /var/log/auth.log | tail -n 50"],
                "performance_hints": ["Use journalctl for systemd systems", "Index logs for faster searches"],
                "dependencies": ["grep", "awk"]
            },
            {
                "id": "sec_audit_sudo_usage",
                "name": "Audit Sudo Command Usage",
                "description": "Track and analyze sudo command execution history",
                "command_template": "grep 'sudo:' /var/log/auth.log | grep 'COMMAND' | tail -n {count}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "count", "type": "int", "default": 100}],
                "examples": ["grep 'sudo:' /var/log/auth.log | grep 'COMMAND'"],
                "performance_hints": ["Monitor in real-time with tail -f", "Alert on suspicious patterns"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_detect_port_scan",
                "name": "Detect Port Scanning Activity",
                "description": "Identify potential port scanning attempts from network logs",
                "command_template": "netstat -an | grep 'SYN_RECV' | awk '{{print $5}}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -n {top}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "top", "type": "int", "default": 10}],
                "examples": ["netstat -an | grep 'SYN_RECV'"],
                "performance_hints": ["Use ss for better performance", "Implement rate limiting"],
                "dependencies": ["netstat", "awk", "sort", "uniq"]
            },
            {
                "id": "sec_check_listening_ports",
                "name": "Check All Listening Ports",
                "description": "List all open ports and associated processes",
                "command_template": "sudo ss -tulpn | grep LISTEN | awk '{{print $5,$7}}'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["ss -tulpn | grep LISTEN", "netstat -tulpn"],
                "performance_hints": ["ss is faster than netstat", "Regular baseline comparisons"],
                "dependencies": ["ss", "sudo"]
            },
            {
                "id": "sec_file_integrity_check",
                "name": "File Integrity Monitoring",
                "description": "Check file integrity using checksums for critical system files",
                "command_template": "find {path} -type f -exec sha256sum {{}} \\; | sort -k 2",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "/etc"}],
                "examples": ["find /etc -type f -exec sha256sum {} \\;"],
                "performance_hints": ["Store baseline hashes", "Use AIDE or Tripwire for automation"],
                "dependencies": ["find", "sha256sum"]
            },
            {
                "id": "sec_detect_backdoors",
                "name": "Detect Common Backdoors",
                "description": "Scan for common backdoor signatures and suspicious files",
                "command_template": "find / -name '*.php' -type f -exec grep -l 'eval(base64_decode\\|eval(gzinflate\\|eval(str_rot13\\|shell_exec\\|system(' {{}} \\; 2>/dev/null | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["find /var/www -name '*.php' -exec grep -l 'eval(' {} \\;"],
                "performance_hints": ["Limit search scope", "Use parallel processing"],
                "dependencies": ["find", "grep"]
            },
            {
                "id": "sec_monitor_cron_jobs",
                "name": "Monitor Cron Job Changes",
                "description": "Track changes to cron jobs across the system",
                "command_template": "for user in $(cut -f1 -d: /etc/passwd); do echo '=== $user ==='; crontab -u $user -l 2>/dev/null; done",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["crontab -l", "ls -la /etc/cron.*"],
                "performance_hints": ["Check system cron directories", "Monitor for unauthorized changes"],
                "dependencies": ["crontab", "cut"]
            },
            {
                "id": "sec_check_suid_files",
                "name": "Find SUID/SGID Files",
                "description": "Locate all SUID and SGID files for security audit",
                "command_template": "find {path} -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -la {{}} \\; 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "/"}],
                "examples": ["find / -perm -4000", "find / -perm -2000"],
                "performance_hints": ["Maintain baseline list", "Alert on new SUID files"],
                "dependencies": ["find", "ls"]
            },
            {
                "id": "sec_detect_rootkits",
                "name": "Basic Rootkit Detection",
                "description": "Perform basic rootkit detection checks",
                "command_template": "chkrootkit -q 2>/dev/null || rkhunter --check --skip-keypress 2>/dev/null | grep -E 'Warning|Suspect'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["chkrootkit", "rkhunter --check"],
                "performance_hints": ["Run during maintenance windows", "Update signatures regularly"],
                "dependencies": ["chkrootkit", "rkhunter"]
            },
            {
                "id": "sec_monitor_network_connections",
                "name": "Monitor Active Network Connections",
                "description": "Track all active network connections with process info",
                "command_template": "ss -tupan | grep ESTABLISHED | awk '{{print $5,$6,$7}}' | sort | uniq -c | sort -nr | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["ss -tupan", "netstat -tupan"],
                "performance_hints": ["Monitor unusual destinations", "Track connection patterns"],
                "dependencies": ["ss", "awk", "sort"]
            },
            {
                "id": "sec_check_password_policy",
                "name": "Audit Password Policy",
                "description": "Check system password policy configuration",
                "command_template": "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE|^PASS_MIN_LEN' /etc/login.defs | grep -v '^#'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["cat /etc/login.defs", "chage -l username"],
                "performance_hints": ["Check PAM configuration too", "Enforce strong policies"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_monitor_file_changes",
                "name": "Monitor Recent File Changes",
                "description": "Find recently modified files in sensitive directories",
                "command_template": "find {path} -type f -mtime -{days} -ls | grep -v '/proc\\|/sys' | sort -k11 -r",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "/etc"}, {"name": "days", "type": "int", "default": 1}],
                "examples": ["find /etc -mtime -1", "find /bin -mtime -7"],
                "performance_hints": ["Use inotify for real-time monitoring", "Focus on critical paths"],
                "dependencies": ["find", "grep", "sort"]
            },
            {
                "id": "sec_check_kernel_modules",
                "name": "List Loaded Kernel Modules",
                "description": "Display all loaded kernel modules for security review",
                "command_template": "lsmod | awk '{{print $1,$3}}' | sort | column -t",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["lsmod", "modinfo module_name"],
                "performance_hints": ["Check for unsigned modules", "Monitor module changes"],
                "dependencies": ["lsmod", "awk", "column"]
            },
            {
                "id": "sec_audit_user_accounts",
                "name": "Audit User Accounts",
                "description": "List all user accounts with login shells",
                "command_template": "awk -F: '$7 !~ /nologin|false/ {{print $1,$3,$6,$7}}' /etc/passwd | column -t",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["cat /etc/passwd", "getent passwd"],
                "performance_hints": ["Check for UID 0 accounts", "Verify authorized users only"],
                "dependencies": ["awk", "column"]
            },
            {
                "id": "sec_check_ssh_keys",
                "name": "Audit SSH Authorized Keys",
                "description": "Find all authorized SSH keys on the system",
                "command_template": "find /home -name authorized_keys -type f -exec sh -c 'echo \"=== $1 ===\"; cat \"$1\"' _ {{}} \\; 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["find /home -name authorized_keys"],
                "performance_hints": ["Check key strength", "Remove unauthorized keys"],
                "dependencies": ["find", "sh", "cat"]
            },
            {
                "id": "sec_monitor_iptables",
                "name": "Monitor Firewall Rules",
                "description": "Display current iptables firewall rules",
                "command_template": "sudo iptables -L -n -v --line-numbers | grep -v 'Chain\\|pkts'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["iptables -L -n -v", "iptables-save"],
                "performance_hints": ["Use nftables on newer systems", "Backup rules regularly"],
                "dependencies": ["iptables", "sudo", "grep"]
            },
            {
                "id": "sec_check_selinux_status",
                "name": "Check SELinux Status",
                "description": "Verify SELinux status and policy enforcement",
                "command_template": "sestatus && getenforce 2>/dev/null || aa-status 2>/dev/null | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["sestatus", "getenforce", "aa-status"],
                "performance_hints": ["Ensure enforcing mode", "Monitor policy violations"],
                "dependencies": ["sestatus", "getenforce", "aa-status"]
            },
            {
                "id": "sec_scan_open_files",
                "name": "Scan Open Files by Process",
                "description": "List all open files grouped by process",
                "command_template": "lsof -n | awk '{{print $1,$2,$9}}' | sort | uniq -c | sort -nr | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["lsof -n", "lsof -i"],
                "performance_hints": ["Check for suspicious file access", "Monitor deleted files still open"],
                "dependencies": ["lsof", "awk", "sort", "uniq"]
            },
            {
                "id": "sec_detect_bruteforce",
                "name": "Detect Brute Force Attempts",
                "description": "Analyze logs for brute force attack patterns",
                "command_template": "grep 'authentication failure' /var/log/auth.log | awk '{{print $NF}}' | sort | uniq -c | sort -nr | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["grep 'authentication failure' /var/log/auth.log"],
                "performance_hints": ["Implement fail2ban", "Set up rate limiting"],
                "dependencies": ["grep", "awk", "sort", "uniq"]
            },
            {
                "id": "sec_check_world_writable",
                "name": "Find World Writable Files",
                "description": "Locate files and directories writable by everyone",
                "command_template": "find {path} -type f -perm -002 -ls 2>/dev/null | grep -v '/proc\\|/sys\\|/tmp' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "/"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["find / -perm -002", "find /home -perm -002"],
                "performance_hints": ["Fix permissions immediately", "Exclude temp directories"],
                "dependencies": ["find", "grep"]
            },
            {
                "id": "sec_monitor_processes",
                "name": "Monitor Running Processes",
                "description": "Track all running processes with security context",
                "command_template": "ps auxww | awk '{{print $1,$2,$11}}' | sort | uniq -c | sort -nr | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 30}],
                "examples": ["ps auxww", "ps -ef"],
                "performance_hints": ["Check for hidden processes", "Monitor resource usage"],
                "dependencies": ["ps", "awk", "sort", "uniq"]
            },
            {
                "id": "sec_check_tmp_files",
                "name": "Audit Temporary Files",
                "description": "Check for suspicious files in temp directories",
                "command_template": "find /tmp /var/tmp -type f -name '*.sh\\|*.py\\|*.pl\\|*.rb' -ls 2>/dev/null | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["find /tmp -type f -name '*.sh'"],
                "performance_hints": ["Regular cleanup", "Monitor execution attempts"],
                "dependencies": ["find"]
            },
            {
                "id": "sec_verify_package_integrity",
                "name": "Verify Package Integrity",
                "description": "Check installed package integrity using package manager",
                "command_template": "dpkg -V 2>/dev/null | grep -v '^\\.\\.' || rpm -Va 2>/dev/null | grep -v '^\\.\\.'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["dpkg -V", "rpm -Va"],
                "performance_hints": ["Regular verification", "Investigate all changes"],
                "dependencies": ["dpkg", "rpm"]
            },
            {
                "id": "sec_monitor_dns_queries",
                "name": "Monitor DNS Query Patterns",
                "description": "Track DNS queries for suspicious domains",
                "command_template": "tcpdump -nn -c {count} -i any port 53 2>/dev/null | awk '/A\\?/ {{print $NF}}' | sort | uniq -c | sort -nr",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [{"name": "count", "type": "int", "default": 1000}],
                "examples": ["tcpdump -nn port 53"],
                "performance_hints": ["Use dnstop for analysis", "Check for DGA domains"],
                "dependencies": ["tcpdump", "awk", "sort"]
            },
            {
                "id": "sec_check_system_accounts",
                "name": "Audit System Service Accounts",
                "description": "Review system service accounts for security",
                "command_template": "awk -F: '$3 < 1000 && $7 !~ /nologin|false/ {{print $1,$3,$7}}' /etc/passwd | column -t",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["awk -F: '$3 < 1000' /etc/passwd"],
                "performance_hints": ["Disable unnecessary accounts", "Check for shell access"],
                "dependencies": ["awk", "column"]
            },
            {
                "id": "sec_monitor_memory_forensics",
                "name": "Basic Memory Forensics",
                "description": "Extract strings from process memory for analysis",
                "command_template": "sudo grep -a {pattern} /proc/{pid}/mem 2>/dev/null | strings | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.HIGH_RISK,
                "parameters": [{"name": "pattern", "type": "string", "default": "password"}, {"name": "pid", "type": "int", "required": true}, {"name": "limit", "type": "int", "default": 20}],
                "examples": ["grep -a pattern /proc/PID/mem"],
                "performance_hints": ["Use volatility for detailed analysis", "Handle with care"],
                "dependencies": ["grep", "strings", "sudo"]
            },
            {
                "id": "sec_detect_web_shells",
                "name": "Detect Common Web Shells",
                "description": "Scan web directories for known web shell signatures",
                "command_template": "find {webroot} -type f \\( -name '*.php' -o -name '*.asp' -o -name '*.jsp' \\) -exec grep -l 'c99\\|r57\\|WSO\\|FilesMan\\|JspSpy' {{}} \\; 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "webroot", "type": "string", "default": "/var/www"}],
                "examples": ["find /var/www -name '*.php' -exec grep -l 'eval(' {} \\;"],
                "performance_hints": ["Regular scanning", "Use YARA rules"],
                "dependencies": ["find", "grep"]
            },
            {
                "id": "sec_audit_systemd_services",
                "name": "Audit Systemd Services",
                "description": "List all systemd services and their status",
                "command_template": "systemctl list-unit-files --type=service | grep enabled | awk '{{print $1}}' | xargs -I{{}} systemctl is-active {{}} | paste <(systemctl list-unit-files --type=service | grep enabled | awk '{{print $1}}') -",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["systemctl list-unit-files --type=service"],
                "performance_hints": ["Disable unnecessary services", "Monitor new services"],
                "dependencies": ["systemctl", "awk", "xargs", "paste"]
            },
            {
                "id": "sec_check_container_security",
                "name": "Container Security Audit",
                "description": "Security check for running containers",
                "command_template": "docker ps -q | xargs -I{{}} docker inspect {{}} | jq -r '.[] | select(.State.Running==true) | \"\\(.Name) PrivilegedMode:\\(.HostConfig.Privileged) User:\\(.Config.User)\"'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["docker ps --no-trunc"],
                "performance_hints": ["Avoid privileged containers", "Use security scanning"],
                "dependencies": ["docker", "jq", "xargs"]
            },
            {
                "id": "sec_monitor_auditd_events",
                "name": "Monitor Audit Events",
                "description": "Review auditd security events",
                "command_template": "aureport -au -i --summary | head -n {limit} && aureport -f -i --summary | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["aureport -au", "ausearch -m USER_LOGIN"],
                "performance_hints": ["Configure audit rules", "Regular review"],
                "dependencies": ["aureport"]
            },
            {
                "id": "sec_check_ssl_certificates",
                "name": "SSL Certificate Validation",
                "description": "Check SSL certificate expiration and validity",
                "command_template": "echo | openssl s_client -servername {hostname} -connect {hostname}:{port} 2>/dev/null | openssl x509 -noout -dates -subject -issuer",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "hostname", "type": "string", "required": true}, {"name": "port", "type": "int", "default": 443}],
                "examples": ["openssl s_client -connect example.com:443"],
                "performance_hints": ["Monitor expiration", "Check certificate chain"],
                "dependencies": ["openssl"]
            },
            {
                "id": "sec_detect_crypto_mining",
                "name": "Detect Crypto Mining Activity",
                "description": "Search for cryptocurrency mining processes",
                "command_template": "ps aux | grep -E 'minerd|xmrig|cgminer|bfgminer|ethminer|equihash|cryptonight' | grep -v grep",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ps aux | grep minerd"],
                "performance_hints": ["Check CPU usage", "Monitor network connections"],
                "dependencies": ["ps", "grep"]
            },
            {
                "id": "sec_monitor_usb_devices",
                "name": "Monitor USB Device Connections",
                "description": "Track USB device connections and disconnections",
                "command_template": "dmesg | grep -i 'usb\\|storage' | tail -n {limit} | grep -E 'Product:|Manufacturer:|SerialNumber:'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["dmesg | grep -i usb", "lsusb -v"],
                "performance_hints": ["Implement USB policies", "Log all connections"],
                "dependencies": ["dmesg", "grep"]
            },
            {
                "id": "sec_check_apparmor_status",
                "name": "AppArmor Security Status",
                "description": "Check AppArmor profiles and enforcement status",
                "command_template": "aa-status --verbose 2>/dev/null | grep -E 'profiles|processes' | head -10",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["aa-status", "aa-enforce /path/to/profile"],
                "performance_hints": ["Keep profiles updated", "Monitor violations"],
                "dependencies": ["aa-status"]
            },
            {
                "id": "sec_scan_log_injection",
                "name": "Detect Log Injection Attempts",
                "description": "Scan logs for injection attack patterns",
                "command_template": "grep -E '\\r|\\n|%0a|%0d' /var/log/{logfile} | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "logfile", "type": "string", "default": "syslog"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["grep -E '\\r|\\n' /var/log/syslog"],
                "performance_hints": ["Sanitize log inputs", "Use structured logging"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_monitor_kernel_parameters",
                "name": "Audit Kernel Parameters",
                "description": "Check security-related kernel parameters",
                "command_template": "sysctl -a 2>/dev/null | grep -E 'randomize_va_space|ptrace_scope|yama|exec-shield' | sort",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["sysctl kernel.randomize_va_space"],
                "performance_hints": ["Harden kernel settings", "Document changes"],
                "dependencies": ["sysctl", "grep", "sort"]
            },
            {
                "id": "sec_check_core_dumps",
                "name": "Check Core Dump Configuration",
                "description": "Verify core dump settings for security",
                "command_template": "ulimit -c && cat /proc/sys/kernel/core_pattern && ls -la /var/crash/ 2>/dev/null | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 10}],
                "examples": ["ulimit -c", "cat /proc/sys/kernel/core_pattern"],
                "performance_hints": ["Disable in production", "Secure dump location"],
                "dependencies": ["ulimit", "cat", "ls"]
            },
            {
                "id": "sec_detect_reverse_shells",
                "name": "Detect Reverse Shell Connections",
                "description": "Identify potential reverse shell connections",
                "command_template": "netstat -antp 2>/dev/null | grep ESTABLISHED | awk '$4 ~ /:4444|:1234|:31337|:8080/ {{print $0}}'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["netstat -antp | grep ESTABLISHED"],
                "performance_hints": ["Monitor common backdoor ports", "Check process ownership"],
                "dependencies": ["netstat", "awk", "grep"]
            },
            {
                "id": "sec_audit_docker_security",
                "name": "Docker Security Audit",
                "description": "Comprehensive Docker security check",
                "command_template": "docker info --format '{{json .SecurityOptions}}' | jq . && docker images --format 'table {{.Repository}}:{{.Tag}}\\t{{.Size}}' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["docker info", "docker images"],
                "performance_hints": ["Enable Docker Content Trust", "Scan images regularly"],
                "dependencies": ["docker", "jq"]
            },
            {
                "id": "sec_monitor_namespace_isolation",
                "name": "Check Namespace Isolation",
                "description": "Verify process namespace isolation",
                "command_template": "ls -la /proc/*/ns/ 2>/dev/null | grep -E 'pid:|net:|mnt:' | sort | uniq -c | sort -nr | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 30}],
                "examples": ["ls -la /proc/self/ns/"],
                "performance_hints": ["Check container breakouts", "Monitor namespace sharing"],
                "dependencies": ["ls", "grep", "sort", "uniq"]
            },
            {
                "id": "sec_check_pam_config",
                "name": "Audit PAM Configuration",
                "description": "Review PAM security configuration",
                "command_template": "grep -v '^#\\|^$' /etc/pam.d/common-auth /etc/pam.d/common-password 2>/dev/null | grep -E 'pam_tally|pam_faillock|pam_pwquality'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["cat /etc/pam.d/common-auth"],
                "performance_hints": ["Enable account lockout", "Enforce password complexity"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_scan_malware_signatures",
                "name": "Quick Malware Signature Scan",
                "description": "Scan for known malware signatures in files",
                "command_template": "find {path} -type f -size +100k -exec file {{}} \\; | grep -E 'ELF|executable' | cut -d: -f1 | xargs -I{{}} strings {{}} | grep -E 'backdoor|rootkit|keylogger' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [{"name": "path", "type": "string", "default": "/tmp"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["find /tmp -type f -exec file {} \\;"],
                "performance_hints": ["Use ClamAV for comprehensive scans", "Regular signature updates"],
                "dependencies": ["find", "file", "strings", "grep", "xargs"]
            },
            {
                "id": "sec_monitor_systemd_timers",
                "name": "Monitor Systemd Timers",
                "description": "List all systemd timers for security review",
                "command_template": "systemctl list-timers --all | grep -v '^$' | awk 'NR>1 {{print $NF}}' | xargs -I{{}} systemctl status {{}} 2>&1 | grep -E 'Loaded:|Active:' | paste - -",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["systemctl list-timers --all"],
                "performance_hints": ["Check for persistence mechanisms", "Monitor timer creation"],
                "dependencies": ["systemctl", "grep", "awk", "xargs", "paste"]
            },
            {
                "id": "sec_check_ld_preload",
                "name": "Check LD_PRELOAD Hijacking",
                "description": "Detect potential LD_PRELOAD library hijacking",
                "command_template": "find /etc -name 'ld.so.*' -exec cat {{}} \\; 2>/dev/null | grep -v '^#\\|^$' && env | grep LD_PRELOAD",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["cat /etc/ld.so.preload", "env | grep LD_"],
                "performance_hints": ["Monitor for changes", "Check process environments"],
                "dependencies": ["find", "cat", "grep", "env"]
            },
            {
                "id": "sec_audit_capabilities",
                "name": "Audit File Capabilities",
                "description": "Find files with special capabilities set",
                "command_template": "getcap -r {path} 2>/dev/null | grep -v '^$'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "/"}],
                "examples": ["getcap -r /usr/bin"],
                "performance_hints": ["Review all capabilities", "Minimize capability usage"],
                "dependencies": ["getcap"]
            },
            {
                "id": "sec_monitor_aide_changes",
                "name": "AIDE File Integrity Check",
                "description": "Run AIDE file integrity monitoring check",
                "command_template": "aide --check 2>/dev/null | grep -E 'Added:|Removed:|Changed:' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [{"name": "limit", "type": "int", "default": 100}],
                "examples": ["aide --check", "aide --update"],
                "performance_hints": ["Regular baseline updates", "Investigate all changes"],
                "dependencies": ["aide"]
            },
            {
                "id": "sec_check_gpg_keys",
                "name": "Audit GPG Keys",
                "description": "List and verify GPG keys on the system",
                "command_template": "gpg --list-keys 2>/dev/null | grep -E 'pub|uid' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["gpg --list-keys", "gpg --list-secret-keys"],
                "performance_hints": ["Verify key trust", "Remove unauthorized keys"],
                "dependencies": ["gpg"]
            },
            {
                "id": "sec_scan_sql_injection_logs",
                "name": "Detect SQL Injection Attempts",
                "description": "Scan web logs for SQL injection patterns",
                "command_template": "grep -E 'union.*select|select.*from|drop.*table|update.*set|delete.*from' {logfile} | grep -i 'sql\\|query\\|database' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "logfile", "type": "string", "default": "/var/log/apache2/access.log"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["grep -E 'union.*select' /var/log/nginx/access.log"],
                "performance_hints": ["Use WAF rules", "Parameterized queries"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_monitor_seccomp",
                "name": "Check Seccomp Filters",
                "description": "Monitor processes using seccomp filters",
                "command_template": "grep Seccomp /proc/*/status 2>/dev/null | grep -v ': 0' | cut -d/ -f3 | xargs -I{{}} sh -c 'echo \"PID {{}} - $(cat /proc/{{}}/comm 2>/dev/null)\"' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 30}],
                "examples": ["grep Seccomp /proc/*/status"],
                "performance_hints": ["Enable for containers", "Monitor filter changes"],
                "dependencies": ["grep", "cut", "xargs", "sh"]
            },
            {
                "id": "sec_check_mail_queue",
                "name": "Monitor Mail Queue Security",
                "description": "Check mail queue for suspicious activity",
                "command_template": "mailq | grep -E '<>|MAILER-DAEMON' | wc -l && postqueue -p 2>/dev/null | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["mailq", "postqueue -p"],
                "performance_hints": ["Monitor spam activity", "Check for mail bombs"],
                "dependencies": ["mailq", "postqueue", "grep", "wc"]
            },
            {
                "id": "sec_audit_nfs_exports",
                "name": "Audit NFS Exports Security",
                "description": "Review NFS export configurations for security",
                "command_template": "showmount -e localhost 2>/dev/null && cat /etc/exports 2>/dev/null | grep -v '^#\\|^$'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["showmount -e", "exportfs -v"],
                "performance_hints": ["Restrict access", "Use NFSv4 with Kerberos"],
                "dependencies": ["showmount", "cat", "grep"]
            },
            {
                "id": "sec_monitor_journal_security",
                "name": "Monitor Journal Security Events",
                "description": "Extract security events from systemd journal",
                "command_template": "journalctl -p err -u ssh -u sshd --since '{time}' --no-pager | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "time", "type": "string", "default": "1 hour ago"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["journalctl -p err", "journalctl -u ssh"],
                "performance_hints": ["Regular review", "Forward to SIEM"],
                "dependencies": ["journalctl"]
            },
            {
                "id": "sec_check_umask_settings",
                "name": "Audit Umask Settings",
                "description": "Check default umask settings for security",
                "command_template": "grep -h umask /etc/profile /etc/bashrc /etc/login.defs 2>/dev/null | grep -v '^#' | sort -u",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["umask", "grep umask /etc/profile"],
                "performance_hints": ["Use restrictive umask", "Set to 077 for sensitive systems"],
                "dependencies": ["grep", "sort"]
            },
            {
                "id": "sec_detect_persistence",
                "name": "Detect Persistence Mechanisms",
                "description": "Search for common persistence techniques",
                "command_template": "find /etc/rc*.d /etc/init.d /etc/systemd/system -type f -mtime -{days} -ls 2>/dev/null | grep -v 'README' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "days", "type": "int", "default": 7}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["find /etc/systemd/system -mtime -7"],
                "performance_hints": ["Monitor startup changes", "Check all init systems"],
                "dependencies": ["find", "grep"]
            },
            {
                "id": "sec_monitor_resource_limits",
                "name": "Check Resource Limit Security",
                "description": "Audit system resource limits for security",
                "command_template": "cat /etc/security/limits.conf | grep -v '^#\\|^$' && ulimit -a",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ulimit -a", "cat /etc/security/limits.conf"],
                "performance_hints": ["Prevent DoS", "Set appropriate limits"],
                "dependencies": ["cat", "grep", "ulimit"]
            },
            {
                "id": "sec_check_proc_hidepid",
                "name": "Check /proc Mount Security",
                "description": "Verify /proc mount options for security",
                "command_template": "mount | grep ' /proc ' && ls -ld /proc/[0-9]* | head -5",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["mount | grep /proc"],
                "performance_hints": ["Use hidepid option", "Restrict proc access"],
                "dependencies": ["mount", "grep", "ls"]
            },
            {
                "id": "sec_audit_xinetd_services",
                "name": "Audit xinetd Services",
                "description": "Check xinetd services for security",
                "command_template": "ls -la /etc/xinetd.d/ 2>/dev/null && grep -h 'disable' /etc/xinetd.d/* 2>/dev/null | sort -u",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ls /etc/xinetd.d/"],
                "performance_hints": ["Disable unnecessary services", "Use systemd instead"],
                "dependencies": ["ls", "grep", "sort"]
            },
            {
                "id": "sec_monitor_bash_history",
                "name": "Audit Bash History Security",
                "description": "Check bash history files for sensitive data",
                "command_template": "find /home -name .bash_history -exec sh -c 'echo \"=== $1 ===\"; grep -E \"password|passwd|token|key\" \"$1\" | head -5' _ {{}} \\; 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [],
                "examples": ["find /home -name .bash_history"],
                "performance_hints": ["Educate users", "Consider HISTCONTROL settings"],
                "dependencies": ["find", "sh", "grep"]
            },
            {
                "id": "sec_check_sticky_bits",
                "name": "Audit Sticky Bit Directories",
                "description": "Find directories with sticky bit set",
                "command_template": "find / -type d -perm -1000 -ls 2>/dev/null | grep -v '/proc\\|/sys' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 30}],
                "examples": ["find / -type d -perm -1000"],
                "performance_hints": ["Verify all sticky directories", "Check /tmp and /var/tmp"],
                "dependencies": ["find", "grep"]
            },
            {
                "id": "sec_monitor_at_jobs",
                "name": "Monitor At Job Queue",
                "description": "Check at job queue for suspicious tasks",
                "command_template": "atq 2>/dev/null | awk '{{print $1}}' | xargs -I{{}} at -c {{}} 2>/dev/null | grep -v '^#' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["atq", "at -c jobid"],
                "performance_hints": ["Monitor job creation", "Check user permissions"],
                "dependencies": ["atq", "at", "awk", "xargs", "grep"]
            },
            {
                "id": "sec_check_motd_security",
                "name": "Audit MOTD Scripts Security",
                "description": "Check message of the day scripts for security",
                "command_template": "ls -la /etc/update-motd.d/ 2>/dev/null && file /etc/update-motd.d/* 2>/dev/null | grep -E 'script|executable'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ls /etc/update-motd.d/"],
                "performance_hints": ["Review all scripts", "Check for information leakage"],
                "dependencies": ["ls", "file", "grep"]
            },
            {
                "id": "sec_monitor_coredump_patterns",
                "name": "Monitor Core Dump Patterns",
                "description": "Check core dump handler configuration",
                "command_template": "cat /proc/sys/kernel/core_pattern && ls -la /var/crash/ 2>/dev/null | tail -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["cat /proc/sys/kernel/core_pattern"],
                "performance_hints": ["Secure core handler", "Limit core dump size"],
                "dependencies": ["cat", "ls", "tail"]
            },
            {
                "id": "sec_audit_shell_escapes",
                "name": "Detect Shell Escape Attempts",
                "description": "Search logs for shell escape patterns",
                "command_template": "grep -E '\\$\\(|`|;|&&|\\|\\||<\\(|>\\(' {logfile} | grep -v 'grep' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "logfile", "type": "string", "default": "/var/log/syslog"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["grep -E '\\$\\(|`' /var/log/apache2/error.log"],
                "performance_hints": ["Input validation", "Use allowlists"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_check_account_expiry",
                "name": "Check Account Expiration",
                "description": "List user accounts with expiration info",
                "command_template": "awk -F: '$7 !~ /nologin|false/ {{print $1}}' /etc/passwd | xargs -I{{}} chage -l {{}} 2>/dev/null | grep -E 'Account expires|Password expires' | paste - - | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["chage -l username"],
                "performance_hints": ["Regular reviews", "Automate expiration"],
                "dependencies": ["awk", "xargs", "chage", "grep", "paste"]
            },
            {
                "id": "sec_monitor_ptrace_scope",
                "name": "Check Ptrace Scope Security",
                "description": "Verify ptrace scope restrictions",
                "command_template": "cat /proc/sys/kernel/yama/ptrace_scope && grep -r ptrace /etc/sysctl* 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["sysctl kernel.yama.ptrace_scope"],
                "performance_hints": ["Set to 1 or higher", "Prevent debugging attacks"],
                "dependencies": ["cat", "grep"]
            },
            {
                "id": "sec_audit_mysql_users",
                "name": "Audit MySQL User Security",
                "description": "Check MySQL user privileges and security",
                "command_template": "mysql -e \"SELECT user,host,authentication_string FROM mysql.user WHERE authentication_string='' OR authentication_string IS NULL;\" 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["mysql -e 'SELECT user,host FROM mysql.user;'"],
                "performance_hints": ["No blank passwords", "Limit root access"],
                "dependencies": ["mysql"]
            },
            {
                "id": "sec_check_immutable_files",
                "name": "Find Immutable Files",
                "description": "Locate files with immutable attribute set",
                "command_template": "lsattr -R {path} 2>/dev/null | grep -E '^....i' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "/etc"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["lsattr /etc/passwd"],
                "performance_hints": ["Check critical files", "Monitor attribute changes"],
                "dependencies": ["lsattr", "grep"]
            },
            {
                "id": "sec_monitor_memory_corruption",
                "name": "Check Memory Corruption Protection",
                "description": "Verify memory corruption protection mechanisms",
                "command_template": "dmesg | grep -i 'nx\\|aslr\\|dep\\|pie' | tail -n {limit} && cat /proc/sys/kernel/randomize_va_space",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["dmesg | grep -i nx"],
                "performance_hints": ["Enable all protections", "Check compiler flags"],
                "dependencies": ["dmesg", "grep", "cat"]
            },
            {
                "id": "sec_audit_rsyslog_config",
                "name": "Audit Rsyslog Security Config",
                "description": "Review rsyslog configuration for security",
                "command_template": "grep -E '^\\$|^\\*\\.\\*|@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -v '^#'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["cat /etc/rsyslog.conf"],
                "performance_hints": ["Remote logging", "Encrypt log transport"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_check_grub_password",
                "name": "Check GRUB Password Protection",
                "description": "Verify GRUB bootloader password configuration",
                "command_template": "grep -E 'password|superusers' /boot/grub/grub.cfg /etc/grub.d/* 2>/dev/null | grep -v '^#'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["grep password /boot/grub/grub.cfg"],
                "performance_hints": ["Protect boot process", "Use GRUB2 passwords"],
                "dependencies": ["grep"]
            },
            {
                "id": "sec_monitor_swap_usage",
                "name": "Monitor Swap Security",
                "description": "Check swap usage and encryption status",
                "command_template": "swapon -s && cat /proc/swaps && cryptsetup status $(swapon -s | awk 'NR>1 {{print $1}}' | head -1) 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["swapon -s", "cat /proc/swaps"],
                "performance_hints": ["Encrypt swap", "Monitor sensitive data"],
                "dependencies": ["swapon", "cat", "cryptsetup", "awk"]
            },
            {
                "id": "sec_audit_postfix_security",
                "name": "Audit Postfix Security Config",
                "description": "Check Postfix mail server security settings",
                "command_template": "postconf -n | grep -E 'relayhost|mynetworks|recipient|sender' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["postconf -n"],
                "performance_hints": ["Prevent open relay", "Use TLS"],
                "dependencies": ["postconf", "grep"]
            },
            {
                "id": "sec_check_chroot_processes",
                "name": "Find Chrooted Processes",
                "description": "Identify processes running in chroot environments",
                "command_template": "ls -la /proc/*/root 2>/dev/null | grep -v ' / *$' | cut -d/ -f3 | xargs -I{{}} sh -c 'echo \"PID {{}} - $(cat /proc/{{}}/comm 2>/dev/null) - $(readlink /proc/{{}}/root)\"' | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["ls -la /proc/*/root"],
                "performance_hints": ["Verify chroot security", "Check escape attempts"],
                "dependencies": ["ls", "grep", "cut", "xargs", "sh", "readlink"]
            },
            {
                "id": "sec_monitor_kworker_threads",
                "name": "Monitor Kernel Worker Threads",
                "description": "Check kernel worker thread activity",
                "command_template": "ps aux | grep '\\[kworker' | awk '{{print $2,$11,$1}}' | sort | uniq -c | sort -nr | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["ps aux | grep kworker"],
                "performance_hints": ["Monitor abnormal activity", "Check CPU usage"],
                "dependencies": ["ps", "grep", "awk", "sort", "uniq"]
            },
            {
                "id": "sec_audit_aws_credentials",
                "name": "Audit AWS Credentials Security",
                "description": "Search for exposed AWS credentials",
                "command_template": "find /home /root -name '.aws' -type d -exec ls -la {{}}/credentials {{}}config 2>/dev/null \\; | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [{"name": "limit", "type": "int", "default": 20}],
                "examples": ["find /home -name .aws"],
                "performance_hints": ["Use IAM roles", "Rotate keys regularly"],
                "dependencies": ["find", "ls"]
            },
            {
                "id": "sec_check_debugfs_mount",
                "name": "Check Debugfs Mount Security",
                "description": "Verify debugfs mount restrictions",
                "command_template": "mount | grep debugfs && ls -la /sys/kernel/debug/ 2>/dev/null | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 10}],
                "examples": ["mount | grep debugfs"],
                "performance_hints": ["Restrict access", "Unmount if not needed"],
                "dependencies": ["mount", "grep", "ls"]
            },
            {
                "id": "sec_monitor_bpf_programs",
                "name": "Monitor BPF Programs",
                "description": "List loaded BPF programs",
                "command_template": "bpftool prog list 2>/dev/null | head -n {limit} || ls -la /sys/fs/bpf/ 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["bpftool prog list"],
                "performance_hints": ["Monitor BPF usage", "Check for rootkits"],
                "dependencies": ["bpftool", "ls"]
            },
            {
                "id": "sec_audit_git_repositories",
                "name": "Audit Git Repository Security",
                "description": "Find Git repositories and check for sensitive data",
                "command_template": "find {path} -name '.git' -type d -prune -exec sh -c 'echo \"=== $1 ===\"; git -C $(dirname \"$1\") log --oneline -5 2>/dev/null' _ {{}} \\; | head -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "/home"}, {"name": "limit", "type": "int", "default": 50}],
                "examples": ["find /home -name .git"],
                "performance_hints": ["Check .gitignore", "Scan for secrets"],
                "dependencies": ["find", "sh", "git"]
            },
            {
                "id": "sec_check_polkit_rules",
                "name": "Audit PolicyKit Rules",
                "description": "Review PolicyKit authorization rules",
                "command_template": "ls -la /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/ 2>/dev/null | grep -v '^total' | tail -n {limit}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 30}],
                "examples": ["ls /etc/polkit-1/rules.d/"],
                "performance_hints": ["Review custom rules", "Principle of least privilege"],
                "dependencies": ["ls", "grep", "tail"]
            },
            {
                "id": "sec_monitor_dbus_services",
                "name": "Monitor D-Bus Services",
                "description": "List D-Bus services and their security context",
                "command_template": "busctl list --no-pager | head -n {limit} && ls -la /etc/dbus-1/system.d/ | tail -10",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "limit", "type": "int", "default": 50}],
                "examples": ["busctl list"],
                "performance_hints": ["Review service permissions", "Monitor new services"],
                "dependencies": ["busctl", "ls", "tail"]
            },
            
            # DEVOPS PIPELINE COMMANDS (50+ commands)
            {
                "id": "devops_docker_build_multi_stage",
                "name": "Multi-Stage Docker Build",
                "description": "Build optimized Docker images using multi-stage builds",
                "command_template": "docker build --target {stage} -t {image}:{tag} -f {dockerfile} {context}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "stage", "type": "string", "default": "production"},
                    {"name": "image", "type": "string", "required": True},
                    {"name": "tag", "type": "string", "default": "latest"},
                    {"name": "dockerfile", "type": "string", "default": "Dockerfile"},
                    {"name": "context", "type": "string", "default": "."}
                ],
                "examples": ["docker build --target production -t myapp:v1.0 ."],
                "performance_hints": ["Use build cache", "Minimize layers", "Order commands efficiently"],
                "dependencies": ["docker"],
                "parallel_execution": False
            },
            {
                "id": "devops_k8s_rolling_update",
                "name": "Kubernetes Rolling Update",
                "description": "Perform zero-downtime rolling updates in Kubernetes",
                "command_template": "kubectl set image deployment/{deployment} {container}={image}:{tag} -n {namespace} && kubectl rollout status deployment/{deployment} -n {namespace}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "deployment", "type": "string", "required": True},
                    {"name": "container", "type": "string", "required": True},
                    {"name": "image", "type": "string", "required": True},
                    {"name": "tag", "type": "string", "required": True},
                    {"name": "namespace", "type": "string", "default": "default"}
                ],
                "examples": ["kubectl set image deployment/api api=myapp:v2.0 -n production"],
                "performance_hints": ["Configure proper readiness probes", "Set maxSurge and maxUnavailable"],
                "dependencies": ["kubectl"]
            },
            {
                "id": "devops_terraform_plan_apply",
                "name": "Terraform Plan and Apply",
                "description": "Plan and apply infrastructure changes with Terraform",
                "command_template": "terraform plan -out={plan_file} {options} && terraform apply {plan_file}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.HIGH_RISK,
                "parameters": [
                    {"name": "plan_file", "type": "string", "default": "tfplan"},
                    {"name": "options", "type": "string", "default": "-parallelism=10"}
                ],
                "examples": ["terraform plan -out=prod.tfplan && terraform apply prod.tfplan"],
                "performance_hints": ["Use remote state", "Implement state locking", "Review plan before applying"],
                "dependencies": ["terraform"]
            },
            {
                "id": "devops_ansible_playbook_check",
                "name": "Ansible Playbook Dry Run",
                "description": "Execute Ansible playbook in check mode with diff",
                "command_template": "ansible-playbook -i {inventory} {playbook} --check --diff -v",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "inventory", "type": "string", "required": True},
                    {"name": "playbook", "type": "string", "required": True}
                ],
                "examples": ["ansible-playbook -i inventory/production site.yml --check --diff"],
                "performance_hints": ["Use fact caching", "Implement proper error handling"],
                "dependencies": ["ansible-playbook"]
            },
            {
                "id": "devops_jenkins_job_trigger",
                "name": "Trigger Jenkins Job with Parameters",
                "description": "Trigger Jenkins job via CLI with parameters",
                "command_template": "jenkins-cli build {job_name} -p {parameters} -s {jenkins_url} -auth {credentials}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "job_name", "type": "string", "required": True},
                    {"name": "parameters", "type": "string", "default": ""},
                    {"name": "jenkins_url", "type": "string", "required": True},
                    {"name": "credentials", "type": "string", "required": True}
                ],
                "examples": ["jenkins-cli build deploy-api -p 'ENV=prod VERSION=1.2.3'"],
                "performance_hints": ["Use build queues", "Monitor job status"],
                "dependencies": ["jenkins-cli"]
            },
            {
                "id": "devops_gitlab_ci_lint",
                "name": "Validate GitLab CI Configuration",
                "description": "Lint and validate .gitlab-ci.yml configuration",
                "command_template": "gitlab-ci-lint {file} --api-url {gitlab_url} --token {token}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "file", "type": "string", "default": ".gitlab-ci.yml"},
                    {"name": "gitlab_url", "type": "string", "required": True},
                    {"name": "token", "type": "string", "required": True}
                ],
                "examples": ["gitlab-ci-lint .gitlab-ci.yml --api-url https://gitlab.com"],
                "performance_hints": ["Validate before commit", "Use CI/CD templates"],
                "dependencies": ["gitlab-ci-lint", "curl"]
            },
            {
                "id": "devops_helm_upgrade_rollback",
                "name": "Helm Chart Upgrade with Rollback",
                "description": "Upgrade Helm release with automatic rollback on failure",
                "command_template": "helm upgrade {release} {chart} --atomic --cleanup-on-fail --timeout {timeout} -n {namespace} -f {values}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "release", "type": "string", "required": True},
                    {"name": "chart", "type": "string", "required": True},
                    {"name": "timeout", "type": "string", "default": "5m"},
                    {"name": "namespace", "type": "string", "default": "default"},
                    {"name": "values", "type": "string", "default": "values.yaml"}
                ],
                "examples": ["helm upgrade myapp ./charts/myapp --atomic --timeout 10m"],
                "performance_hints": ["Test in staging first", "Use --dry-run"],
                "dependencies": ["helm"]
            },
            {
                "id": "devops_argocd_sync",
                "name": "ArgoCD Application Sync",
                "description": "Sync ArgoCD application with Git repository",
                "command_template": "argocd app sync {app_name} --prune --timeout {timeout} --strategy {strategy}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "app_name", "type": "string", "required": True},
                    {"name": "timeout", "type": "int", "default": 300},
                    {"name": "strategy", "type": "string", "default": "apply"}
                ],
                "examples": ["argocd app sync production-api --prune --timeout 600"],
                "performance_hints": ["Use sync waves", "Configure resource hooks"],
                "dependencies": ["argocd"]
            },
            {
                "id": "devops_prometheus_reload",
                "name": "Reload Prometheus Configuration",
                "description": "Hot reload Prometheus configuration without restart",
                "command_template": "curl -X POST {prometheus_url}/-/reload && promtool check config {config_file}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "prometheus_url", "type": "string", "default": "http://localhost:9090"},
                    {"name": "config_file", "type": "string", "default": "/etc/prometheus/prometheus.yml"}
                ],
                "examples": ["curl -X POST http://prometheus:9090/-/reload"],
                "performance_hints": ["Validate config first", "Monitor reload status"],
                "dependencies": ["curl", "promtool"]
            },
            {
                "id": "devops_grafana_dashboard_import",
                "name": "Import Grafana Dashboard",
                "description": "Import dashboard to Grafana via API",
                "command_template": "curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer {api_key}' -d @{dashboard_file} {grafana_url}/api/dashboards/db",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "api_key", "type": "string", "required": True},
                    {"name": "dashboard_file", "type": "string", "required": True},
                    {"name": "grafana_url", "type": "string", "default": "http://localhost:3000"}
                ],
                "examples": ["curl -X POST -H 'Authorization: Bearer xxx' -d @dashboard.json http://grafana:3000/api/dashboards/db"],
                "performance_hints": ["Version control dashboards", "Use dashboard UIDs"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_vault_secret_rotate",
                "name": "Rotate Vault Secrets",
                "description": "Rotate secrets in HashiCorp Vault",
                "command_template": "vault write -force {secret_engine}/rotate-root && vault write {secret_engine}/config/rotate-root ttl={ttl}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.HIGH_RISK,
                "parameters": [
                    {"name": "secret_engine", "type": "string", "required": True},
                    {"name": "ttl", "type": "string", "default": "24h"}
                ],
                "examples": ["vault write -force database/rotate-root"],
                "performance_hints": ["Automate rotation", "Monitor secret usage"],
                "dependencies": ["vault"]
            },
            {
                "id": "devops_nexus_artifact_upload",
                "name": "Upload Artifact to Nexus",
                "description": "Upload build artifacts to Nexus repository",
                "command_template": "curl -v -u {credentials} --upload-file {file} {nexus_url}/repository/{repo}/{path}/{filename}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "credentials", "type": "string", "required": True},
                    {"name": "file", "type": "string", "required": True},
                    {"name": "nexus_url", "type": "string", "required": True},
                    {"name": "repo", "type": "string", "required": True},
                    {"name": "path", "type": "string", "required": True},
                    {"name": "filename", "type": "string", "required": True}
                ],
                "examples": ["curl -u admin:password --upload-file app.jar https://nexus.company.com/repository/releases/com/company/app/1.0/app-1.0.jar"],
                "performance_hints": ["Use checksums", "Implement retention policies"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_sonarqube_scan",
                "name": "SonarQube Code Analysis",
                "description": "Run SonarQube analysis on project",
                "command_template": "sonar-scanner -Dsonar.projectKey={project_key} -Dsonar.sources={sources} -Dsonar.host.url={sonar_url} -Dsonar.login={token}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "project_key", "type": "string", "required": True},
                    {"name": "sources", "type": "string", "default": "."},
                    {"name": "sonar_url", "type": "string", "required": True},
                    {"name": "token", "type": "string", "required": True}
                ],
                "examples": ["sonar-scanner -Dsonar.projectKey=myapp -Dsonar.sources=src"],
                "performance_hints": ["Cache analysis data", "Use quality gates"],
                "dependencies": ["sonar-scanner"]
            },
            {
                "id": "devops_aws_ecs_deploy",
                "name": "AWS ECS Service Deployment",
                "description": "Deploy new task definition to ECS service",
                "command_template": "aws ecs update-service --cluster {cluster} --service {service} --task-definition {task_def} --desired-count {count} --force-new-deployment",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "cluster", "type": "string", "required": True},
                    {"name": "service", "type": "string", "required": True},
                    {"name": "task_def", "type": "string", "required": True},
                    {"name": "count", "type": "int", "default": 2}
                ],
                "examples": ["aws ecs update-service --cluster prod --service api --task-definition api:123"],
                "performance_hints": ["Use deployment circuit breaker", "Monitor service events"],
                "dependencies": ["aws"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "devops_cloudformation_deploy",
                "name": "CloudFormation Stack Deployment",
                "description": "Deploy AWS CloudFormation stack with parameters",
                "command_template": "aws cloudformation deploy --template-file {template} --stack-name {stack} --parameter-overrides {params} --capabilities CAPABILITY_IAM",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.HIGH_RISK,
                "parameters": [
                    {"name": "template", "type": "string", "required": True},
                    {"name": "stack", "type": "string", "required": True},
                    {"name": "params", "type": "string", "default": ""}
                ],
                "examples": ["aws cloudformation deploy --template-file template.yml --stack-name prod-stack"],
                "performance_hints": ["Use change sets", "Implement stack policies"],
                "dependencies": ["aws"]
            },
            {
                "id": "devops_github_actions_dispatch",
                "name": "Trigger GitHub Actions Workflow",
                "description": "Manually trigger GitHub Actions workflow",
                "command_template": "gh workflow run {workflow} -f {inputs} -R {repo}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "workflow", "type": "string", "required": True},
                    {"name": "inputs", "type": "string", "default": ""},
                    {"name": "repo", "type": "string", "required": True}
                ],
                "examples": ["gh workflow run deploy.yml -f environment=production -R owner/repo"],
                "performance_hints": ["Use workflow concurrency", "Cache dependencies"],
                "dependencies": ["gh"]
            },
            {
                "id": "devops_consul_kv_backup",
                "name": "Consul KV Store Backup",
                "description": "Backup Consul key-value store",
                "command_template": "consul kv export {prefix} > {backup_file} && gzip {backup_file}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "prefix", "type": "string", "default": ""},
                    {"name": "backup_file", "type": "string", "default": "consul-backup-$(date +%Y%m%d-%H%M%S).json"}
                ],
                "examples": ["consul kv export > consul-backup.json"],
                "performance_hints": ["Automate backups", "Test restore procedures"],
                "dependencies": ["consul", "gzip"]
            },
            {
                "id": "devops_istio_canary_deploy",
                "name": "Istio Canary Deployment",
                "description": "Configure Istio for canary deployment",
                "command_template": "kubectl apply -f - <<EOF\napiVersion: networking.istio.io/v1beta1\nkind: VirtualService\nmetadata:\n  name: {service}\nspec:\n  http:\n  - match:\n    - headers:\n        canary:\n          exact: \"true\"\n    route:\n    - destination:\n        host: {service}\n        subset: {canary_version}\n      weight: {canary_weight}\n  - route:\n    - destination:\n        host: {service}\n        subset: {stable_version}\n      weight: {stable_weight}\nEOF",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "service", "type": "string", "required": True},
                    {"name": "canary_version", "type": "string", "required": True},
                    {"name": "stable_version", "type": "string", "required": True},
                    {"name": "canary_weight", "type": "int", "default": 10},
                    {"name": "stable_weight", "type": "int", "default": 90}
                ],
                "examples": ["kubectl apply -f virtualservice.yaml"],
                "performance_hints": ["Monitor golden signals", "Gradual traffic shift"],
                "dependencies": ["kubectl", "istio"]
            },
            {
                "id": "devops_fluentd_config_reload",
                "name": "Reload Fluentd Configuration",
                "description": "Hot reload Fluentd configuration",
                "command_template": "kill -USR2 $(cat /var/run/fluentd.pid) && fluentd --dry-run -c {config_file}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "config_file", "type": "string", "default": "/etc/fluentd/fluent.conf"}
                ],
                "examples": ["kill -USR2 $(cat /var/run/fluentd.pid)"],
                "performance_hints": ["Validate config syntax", "Monitor buffer usage"],
                "dependencies": ["fluentd"]
            },
            {
                "id": "devops_datadog_event_post",
                "name": "Post Datadog Deployment Event",
                "description": "Send deployment event to Datadog",
                "command_template": "curl -X POST https://api.datadoghq.com/api/v1/events -H 'DD-API-KEY: {api_key}' -H 'Content-Type: application/json' -d '{{\"title\":\"{title}\",\"text\":\"{text}\",\"tags\":{tags},\"alert_type\":\"{alert_type}\"}}' ",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "api_key", "type": "string", "required": True},
                    {"name": "title", "type": "string", "required": True},
                    {"name": "text", "type": "string", "required": True},
                    {"name": "tags", "type": "string", "default": "[\"deployment\"]"},
                    {"name": "alert_type", "type": "string", "default": "info"}
                ],
                "examples": ["curl -X POST https://api.datadoghq.com/api/v1/events -H 'DD-API-KEY: xxx'"],
                "performance_hints": ["Tag appropriately", "Correlate with metrics"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_packer_build_ami",
                "name": "Build AMI with Packer",
                "description": "Build AWS AMI using Packer",
                "command_template": "packer build -var 'aws_region={region}' -var 'instance_type={instance_type}' -parallel-builds={parallel} {template}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "region", "type": "string", "default": "us-east-1"},
                    {"name": "instance_type", "type": "string", "default": "t3.medium"},
                    {"name": "parallel", "type": "int", "default": 1},
                    {"name": "template", "type": "string", "required": True}
                ],
                "examples": ["packer build -var 'aws_region=us-west-2' template.json"],
                "performance_hints": ["Use spot instances", "Enable fast launch"],
                "dependencies": ["packer"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "devops_tekton_pipeline_run",
                "name": "Run Tekton Pipeline",
                "description": "Trigger Tekton CI/CD pipeline",
                "command_template": "tkn pipeline start {pipeline} --param {params} --workspace name={workspace},claimName={pvc} -n {namespace}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "pipeline", "type": "string", "required": True},
                    {"name": "params", "type": "string", "default": ""},
                    {"name": "workspace", "type": "string", "default": "source"},
                    {"name": "pvc", "type": "string", "required": True},
                    {"name": "namespace", "type": "string", "default": "default"}
                ],
                "examples": ["tkn pipeline start build-deploy --param git-url=https://github.com/repo"],
                "performance_hints": ["Use pipeline caching", "Parallelize tasks"],
                "dependencies": ["tkn"]
            },
            {
                "id": "devops_skaffold_dev",
                "name": "Skaffold Development Mode",
                "description": "Run Skaffold in development mode with hot reload",
                "command_template": "skaffold dev --port-forward --cleanup=false --cache-artifacts=true --profile={profile}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "profile", "type": "string", "default": "dev"}
                ],
                "examples": ["skaffold dev --port-forward"],
                "performance_hints": ["Use file sync", "Configure build cache"],
                "dependencies": ["skaffold"]
            },
            {
                "id": "devops_flux_reconcile",
                "name": "Flux GitOps Reconciliation",
                "description": "Force Flux to reconcile with Git repository",
                "command_template": "flux reconcile source git {source} -n {namespace} && flux reconcile kustomization {kustomization} -n {namespace}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "source", "type": "string", "required": True},
                    {"name": "kustomization", "type": "string", "required": True},
                    {"name": "namespace", "type": "string", "default": "flux-system"}
                ],
                "examples": ["flux reconcile source git flux-system"],
                "performance_hints": ["Monitor reconciliation", "Use image automation"],
                "dependencies": ["flux"]
            },
            {
                "id": "devops_buildah_container",
                "name": "Build Container with Buildah",
                "description": "Build OCI container without Docker daemon",
                "command_template": "buildah bud --layers --cache-from {cache} -t {image}:{tag} -f {dockerfile} {context}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "cache", "type": "string", "default": "localhost/cache"},
                    {"name": "image", "type": "string", "required": True},
                    {"name": "tag", "type": "string", "default": "latest"},
                    {"name": "dockerfile", "type": "string", "default": "Containerfile"},
                    {"name": "context", "type": "string", "default": "."}
                ],
                "examples": ["buildah bud --layers -t myapp:v1.0 ."],
                "performance_hints": ["Use layer caching", "Rootless builds"],
                "dependencies": ["buildah"]
            },
            {
                "id": "devops_podman_compose_up",
                "name": "Podman Compose Deployment",
                "description": "Deploy multi-container apps with Podman Compose",
                "command_template": "podman-compose -f {compose_file} -p {project} up -d --build --force-recreate",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "compose_file", "type": "string", "default": "docker-compose.yml"},
                    {"name": "project", "type": "string", "required": True}
                ],
                "examples": ["podman-compose -f docker-compose.yml up -d"],
                "performance_hints": ["Use pods for networking", "Enable systemd integration"],
                "dependencies": ["podman-compose"]
            },
            {
                "id": "devops_crossplane_claim",
                "name": "Create Crossplane Resource Claim",
                "description": "Provision cloud resources via Crossplane",
                "command_template": "kubectl apply -f - <<EOF\napiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: {name}\nspec:\n  parameters:\n    {parameters}\n  compositionRef:\n    name: {composition}\n  publishConnectionDetailsTo:\n    name: {secret}\nEOF",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "api_version", "type": "string", "required": True},
                    {"name": "kind", "type": "string", "required": True},
                    {"name": "name", "type": "string", "required": True},
                    {"name": "parameters", "type": "string", "required": True},
                    {"name": "composition", "type": "string", "required": True},
                    {"name": "secret", "type": "string", "required": True}
                ],
                "examples": ["kubectl apply -f database-claim.yaml"],
                "performance_hints": ["Use compositions", "Monitor sync status"],
                "dependencies": ["kubectl", "crossplane"]
            },
            {
                "id": "devops_kustomize_build",
                "name": "Build Kustomize Manifests",
                "description": "Build Kubernetes manifests with Kustomize",
                "command_template": "kustomize build {path} --enable-helm --load-restrictor LoadRestrictionsNone | kubectl apply -f -",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "path", "type": "string", "default": "."}
                ],
                "examples": ["kustomize build overlays/production | kubectl apply -f -"],
                "performance_hints": ["Use strategic merge", "Validate output"],
                "dependencies": ["kustomize", "kubectl"]
            },
            {
                "id": "devops_octopus_deploy_release",
                "name": "Create Octopus Deploy Release",
                "description": "Create and deploy release in Octopus Deploy",
                "command_template": "octo create-release --project {project} --version {version} --deployto {environment} --server {server} --apiKey {api_key}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "project", "type": "string", "required": True},
                    {"name": "version", "type": "string", "required": True},
                    {"name": "environment", "type": "string", "required": True},
                    {"name": "server", "type": "string", "required": True},
                    {"name": "api_key", "type": "string", "required": True}
                ],
                "examples": ["octo create-release --project MyApp --version 1.0.0 --deployto Production"],
                "performance_hints": ["Use channels", "Configure lifecycles"],
                "dependencies": ["octo"]
            },
            {
                "id": "devops_spinnaker_pipeline_execute",
                "name": "Execute Spinnaker Pipeline",
                "description": "Trigger Spinnaker deployment pipeline",
                "command_template": "spin pipeline execute --application {app} --name {pipeline} --parameter-file {params_file}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "app", "type": "string", "required": True},
                    {"name": "pipeline", "type": "string", "required": True},
                    {"name": "params_file", "type": "string", "default": "parameters.json"}
                ],
                "examples": ["spin pipeline execute --application myapp --name deploy-prod"],
                "performance_hints": ["Use pipeline templates", "Implement stages"],
                "dependencies": ["spin"]
            },
            {
                "id": "devops_rancher_cluster_import",
                "name": "Import Cluster to Rancher",
                "description": "Import existing Kubernetes cluster to Rancher",
                "command_template": "rancher clusters import --name {cluster_name} --kubeconfig {kubeconfig} --wait",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "cluster_name", "type": "string", "required": True},
                    {"name": "kubeconfig", "type": "string", "required": True}
                ],
                "examples": ["rancher clusters import --name production --kubeconfig ~/.kube/config"],
                "performance_hints": ["Configure RBAC", "Enable monitoring"],
                "dependencies": ["rancher"]
            },
            {
                "id": "devops_waypoint_deploy",
                "name": "Deploy with HashiCorp Waypoint",
                "description": "Build and deploy application using Waypoint",
                "command_template": "waypoint up -app={app} -workspace={workspace} -var={variables}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "app", "type": "string", "required": True},
                    {"name": "workspace", "type": "string", "default": "default"},
                    {"name": "variables", "type": "string", "default": ""}
                ],
                "examples": ["waypoint up -app=api -workspace=production"],
                "performance_hints": ["Use remote runners", "Configure plugins"],
                "dependencies": ["waypoint"]
            },
            {
                "id": "devops_nomad_job_run",
                "name": "Run Nomad Job",
                "description": "Submit and run job to Nomad cluster",
                "command_template": "nomad job run -check-index {index} -var-file={vars} {job_file}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "index", "type": "int", "default": 0},
                    {"name": "vars", "type": "string", "default": "vars.hcl"},
                    {"name": "job_file", "type": "string", "required": True}
                ],
                "examples": ["nomad job run -var-file=prod.vars api.nomad"],
                "performance_hints": ["Use job priorities", "Configure constraints"],
                "dependencies": ["nomad"]
            },
            {
                "id": "devops_pulumi_up",
                "name": "Pulumi Infrastructure Update",
                "description": "Update infrastructure using Pulumi",
                "command_template": "pulumi up --yes --stack {stack} --config {config} --parallel {parallel}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.HIGH_RISK,
                "parameters": [
                    {"name": "stack", "type": "string", "required": True},
                    {"name": "config", "type": "string", "default": ""},
                    {"name": "parallel", "type": "int", "default": 10}
                ],
                "examples": ["pulumi up --yes --stack production"],
                "performance_hints": ["Use policy packs", "Enable state locking"],
                "dependencies": ["pulumi"]
            },
            {
                "id": "devops_azure_devops_pipeline",
                "name": "Trigger Azure DevOps Pipeline",
                "description": "Queue Azure DevOps pipeline run",
                "command_template": "az pipelines run --id {pipeline_id} --org {organization} --project {project} --parameters {params}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "pipeline_id", "type": "int", "required": True},
                    {"name": "organization", "type": "string", "required": True},
                    {"name": "project", "type": "string", "required": True},
                    {"name": "params", "type": "string", "default": ""}
                ],
                "examples": ["az pipelines run --id 42 --org myorg --project myproject"],
                "performance_hints": ["Use pipeline caching", "Parallelize jobs"],
                "dependencies": ["az"]
            },
            {
                "id": "devops_circleci_job_trigger",
                "name": "Trigger CircleCI Job",
                "description": "Trigger CircleCI pipeline via API",
                "command_template": "curl -X POST https://circleci.com/api/v2/project/{vcs}/{org}/{project}/pipeline -H 'Circle-Token: {token}' -H 'Content-Type: application/json' -d '{{\"branch\":\"{branch}\",\"parameters\":{params}}}'",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "vcs", "type": "string", "default": "github"},
                    {"name": "org", "type": "string", "required": True},
                    {"name": "project", "type": "string", "required": True},
                    {"name": "token", "type": "string", "required": True},
                    {"name": "branch", "type": "string", "default": "main"},
                    {"name": "params", "type": "string", "default": "{}"}
                ],
                "examples": ["curl -X POST https://circleci.com/api/v2/project/github/myorg/myrepo/pipeline"],
                "performance_hints": ["Use workflows", "Cache dependencies"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_teamcity_build_trigger",
                "name": "Trigger TeamCity Build",
                "description": "Queue TeamCity build configuration",
                "command_template": "curl -X POST {teamcity_url}/app/rest/buildQueue -H 'Authorization: Bearer {token}' -H 'Content-Type: application/xml' -d '<build><buildType id=\"{build_config}\"/><properties><property name=\"{prop_name}\" value=\"{prop_value}\"/></properties></build>'",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "teamcity_url", "type": "string", "required": True},
                    {"name": "token", "type": "string", "required": True},
                    {"name": "build_config", "type": "string", "required": True},
                    {"name": "prop_name", "type": "string", "default": ""},
                    {"name": "prop_value", "type": "string", "default": ""}
                ],
                "examples": ["curl -X POST https://teamcity.company.com/app/rest/buildQueue"],
                "performance_hints": ["Use build chains", "Configure artifacts"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_bamboo_deployment",
                "name": "Trigger Bamboo Deployment",
                "description": "Create Bamboo deployment release",
                "command_template": "curl -X POST {bamboo_url}/rest/api/latest/deploy/project/{project_id}/version -u {credentials} -H 'Content-Type: application/json' -d '{{\"planResultKey\":\"{build_key}\",\"name\":\"{version}\"}}'",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "bamboo_url", "type": "string", "required": True},
                    {"name": "credentials", "type": "string", "required": True},
                    {"name": "project_id", "type": "int", "required": True},
                    {"name": "build_key", "type": "string", "required": True},
                    {"name": "version", "type": "string", "required": True}
                ],
                "examples": ["curl -X POST https://bamboo.company.com/rest/api/latest/deploy/project/123/version"],
                "performance_hints": ["Use deployment projects", "Configure environments"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_chef_knife_bootstrap",
                "name": "Bootstrap Node with Chef",
                "description": "Bootstrap new node with Chef configuration",
                "command_template": "knife bootstrap {host} -x {user} -P {password} --node-name {node_name} -r 'role[{role}]' --bootstrap-version {version}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "host", "type": "string", "required": True},
                    {"name": "user", "type": "string", "required": True},
                    {"name": "password", "type": "string", "required": True},
                    {"name": "node_name", "type": "string", "required": True},
                    {"name": "role", "type": "string", "required": True},
                    {"name": "version", "type": "string", "default": "latest"}
                ],
                "examples": ["knife bootstrap server.example.com -x root -P password --node-name web01"],
                "performance_hints": ["Use SSH keys", "Pre-stage cookbooks"],
                "dependencies": ["knife"]
            },
            {
                "id": "devops_puppet_apply",
                "name": "Apply Puppet Manifest",
                "description": "Apply Puppet configuration to node",
                "command_template": "puppet apply {manifest} --modulepath {module_path} --environment {environment} --noop --verbose",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "manifest", "type": "string", "required": True},
                    {"name": "module_path", "type": "string", "default": "/etc/puppetlabs/code/modules"},
                    {"name": "environment", "type": "string", "default": "production"}
                ],
                "examples": ["puppet apply site.pp --modulepath ./modules --noop"],
                "performance_hints": ["Use r10k for deployment", "Enable caching"],
                "dependencies": ["puppet"]
            },
            {
                "id": "devops_salt_highstate",
                "name": "Apply Salt Highstate",
                "description": "Apply Salt state configuration to minions",
                "command_template": "salt '{target}' state.highstate test={test} --output={output}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "target", "type": "string", "default": "*"},
                    {"name": "test", "type": "string", "default": "True"},
                    {"name": "output", "type": "string", "default": "highstate"}
                ],
                "examples": ["salt 'web*' state.highstate test=True"],
                "performance_hints": ["Use targeting", "Enable state cache"],
                "dependencies": ["salt"]
            },
            {
                "id": "devops_harbor_scan_image",
                "name": "Scan Image in Harbor Registry",
                "description": "Trigger vulnerability scan for image in Harbor",
                "command_template": "curl -X POST {harbor_url}/api/v2.0/projects/{project}/repositories/{repo}/artifacts/{tag}/scan -H 'Authorization: Basic {auth}'",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "harbor_url", "type": "string", "required": True},
                    {"name": "project", "type": "string", "required": True},
                    {"name": "repo", "type": "string", "required": True},
                    {"name": "tag", "type": "string", "required": True},
                    {"name": "auth", "type": "string", "required": True}
                ],
                "examples": ["curl -X POST https://harbor.company.com/api/v2.0/projects/library/repositories/app/artifacts/v1.0/scan"],
                "performance_hints": ["Configure scan policies", "Set CVE allowlists"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_artifactory_promote",
                "name": "Promote Artifact in JFrog",
                "description": "Promote artifact between repositories in Artifactory",
                "command_template": "jfrog rt copy {source_repo}/{artifact} {target_repo}/ --flat=false --props='{properties}'",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "source_repo", "type": "string", "required": True},
                    {"name": "artifact", "type": "string", "required": True},
                    {"name": "target_repo", "type": "string", "required": True},
                    {"name": "properties", "type": "string", "default": "status=promoted"}
                ],
                "examples": ["jfrog rt copy snapshots/app-1.0.jar releases/"],
                "performance_hints": ["Use properties", "Configure permissions"],
                "dependencies": ["jfrog"]
            },
            {
                "id": "devops_concourse_fly_execute",
                "name": "Execute Concourse Pipeline",
                "description": "Trigger Concourse CI pipeline execution",
                "command_template": "fly -t {target} trigger-job -j {pipeline}/{job} -w",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "target", "type": "string", "required": True},
                    {"name": "pipeline", "type": "string", "required": True},
                    {"name": "job", "type": "string", "required": True}
                ],
                "examples": ["fly -t main trigger-job -j my-pipeline/build -w"],
                "performance_hints": ["Use resource caching", "Parallelize tasks"],
                "dependencies": ["fly"]
            },
            {
                "id": "devops_drone_build_promote",
                "name": "Promote Drone CI Build",
                "description": "Promote Drone build to target environment",
                "command_template": "drone build promote {repo} {build} {environment}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [
                    {"name": "repo", "type": "string", "required": True},
                    {"name": "build", "type": "int", "required": True},
                    {"name": "environment", "type": "string", "required": True}
                ],
                "examples": ["drone build promote myorg/myrepo 42 production"],
                "performance_hints": ["Use build matrix", "Cache dependencies"],
                "dependencies": ["drone"]
            },
            {
                "id": "devops_backstage_catalog_register",
                "name": "Register Component in Backstage",
                "description": "Register component in Backstage software catalog",
                "command_template": "curl -X POST {backstage_url}/api/catalog/locations -H 'Authorization: Bearer {token}' -H 'Content-Type: application/json' -d '{{\"type\":\"url\",\"target\":\"{catalog_url}\"}}'",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "backstage_url", "type": "string", "required": True},
                    {"name": "token", "type": "string", "required": True},
                    {"name": "catalog_url", "type": "string", "required": True}
                ],
                "examples": ["curl -X POST https://backstage.company.com/api/catalog/locations"],
                "performance_hints": ["Use catalog-info.yaml", "Configure processors"],
                "dependencies": ["curl"]
            },
            {
                "id": "devops_opa_policy_test",
                "name": "Test OPA Policies",
                "description": "Test Open Policy Agent policies",
                "command_template": "opa test {policy_dir} -v --format {format}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [
                    {"name": "policy_dir", "type": "string", "default": "."},
                    {"name": "format", "type": "string", "default": "pretty"}
                ],
                "examples": ["opa test policies/ -v"],
                "performance_hints": ["Use coverage reports", "Organize policies"],
                "dependencies": ["opa"]
            },
            {
                "id": "devops_falco_rules_reload",
                "name": "Reload Falco Security Rules",
                "description": "Hot reload Falco runtime security rules",
                "command_template": "kill -USR1 $(cat /var/run/falco.pid) && falco --validate {rules_file}",
                "category": CommandCategory.DEVOPS_PIPELINE,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [
                    {"name": "rules_file", "type": "string", "default": "/etc/falco/falco_rules.yaml"}
                ],
                "examples": ["kill -USR1 $(cat /var/run/falco.pid)"],
                "performance_hints": ["Test rules first", "Monitor performance impact"],
                "dependencies": ["falco"]
            }
        ]
        
        # Convert command definitions to BashCommand objects
        for cmd_def in system_admin_commands + security_monitoring_commands + devops_pipeline_commands:
            try:
                cmd = BashCommand(
                    id=cmd_def["id"],
                    name=cmd_def["name"],
                    description=cmd_def["description"],
                    command_template=cmd_def["command_template"],
                    category=cmd_def["category"],
                    safety_level=cmd_def["safety_level"],
                    parameters=cmd_def["parameters"],
                    examples=cmd_def["examples"],
                    performance_hints=cmd_def["performance_hints"],
                    dependencies=cmd_def["dependencies"],
                    amd_ryzen_optimized=cmd_def.get("amd_ryzen_optimized", False),
                    parallel_execution=cmd_def.get("parallel_execution", False),
                    estimated_duration=cmd_def.get("estimated_duration", 0.0),
                    memory_requirement=cmd_def.get("memory_requirement", 0),
                    cpu_cores=cmd_def.get("cpu_cores", 1)
                )
                self.commands[cmd.id] = cmd
            except Exception as e:
                logger.error(f"Failed to create command {cmd_def.get('id', 'unknown')}: {str(e)}")
"""

def add_commands_to_file():
    """Add the missing commands to bash_god_mcp_server.py"""
    
    # Read the current file
    with open('bash_god_mcp_server.py', 'r') as f:
        content = f.read()
    
    # Find where to insert the new commands (after the existing security monitoring commands)
    # Look for the end of the current command definitions
    insert_pattern = r'(\s+# Convert command definitions to BashCommand objects)'
    
    # Find the position to insert
    match = re.search(insert_pattern, content)
    if match:
        insert_pos = match.start()
        
        # Insert the new commands before the conversion section
        new_content = content[:insert_pos] + ADDITIONAL_COMMANDS + content[insert_pos:]
        
        # Write the updated content
        with open('bash_god_mcp_server.py', 'w') as f:
            f.write(new_content)
        
        print("Successfully added missing commands to bash_god_mcp_server.py")
        return True
    else:
        print("Could not find insertion point in file")
        return False

if __name__ == "__main__":
    add_commands_to_file()
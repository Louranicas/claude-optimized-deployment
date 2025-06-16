#!/usr/bin/env python3
"""
Add missing security commands to bash_god_mcp_server.py
"""

# Security commands to add after the existing 5 security commands
SECURITY_COMMANDS_TO_ADD = '''
            },
            # Intrusion Detection Commands
            {
                "id": "sec_ids_snort",
                "name": "Snort IDS Monitoring",
                "description": "Monitor Snort intrusion detection system",
                "command_template": "snort -A console -q -c /etc/snort/snort.conf -i eth0",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [{"name": "interface", "type": "string", "default": "eth0"}],
                "examples": ["snort -A fast -c /etc/snort/snort.conf"],
                "performance_hints": ["Use unified2 output", "Tune rules for performance"],
                "dependencies": ["snort"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_suricata",
                "name": "Suricata IDS Status",
                "description": "Check Suricata IDS engine status",
                "command_template": "suricatasc -c 'show-all-rules' && suricatactl status",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["suricatasc -c stats"],
                "performance_hints": ["Enable multi-threading", "Use AF_PACKET"],
                "dependencies": ["suricata", "suricatasc"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "sec_ids_ossec",
                "name": "OSSEC HIDS Monitoring",
                "description": "Monitor OSSEC host intrusion detection",
                "command_template": "ossec-control status && tail -20 /var/ossec/logs/alerts/alerts.log",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ossec-control status"],
                "performance_hints": ["Regular log rotation", "Tune alert levels"],
                "dependencies": ["ossec-control"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_aide",
                "name": "AIDE File Integrity",
                "description": "Advanced Intrusion Detection Environment check",
                "command_template": "aide --check --config=/etc/aide/aide.conf",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["aide --init", "aide --update"],
                "performance_hints": ["Schedule during low usage", "Exclude temp files"],
                "dependencies": ["aide"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_tripwire",
                "name": "Tripwire Integrity Check",
                "description": "Run Tripwire file integrity monitoring",
                "command_template": "tripwire --check --interactive",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["tripwire --init", "tripwire --update"],
                "performance_hints": ["Regular database updates", "Focus on critical files"],
                "dependencies": ["tripwire"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_samhain",
                "name": "Samhain HIDS Check",
                "description": "Samhain host intrusion detection check",
                "command_template": "samhain -t check --foreground",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["samhain -t init"],
                "performance_hints": ["Use client/server mode", "Enable stealth mode"],
                "dependencies": ["samhain"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_rkhunter",
                "name": "Rootkit Hunter Scan",
                "description": "Scan for rootkits and backdoors",
                "command_template": "rkhunter --check --skip-keypress --report-warnings-only",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["rkhunter --update"],
                "performance_hints": ["Update signatures regularly", "Schedule scans"],
                "dependencies": ["rkhunter"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_chkrootkit",
                "name": "Chkrootkit Scanner",
                "description": "Check for known rootkits",
                "command_template": "chkrootkit -q | grep -v 'not infected'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["chkrootkit"],
                "performance_hints": ["Run from read-only media", "Compare results"],
                "dependencies": ["chkrootkit"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_fail2ban",
                "name": "Fail2ban Status",
                "description": "Monitor fail2ban intrusion prevention",
                "command_template": "fail2ban-client status && fail2ban-client status sshd",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["fail2ban-client banned"],
                "performance_hints": ["Tune ban times", "Monitor false positives"],
                "dependencies": ["fail2ban-client"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_ids_denyhosts",
                "name": "DenyHosts Monitor",
                "description": "Monitor SSH brute force prevention",
                "command_template": "denyhosts --purge && tail /var/log/denyhosts",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["denyhosts --sync"],
                "performance_hints": ["Regular purge old entries", "Sync with central server"],
                "dependencies": ["denyhosts"],
                "amd_ryzen_optimized": False
            },
            # Firewall Management Commands
            {
                "id": "sec_fw_iptables_list",
                "name": "IPTables Rules List",
                "description": "List all iptables firewall rules",
                "command_template": "iptables -L -n -v --line-numbers && iptables -t nat -L -n -v",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["iptables -L INPUT -n -v"],
                "performance_hints": ["Use -n for faster output", "Check all tables"],
                "dependencies": ["iptables"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_iptables_save",
                "name": "IPTables Rules Backup",
                "description": "Backup current iptables rules",
                "command_template": "iptables-save > /tmp/iptables-backup-$(date +%Y%m%d-%H%M%S).rules",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["iptables-save"],
                "performance_hints": ["Regular backups", "Version control rules"],
                "dependencies": ["iptables-save"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_nftables_list",
                "name": "NFTables Rules List",
                "description": "List nftables firewall rules",
                "command_template": "nft list ruleset",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["nft list table inet filter"],
                "performance_hints": ["More efficient than iptables", "Use sets for IPs"],
                "dependencies": ["nft"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_ufw_status",
                "name": "UFW Firewall Status",
                "description": "Check Uncomplicated Firewall status",
                "command_template": "ufw status verbose && ufw show raw",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ufw status numbered"],
                "performance_hints": ["Simple interface", "Good for basic needs"],
                "dependencies": ["ufw"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_firewalld_list",
                "name": "FirewallD Zone List",
                "description": "List FirewallD zones and rules",
                "command_template": "firewall-cmd --list-all-zones && firewall-cmd --get-active-zones",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["firewall-cmd --list-services"],
                "performance_hints": ["Zone-based management", "Runtime vs permanent"],
                "dependencies": ["firewall-cmd"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_conntrack",
                "name": "Connection Tracking",
                "description": "Monitor netfilter connection tracking",
                "command_template": "conntrack -L -o extended | head -50 && cat /proc/sys/net/netfilter/nf_conntrack_count",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["conntrack -L -p tcp"],
                "performance_hints": ["Monitor table size", "Tune hashsize"],
                "dependencies": ["conntrack"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_ipset_list",
                "name": "IPSet Management",
                "description": "Manage IP sets for efficient filtering",
                "command_template": "ipset list && ipset list -t",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ipset create blacklist hash:ip"],
                "performance_hints": ["Use for large IP lists", "Better performance"],
                "dependencies": ["ipset"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_rate_limit",
                "name": "Rate Limiting Rules",
                "description": "Configure connection rate limiting",
                "command_template": "iptables -L INPUT -n -v | grep -E 'recent|limit'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["iptables -m recent --help"],
                "performance_hints": ["Prevent brute force", "Tune thresholds"],
                "dependencies": ["iptables"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_geoip_check",
                "name": "GeoIP Blocking Status",
                "description": "Check GeoIP blocking rules",
                "command_template": "iptables -L -n -v | grep geoip",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["iptables -m geoip --help"],
                "performance_hints": ["Update GeoIP database", "Use ipset for efficiency"],
                "dependencies": ["iptables"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_fw_ddos_check",
                "name": "DDoS Protection Status",
                "description": "Check DDoS protection rules",
                "command_template": "iptables -L -n -v | grep -E 'syn|flood|limit' | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["iptables -L INPUT -n -v | grep DROP"],
                "performance_hints": ["SYN flood protection", "Connection limits"],
                "dependencies": ["iptables"],
                "amd_ryzen_optimized": False
            },
            # Security Auditing Commands
            {
                "id": "sec_audit_lynis_full",
                "name": "Lynis Full Security Audit",
                "description": "Comprehensive security auditing with Lynis",
                "command_template": "lynis audit system --pentest --quick",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["lynis audit system"],
                "performance_hints": ["Regular audits", "Track score improvements"],
                "dependencies": ["lynis"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_tiger",
                "name": "Tiger Security Audit",
                "description": "Run Tiger security auditing tool",
                "command_template": "tiger -q && tail -50 /var/log/tiger/security.report.*",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["tiger -B"],
                "performance_hints": ["Customize checks", "Review all findings"],
                "dependencies": ["tiger"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_openscap",
                "name": "OpenSCAP Compliance",
                "description": "SCAP security compliance checking",
                "command_template": "oscap info /usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["oscap xccdf eval --profile standard /path/to/content.xml"],
                "performance_hints": ["Use appropriate profiles", "Generate reports"],
                "dependencies": ["oscap"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_permissions",
                "name": "File Permission Audit",
                "description": "Audit file and directory permissions",
                "command_template": "find / -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -la {} \\; 2>/dev/null | head -50",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["find /usr/bin -perm -4000"],
                "performance_hints": ["Check SUID/SGID files", "Monitor changes"],
                "dependencies": ["find"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_accounts",
                "name": "User Account Audit",
                "description": "Audit user accounts and privileges",
                "command_template": "awk -F: '($3 == 0) {print $1}' /etc/passwd && grep -v '^#' /etc/sudoers | grep -v '^$'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["getent passwd | awk -F: '$3 == 0'"],
                "performance_hints": ["Check for UID 0", "Review sudo access"],
                "dependencies": ["awk", "grep"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_ssh_config",
                "name": "SSH Configuration Audit",
                "description": "Audit SSH server configuration",
                "command_template": "sshd -T | grep -E 'permitrootlogin|passwordauthentication|x11forwarding|allowusers'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["sshd -T | grep permit"],
                "performance_hints": ["Harden SSH config", "Use key-based auth"],
                "dependencies": ["sshd"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_kernel_params",
                "name": "Kernel Security Parameters",
                "description": "Audit kernel security parameters",
                "command_template": "sysctl -a | grep -E 'randomize|exec-shield|tcp_syncookies|icmp_echo_ignore'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["sysctl kernel.randomize_va_space"],
                "performance_hints": ["Enable security features", "Document changes"],
                "dependencies": ["sysctl"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_selinux",
                "name": "SELinux Audit",
                "description": "Audit SELinux status and denials",
                "command_template": "sestatus -v && ausearch -m avc -ts recent | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["semanage boolean -l"],
                "performance_hints": ["Don't disable SELinux", "Fix denials properly"],
                "dependencies": ["sestatus", "ausearch"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_apparmor",
                "name": "AppArmor Audit",
                "description": "Audit AppArmor profiles and status",
                "command_template": "aa-status && aa-unconfined --paranoid",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["aa-enforce /etc/apparmor.d/*"],
                "performance_hints": ["Create custom profiles", "Monitor denials"],
                "dependencies": ["aa-status"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_audit_password_policy",
                "name": "Password Policy Audit",
                "description": "Check password policy configuration",
                "command_template": "grep -E '^PASS_' /etc/login.defs && cat /etc/pam.d/common-password | grep -v '^#'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["chage -l username"],
                "performance_hints": ["Enforce strong passwords", "Regular expiry"],
                "dependencies": ["grep"],
                "amd_ryzen_optimized": False
            },
            # Vulnerability Scanning Commands
            {
                "id": "sec_vuln_nmap_scripts",
                "name": "Nmap Vulnerability Scripts",
                "description": "Run Nmap vulnerability detection scripts",
                "command_template": "nmap --script vuln localhost -p-",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [{"name": "target", "type": "string", "default": "localhost"}],
                "examples": ["nmap --script=smb-vuln* 192.168.1.0/24"],
                "performance_hints": ["Update script database", "Target specific services"],
                "dependencies": ["nmap"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "sec_vuln_nikto",
                "name": "Nikto Web Scanner",
                "description": "Web server vulnerability scanning",
                "command_template": "nikto -h http://localhost -o /tmp/nikto-report.html -Format html",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [{"name": "host", "type": "string", "default": "http://localhost"}],
                "examples": ["nikto -h https://example.com"],
                "performance_hints": ["Use plugins wisely", "Tune scan intensity"],
                "dependencies": ["nikto"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_vuln_openvas_check",
                "name": "OpenVAS Status Check",
                "description": "Check OpenVAS vulnerability scanner status",
                "command_template": "gvm-check-setup && systemctl status gvmd",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["gvm-start"],
                "performance_hints": ["Regular feed updates", "Schedule scans"],
                "dependencies": ["gvm-check-setup"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_vuln_wpscan",
                "name": "WordPress Scanner",
                "description": "WordPress vulnerability scanning",
                "command_template": "wpscan --url http://localhost/wordpress --enumerate ap,at,cb,dbe",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [{"name": "url", "type": "string", "default": "http://localhost/wordpress"}],
                "examples": ["wpscan --url http://site.com --enumerate u"],
                "performance_hints": ["Update database", "Use API token"],
                "dependencies": ["wpscan"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_vuln_sqlmap",
                "name": "SQL Injection Scanner",
                "description": "SQL injection vulnerability testing",
                "command_template": "sqlmap -u 'http://localhost/page?id=1' --batch --random-agent",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.HIGH_RISK,
                "parameters": [{"name": "url", "type": "string", "required": true}],
                "examples": ["sqlmap -u URL --dbs"],
                "performance_hints": ["Test safely", "Use --risk and --level"],
                "dependencies": ["sqlmap"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "sec_vuln_nuclei",
                "name": "Nuclei Scanner",
                "description": "Template-based vulnerability scanner",
                "command_template": "nuclei -u http://localhost -t cves/ -severity critical,high",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [{"name": "url", "type": "string", "default": "http://localhost"}],
                "examples": ["nuclei -l urls.txt -t nuclei-templates/"],
                "performance_hints": ["Update templates", "Use tags for filtering"],
                "dependencies": ["nuclei"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "sec_vuln_trivy",
                "name": "Container Vulnerability Scanner",
                "description": "Scan containers for vulnerabilities",
                "command_template": "trivy image alpine:latest",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "image", "type": "string", "default": "alpine:latest"}],
                "examples": ["trivy fs /path/to/project"],
                "performance_hints": ["Scan during CI/CD", "Cache databases"],
                "dependencies": ["trivy"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_vuln_grype",
                "name": "Grype Vulnerability Scanner",
                "description": "Container and filesystem vulnerability scanner",
                "command_template": "grype {target}",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "target", "type": "string", "default": "dir:."}],
                "examples": ["grype image:tag", "grype sbom:./sbom.json"],
                "performance_hints": ["Fast scanning", "SBOM support"],
                "dependencies": ["grype"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "sec_vuln_dependency_check",
                "name": "OWASP Dependency Check",
                "description": "Check dependencies for known vulnerabilities",
                "command_template": "dependency-check --project 'MyApp' --scan .",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [{"name": "path", "type": "string", "default": "."}],
                "examples": ["dependency-check --scan /path/to/project"],
                "performance_hints": ["Update CVE database", "CI/CD integration"],
                "dependencies": ["dependency-check"],
                "amd_ryzen_optimized": True
            },
            {
                "id": "sec_vuln_safety_check",
                "name": "Python Safety Check",
                "description": "Check Python dependencies for vulnerabilities",
                "command_template": "safety check --json",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["safety check -r requirements.txt"],
                "performance_hints": ["Regular checks", "Use in CI/CD"],
                "dependencies": ["safety"],
                "amd_ryzen_optimized": False
            },
            # Log Analysis Commands
            {
                "id": "sec_log_auth_failures",
                "name": "Authentication Failures",
                "description": "Analyze authentication failure logs",
                "command_template": "grep 'authentication failure' /var/log/auth.log | tail -50 | awk '{print $1, $2, $3, $14, $15}'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["journalctl -u sshd | grep Failed"],
                "performance_hints": ["Monitor patterns", "Alert on anomalies"],
                "dependencies": ["grep", "awk"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_sudo_usage",
                "name": "Sudo Usage Analysis",
                "description": "Analyze sudo command usage",
                "command_template": "grep sudo /var/log/auth.log | grep -v 'session opened' | tail -50",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["journalctl | grep sudo"],
                "performance_hints": ["Track privilege escalation", "Review commands"],
                "dependencies": ["grep"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_ssh_attacks",
                "name": "SSH Attack Detection",
                "description": "Detect SSH brute force attempts",
                "command_template": "grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -nr | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf"],
                "performance_hints": ["Use fail2ban", "Block repeat offenders"],
                "dependencies": ["grep", "awk", "sort"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_web_attacks",
                "name": "Web Attack Detection",
                "description": "Detect web application attacks",
                "command_template": "grep -E 'union.*select|<script|onclick|onerror' /var/log/apache2/access.log | tail -50",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["grep -E '(union|select|script)' /var/log/nginx/access.log"],
                "performance_hints": ["Use ModSecurity", "WAF rules"],
                "dependencies": ["grep"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_file_changes",
                "name": "File Change Detection",
                "description": "Monitor critical file modifications",
                "command_template": "aureport -f --summary && ausearch -f /etc/passwd -ts recent",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["auditctl -w /etc/passwd -p wa"],
                "performance_hints": ["Use auditd", "Monitor critical files"],
                "dependencies": ["aureport", "ausearch"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_process_exec",
                "name": "Process Execution Monitoring",
                "description": "Monitor process execution events",
                "command_template": "aureport -x --summary && ausearch -x /bin/bash -ts recent | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["auditctl -a exit,always -F arch=b64 -S execve"],
                "performance_hints": ["Track suspicious processes", "Baseline normal"],
                "dependencies": ["aureport", "ausearch"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_network_conn",
                "name": "Network Connection Logs",
                "description": "Analyze network connection logs",
                "command_template": "ss -tan state established | awk '{print $4, $5}' | grep -v Local | sort | uniq -c | sort -nr | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["netstat -tulpn | grep ESTABLISHED"],
                "performance_hints": ["Monitor connections", "Detect anomalies"],
                "dependencies": ["ss", "awk"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_kernel_events",
                "name": "Kernel Security Events",
                "description": "Monitor kernel security events",
                "command_template": "dmesg | grep -E 'segfault|protection fault|killed process' | tail -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["journalctl -k | grep -i denied"],
                "performance_hints": ["Check for exploits", "Monitor crashes"],
                "dependencies": ["dmesg", "grep"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_firewall_drops",
                "name": "Firewall Drop Analysis",
                "description": "Analyze firewall dropped packets",
                "command_template": "grep 'DPT=' /var/log/syslog | awk '{print $12, $13}' | sort | uniq -c | sort -nr | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["iptables -L -n -v | grep DROP"],
                "performance_hints": ["Identify attack patterns", "Tune rules"],
                "dependencies": ["grep", "awk"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_log_malware_detect",
                "name": "Malware Detection Logs",
                "description": "Check malware detection logs",
                "command_template": "grep -i 'infected\\|malware\\|virus' /var/log/clamav/clamav.log 2>/dev/null | tail -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["clamscan --infected --recursive /home"],
                "performance_hints": ["Regular scans", "Update signatures"],
                "dependencies": ["grep"],
                "amd_ryzen_optimized": False
            },
            # Additional Security Monitoring Commands
            {
                "id": "sec_mon_processes",
                "name": "Security Process Monitor",
                "description": "Monitor processes for security threats",
                "command_template": "ps aux | grep -E 'nc -l|/bin/sh|base64|eval' | grep -v grep",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ps aux | grep -E 'backdoor|reverse'"],
                "performance_hints": ["Look for suspicious patterns", "Check unknown processes"],
                "dependencies": ["ps", "grep"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_network_listen",
                "name": "Network Listeners Check",
                "description": "Check for unexpected network listeners",
                "command_template": "netstat -tulpn 2>/dev/null | grep LISTEN || ss -tulpn | grep LISTEN",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["lsof -i -P | grep LISTEN"],
                "performance_hints": ["Identify unauthorized services", "Check ports"],
                "dependencies": ["netstat", "ss"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_cron_jobs",
                "name": "Cron Job Security Check",
                "description": "Check for suspicious cron jobs",
                "command_template": "for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l 2>/dev/null; done",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ls -la /etc/cron.*"],
                "performance_hints": ["Check all users", "Look for backdoors"],
                "dependencies": ["crontab"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_startup_items",
                "name": "Startup Items Check",
                "description": "Check system startup items for persistence",
                "command_template": "systemctl list-unit-files --type=service | grep enabled && ls -la /etc/init.d/",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ls -la /etc/rc*.d/"],
                "performance_hints": ["Check for persistence", "Unknown services"],
                "dependencies": ["systemctl"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_shell_history",
                "name": "Shell History Analysis",
                "description": "Analyze shell command history",
                "command_template": "find /home -name '.bash_history' -exec grep -l 'wget\\|curl\\|nc\\|/dev/tcp' {} \\; 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["history | grep -E 'sudo|passwd'"],
                "performance_hints": ["Look for downloads", "Check commands"],
                "dependencies": ["find", "grep"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_tmp_files",
                "name": "Temporary Files Check",
                "description": "Check for suspicious files in temp directories",
                "command_template": "find /tmp /var/tmp -type f -executable -mtime -7 -ls 2>/dev/null",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ls -la /tmp /var/tmp"],
                "performance_hints": ["Check executables", "Recent files"],
                "dependencies": ["find"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_world_writable",
                "name": "World Writable Files",
                "description": "Find world-writable files and directories",
                "command_template": "find / -xdev -type f -perm -0002 -ls 2>/dev/null | head -50",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["find / -perm -0002 -type d"],
                "performance_hints": ["Security risk", "Fix permissions"],
                "dependencies": ["find"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_no_owner",
                "name": "Files Without Owner",
                "description": "Find files without valid owner",
                "command_template": "find / -xdev \\( -nouser -o -nogroup \\) -ls 2>/dev/null | head -50",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["find / -nouser"],
                "performance_hints": ["Orphaned files", "Clean up"],
                "dependencies": ["find"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_hidden_files",
                "name": "Hidden Files Check",
                "description": "Find suspicious hidden files",
                "command_template": "find / -name '.*' -type f -mtime -7 -ls 2>/dev/null | grep -v '/home' | head -50",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ls -la /tmp/.*"],
                "performance_hints": ["Check recent files", "Unusual locations"],
                "dependencies": ["find"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_mon_large_files",
                "name": "Large Files Detection",
                "description": "Find unusually large files",
                "command_template": "find / -xdev -type f -size +100M -ls 2>/dev/null | head -20",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["du -h / | sort -hr | head -20"],
                "performance_hints": ["Data exfiltration", "Disk usage"],
                "dependencies": ["find"],
                "amd_ryzen_optimized": False
            },
            # Network Security Monitoring
            {
                "id": "sec_net_connections",
                "name": "Active Network Analysis",
                "description": "Analyze active network connections",
                "command_template": "netstat -atnp 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ss -tnp | grep ESTAB"],
                "performance_hints": ["Connection tracking", "Geographic analysis"],
                "dependencies": ["netstat", "awk"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_net_dns_queries",
                "name": "DNS Query Monitoring",
                "description": "Monitor DNS queries for suspicious domains",
                "command_template": "tcpdump -i any -n port 53 -l 2>/dev/null | head -50",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.LOW_RISK,
                "parameters": [],
                "examples": ["tshark -f 'port 53'"],
                "performance_hints": ["Detect malware", "C&C communication"],
                "dependencies": ["tcpdump"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_net_packet_capture",
                "name": "Security Packet Capture",
                "description": "Capture packets for security analysis",
                "command_template": "tcpdump -i any -w /tmp/security-capture-$(date +%Y%m%d-%H%M%S).pcap -c 1000",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.MEDIUM_RISK,
                "parameters": [{"name": "count", "type": "int", "default": 1000}],
                "examples": ["tcpdump -r capture.pcap"],
                "performance_hints": ["Limited capture", "Analyze offline"],
                "dependencies": ["tcpdump"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_net_arp_cache",
                "name": "ARP Cache Monitoring",
                "description": "Monitor ARP cache for spoofing",
                "command_template": "arp -a && ip neigh show",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["watch arp -a"],
                "performance_hints": ["Detect ARP spoofing", "Monitor changes"],
                "dependencies": ["arp", "ip"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_net_route_check",
                "name": "Routing Table Security",
                "description": "Check routing table for malicious routes",
                "command_template": "ip route show && route -n",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["ip route get 8.8.8.8"],
                "performance_hints": ["Check default route", "Detect hijacking"],
                "dependencies": ["ip", "route"],
                "amd_ryzen_optimized": False
            },
            # Container Security
            {
                "id": "sec_container_docker",
                "name": "Docker Security Check",
                "description": "Check Docker security configuration",
                "command_template": "docker system info --format '{{json .SecurityOptions}}' && docker ps -a",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["docker inspect container_name"],
                "performance_hints": ["Check security options", "Review containers"],
                "dependencies": ["docker"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_container_images",
                "name": "Container Image Security",
                "description": "List and check container images",
                "command_template": "docker images --digests && docker history alpine:latest",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["docker image inspect image:tag"],
                "performance_hints": ["Check image sources", "Verify digests"],
                "dependencies": ["docker"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_container_runtime",
                "name": "Container Runtime Security",
                "description": "Check container runtime security",
                "command_template": "docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Command}}' && docker stats --no-stream",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["docker top container_name"],
                "performance_hints": ["Monitor resources", "Check processes"],
                "dependencies": ["docker"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_container_k8s_pods",
                "name": "Kubernetes Pod Security",
                "description": "Check Kubernetes pod security",
                "command_template": "kubectl get pods --all-namespaces -o jsonpath='{.items[*].spec.securityContext}'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["kubectl describe pod pod-name"],
                "performance_hints": ["Check security contexts", "Pod policies"],
                "dependencies": ["kubectl"],
                "amd_ryzen_optimized": False
            },
            {
                "id": "sec_container_secrets",
                "name": "Container Secrets Check",
                "description": "Check for exposed secrets in containers",
                "command_template": "docker inspect $(docker ps -q) | grep -E 'Env|Cmd' | grep -i 'pass\\|key\\|token' || echo 'No obvious secrets found'",
                "category": CommandCategory.SECURITY_MONITORING,
                "safety_level": SafetyLevel.SAFE,
                "parameters": [],
                "examples": ["docker secret ls"],
                "performance_hints": ["Use secret management", "Avoid env vars"],
                "dependencies": ["docker"],
                "amd_ryzen_optimized": False
            }'''

# Read the file
with open('bash_god_mcp_server.py', 'r') as f:
    content = f.read()

# Find where to insert the security commands
# Look for the closing bracket of the last security command
import re

# Find the pattern that ends the security commands section
pattern = r'(\s+\{\s*"id":\s*"sec_log_analysis"[^}]+\})\s*\]'
match = re.search(pattern, content, re.DOTALL)

if match:
    # Insert our new commands before the closing bracket
    insertion_point = match.end() - 1  # Before the ]
    
    # Create the new content
    new_content = content[:insertion_point] + SECURITY_COMMANDS_TO_ADD + content[insertion_point:]
    
    # Write the updated file
    with open('bash_god_mcp_server.py', 'w') as f:
        f.write(new_content)
    
    print("Successfully added security commands to bash_god_mcp_server.py")
else:
    print("Error: Could not find insertion point for security commands")
    print("Looking for alternative pattern...")
    
    # Try another pattern - find where security commands are defined
    pattern2 = r'(# SECURITY & MONITORING.*?)\n\s+security_commands = \[(.*?)\]'
    match2 = re.search(pattern2, content, re.DOTALL)
    
    if match2:
        print(f"Found security commands section at position {match2.start()}")
    else:
        print("Could not locate security commands section")
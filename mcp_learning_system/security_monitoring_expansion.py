#!/usr/bin/env python3
"""
Security Monitoring Command Expansion for Bash God MCP Server
Implements 115+ real security monitoring commands across 6 categories
"""

from typing import List, Dict, Any


class SecurityMonitoringExpansion:
    """Comprehensive security monitoring command expansion"""
    
    @staticmethod
    def get_network_security_commands() -> List[Dict[str, Any]]:
        """Network Security Commands (25 commands)"""
        return [
            # Port Scanning and Network Reconnaissance
            {
                "id": "sec_net_nmap_full",
                "name": "Nmap Full Port Scan",
                "description": "Comprehensive network port scanning",
                "command_template": "nmap -sS -sV -O -p- --script vuln {target}",
                "examples": [
                    "nmap -sS -sV -p 1-65535 192.168.1.0/24",
                    "nmap -sU -sV --top-ports 1000 192.168.1.1"
                ],
                "performance_hints": ["Use -T4 for faster scans", "Limit port ranges for speed"],
                "category": "security_monitoring",
                "subcategory": "network_security",
                "tags": ["network", "scanning", "reconnaissance"]
            },
            {
                "id": "sec_net_masscan",
                "name": "Masscan High-Speed Scanner",
                "description": "Ultra-fast port scanning for large networks",
                "command_template": "masscan -p1-65535 {target} --rate=1000",
                "examples": [
                    "masscan -p80,443,22,21 10.0.0.0/8 --rate=10000",
                    "masscan --top-ports 100 192.168.1.0/24"
                ],
                "performance_hints": ["Adjust --rate based on network", "Use --exclude for exceptions"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_zmap",
                "name": "ZMap Internet Scanner",
                "description": "High-speed single-port network scanner",
                "command_template": "zmap -p {port} -o results.csv {target}",
                "examples": [
                    "zmap -p 443 -B 10M 10.0.0.0/8",
                    "zmap -p 22 --probe-module=banner"
                ],
                "performance_hints": ["Bandwidth limiting with -B", "Use blacklists"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            
            # Firewall Management
            {
                "id": "sec_net_iptables_monitor",
                "name": "IPTables Live Monitor",
                "description": "Real-time monitoring of iptables activity",
                "command_template": "watch -n 1 'iptables -nvL | grep -E \"DROP|REJECT\"'",
                "examples": [
                    "iptables -L -n -v --line-numbers",
                    "iptables -Z && sleep 60 && iptables -nvL"
                ],
                "performance_hints": ["Monitor specific chains", "Use counters effectively"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_pf_monitor",
                "name": "PF Firewall Monitor",
                "description": "Monitor BSD packet filter firewall",
                "command_template": "pfctl -s all && pfctl -s info",
                "examples": [
                    "pfctl -s states",
                    "pfctl -s rules -v"
                ],
                "performance_hints": ["Regular state table cleanup", "Rule optimization"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            
            # Network Traffic Analysis
            {
                "id": "sec_net_tcpdump_analysis",
                "name": "TCPDump Traffic Analysis",
                "description": "Deep packet inspection and analysis",
                "command_template": "tcpdump -i any -nn -X -s0 'tcp port {port} and (tcp[tcpflags] & (tcp-syn|tcp-fin) != 0)'",
                "examples": [
                    "tcpdump -i eth0 -nn 'port 443 and tcp[tcpflags] & tcp-syn != 0'",
                    "tcpdump -w capture.pcap -C 100 -W 10"
                ],
                "performance_hints": ["Use BPF filters", "Rotate capture files"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_tshark_monitor",
                "name": "TShark Protocol Analysis",
                "description": "Command-line Wireshark for protocol analysis",
                "command_template": "tshark -i any -f 'tcp port {port}' -T fields -e ip.src -e ip.dst -e tcp.flags",
                "examples": [
                    "tshark -i eth0 -Y 'http.request.method == \"POST\"'",
                    "tshark -r capture.pcap -z io,stat,1"
                ],
                "performance_hints": ["Use display filters", "Export specific fields"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_netflow_analysis",
                "name": "NetFlow Traffic Analysis",
                "description": "Analyze network flow data for anomalies",
                "command_template": "nfdump -R /var/cache/nfdump -t {timeframe} -s ip/flows",
                "examples": [
                    "nfdump -R . -c 100 -o extended",
                    "nfdump -R . 'proto tcp and port 443'"
                ],
                "performance_hints": ["Aggregate flows", "Use time windows"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            
            # VPN and Secure Connections
            {
                "id": "sec_net_openvpn_monitor",
                "name": "OpenVPN Connection Monitor",
                "description": "Monitor OpenVPN server connections and status",
                "command_template": "openvpn --status /var/log/openvpn-status.log && tail -f /var/log/openvpn.log",
                "examples": [
                    "killall -USR2 openvpn && cat /var/run/openvpn.status",
                    "grep -i 'VERIFY ERROR' /var/log/openvpn.log"
                ],
                "performance_hints": ["Monitor connection states", "Track authentication failures"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_wireguard_monitor",
                "name": "WireGuard VPN Monitor",
                "description": "Monitor WireGuard tunnel status and peers",
                "command_template": "wg show all && wg show all dump",
                "examples": [
                    "wg show wg0 endpoints",
                    "wg show wg0 transfer"
                ],
                "performance_hints": ["Monitor handshake times", "Track data transfer"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_ipsec_monitor",
                "name": "IPSec Tunnel Monitor",
                "description": "Monitor IPSec VPN tunnels and SA status",
                "command_template": "ipsec status && ip xfrm state",
                "examples": [
                    "ipsec statusall",
                    "ip xfrm policy"
                ],
                "performance_hints": ["Monitor SA lifetime", "Check policy matches"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            
            # Network Intrusion Detection
            {
                "id": "sec_net_snort_monitor",
                "name": "Snort IDS Real-time",
                "description": "Real-time intrusion detection with Snort",
                "command_template": "snort -A console -q -c /etc/snort/snort.conf -i {interface}",
                "examples": [
                    "snort -A fast -c /etc/snort/snort.conf -l /var/log/snort",
                    "snort -A full -c /etc/snort/snort.conf -r capture.pcap"
                ],
                "performance_hints": ["Tune rule sets", "Use unified2 output"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_suricata_monitor",
                "name": "Suricata IDS Monitor",
                "description": "Monitor Suricata IDS/IPS engine",
                "command_template": "suricatasc -c 'show capture-mode' && tail -f /var/log/suricata/fast.log",
                "examples": [
                    "suricatasc -c stats",
                    "suricatasc -c 'pcap-file /tmp/test.pcap /tmp/'"
                ],
                "performance_hints": ["Enable multi-threading", "Use AF_PACKET mode"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_zeek_monitor",
                "name": "Zeek Network Monitor",
                "description": "Network security monitoring with Zeek (formerly Bro)",
                "command_template": "zeekctl status && tail -f /usr/local/zeek/logs/current/conn.log",
                "examples": [
                    "zeekctl top",
                    "zeek -C -r capture.pcap local"
                ],
                "performance_hints": ["Cluster deployment", "Custom scripts"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            
            # Additional Network Security Commands
            {
                "id": "sec_net_arp_monitor",
                "name": "ARP Table Monitor",
                "description": "Monitor ARP table for spoofing attacks",
                "command_template": "arpwatch -i {interface} -d && arp -a",
                "examples": [
                    "arp -n | grep -v incomplete",
                    "ip neigh show"
                ],
                "performance_hints": ["Detect ARP poisoning", "Monitor changes"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_dns_monitor",
                "name": "DNS Query Monitor",
                "description": "Monitor DNS queries for malicious domains",
                "command_template": "tcpdump -i any -nn port 53 | grep -E 'A\\?|AAAA\\?'",
                "examples": [
                    "dnstop -l 3 eth0",
                    "tshark -f 'port 53' -Y 'dns.qry.name contains \"suspicious\"'"
                ],
                "performance_hints": ["Check for tunneling", "Monitor query volume"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_ssl_monitor",
                "name": "SSL/TLS Monitor",
                "description": "Monitor SSL/TLS connections and certificates",
                "command_template": "ssldump -i {interface} -d",
                "examples": [
                    "tshark -f 'tcp port 443' -Y 'ssl.handshake.type == 1'",
                    "openssl s_client -connect host:443 -showcerts"
                ],
                "performance_hints": ["Check cipher suites", "Monitor cert expiry"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_netstat_monitor",
                "name": "Network Connections Monitor",
                "description": "Monitor active network connections",
                "command_template": "netstat -tunlp | grep LISTEN && ss -tunap",
                "examples": [
                    "netstat -an | grep ESTABLISHED",
                    "ss -tunap | grep -v LISTEN"
                ],
                "performance_hints": ["Use ss over netstat", "Monitor state changes"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_lsof_network",
                "name": "Network File Descriptors",
                "description": "Monitor network file descriptors and connections",
                "command_template": "lsof -i -P -n | grep -E 'LISTEN|ESTABLISHED'",
                "examples": [
                    "lsof -i :80",
                    "lsof -i @192.168.1.1"
                ],
                "performance_hints": ["Track process connections", "Monitor socket usage"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_bandwidth_monitor",
                "name": "Bandwidth Anomaly Detection",
                "description": "Monitor network bandwidth for anomalies",
                "command_template": "iftop -i {interface} -P -B",
                "examples": [
                    "vnstat -l -i eth0",
                    "bmon -p eth0"
                ],
                "performance_hints": ["Set thresholds", "Track patterns"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_packet_loss",
                "name": "Packet Loss Detection",
                "description": "Monitor for packet loss and network issues",
                "command_template": "mtr --report --report-cycles 100 {target}",
                "examples": [
                    "ping -f -c 1000 192.168.1.1",
                    "hping3 -S -p 80 -c 100 target.com"
                ],
                "performance_hints": ["Baseline normal loss", "Check multiple paths"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_wifi_monitor",
                "name": "WiFi Security Monitor",
                "description": "Monitor WiFi networks for security issues",
                "command_template": "airmon-ng start {interface} && airodump-ng {monitor_interface}",
                "examples": [
                    "iwlist scan | grep -E 'ESSID|Encryption'",
                    "iw dev wlan0 scan | grep -E 'SSID|RSN'"
                ],
                "performance_hints": ["Check encryption types", "Monitor rogue APs"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_vlan_monitor",
                "name": "VLAN Security Monitor",
                "description": "Monitor VLAN configuration and traffic",
                "command_template": "vconfig set_flag {interface} 1 && tcpdump -i {interface} -e vlan",
                "examples": [
                    "ip link show | grep vlan",
                    "bridge vlan show"
                ],
                "performance_hints": ["Check VLAN hopping", "Monitor trunk ports"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_route_monitor",
                "name": "Routing Table Monitor",
                "description": "Monitor routing table for unauthorized changes",
                "command_template": "ip route show && ip rule show",
                "examples": [
                    "route -n",
                    "ip route get 8.8.8.8"
                ],
                "performance_hints": ["Baseline routes", "Monitor changes"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            },
            {
                "id": "sec_net_bridge_monitor",
                "name": "Bridge Security Monitor",
                "description": "Monitor network bridges and spanning tree",
                "command_template": "brctl show && brctl showstp {bridge}",
                "examples": [
                    "bridge link show",
                    "bridge fdb show"
                ],
                "performance_hints": ["Check STP state", "Monitor MAC flooding"],
                "category": "security_monitoring",
                "subcategory": "network_security"
            }
        ]
    
    @staticmethod
    def get_system_security_commands() -> List[Dict[str, Any]]:
        """System Security Commands (25 commands)"""
        return [
            # File Integrity Monitoring
            {
                "id": "sec_sys_aide_check",
                "name": "AIDE Integrity Check",
                "description": "Advanced Intrusion Detection Environment file integrity check",
                "command_template": "aide --check --config=/etc/aide/aide.conf",
                "examples": [
                    "aide --init",
                    "aide --update"
                ],
                "performance_hints": ["Schedule during maintenance", "Exclude volatile files"],
                "category": "security_monitoring",
                "subcategory": "system_security",
                "tags": ["integrity", "file-monitoring", "compliance"]
            },
            {
                "id": "sec_sys_tripwire_scan",
                "name": "Tripwire Integrity Scan",
                "description": "Tripwire file and directory integrity monitoring",
                "command_template": "tripwire --check --severity 100",
                "examples": [
                    "tripwire --init",
                    "tripwire --check --interactive"
                ],
                "performance_hints": ["Regular database updates", "Focus on critical paths"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_samhain_check",
                "name": "Samhain HIDS Check",
                "description": "Samhain host-based intrusion detection system check",
                "command_template": "samhain -t check --foreground",
                "examples": [
                    "samhain --daemon",
                    "samhain -t update"
                ],
                "performance_hints": ["Use stealth mode", "Client-server architecture"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            
            # Access Control and Permissions
            {
                "id": "sec_sys_permission_audit",
                "name": "File Permission Audit",
                "description": "Audit file permissions for security issues",
                "command_template": "find / -type f \\( -perm -4000 -o -perm -2000 \\) -ls 2>/dev/null",
                "examples": [
                    "find /home -type f -perm 777",
                    "find /etc -type f -perm -o+w"
                ],
                "performance_hints": ["Regular scans", "Focus on sensitive directories"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_selinux_status",
                "name": "SELinux Status Check",
                "description": "Check SELinux security context and status",
                "command_template": "sestatus -v && semanage login -l",
                "examples": [
                    "getenforce",
                    "semanage boolean -l | grep on$"
                ],
                "performance_hints": ["Monitor denials", "Tune policies"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_apparmor_status",
                "name": "AppArmor Profile Status",
                "description": "Check AppArmor mandatory access control status",
                "command_template": "aa-status && aa-unconfined",
                "examples": [
                    "aa-enforce /etc/apparmor.d/*",
                    "aa-complain /usr/bin/firefox"
                ],
                "performance_hints": ["Profile all services", "Monitor violations"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            
            # Audit Logging and Compliance
            {
                "id": "sec_sys_auditd_monitor",
                "name": "Auditd Log Monitor",
                "description": "Monitor Linux audit daemon logs",
                "command_template": "aureport --summary && ausearch -ts today -m USER_LOGIN",
                "examples": [
                    "aureport --failed",
                    "ausearch -m SYSCALL -sv no"
                ],
                "performance_hints": ["Rotate logs regularly", "Focus on key events"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_syslog_security",
                "name": "Syslog Security Events",
                "description": "Monitor syslog for security-related events",
                "command_template": "grep -E 'Failed|Invalid|error|attack' /var/log/syslog | tail -100",
                "examples": [
                    "journalctl -p err -S today",
                    "grep 'authentication failure' /var/log/auth.log"
                ],
                "performance_hints": ["Use structured logging", "Forward to SIEM"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_lastlog_check",
                "name": "Login History Analysis",
                "description": "Analyze user login history for anomalies",
                "command_template": "lastlog && last -F | head -50",
                "examples": [
                    "last -f /var/log/wtmp",
                    "lastb -F"
                ],
                "performance_hints": ["Check unusual times", "Monitor failed logins"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            
            # System Hardening
            {
                "id": "sec_sys_kernel_hardening",
                "name": "Kernel Security Parameters",
                "description": "Check kernel security hardening parameters",
                "command_template": "sysctl -a | grep -E 'randomize|exec|ptrace'",
                "examples": [
                    "sysctl kernel.randomize_va_space",
                    "sysctl -a | grep yama"
                ],
                "performance_hints": ["Apply via sysctl.conf", "Test impact"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_service_audit",
                "name": "Service Security Audit",
                "description": "Audit running services for security",
                "command_template": "systemctl list-units --type=service --state=running",
                "examples": [
                    "systemctl list-dependencies",
                    "systemctl show -p PrivateNetwork,ProtectSystem"
                ],
                "performance_hints": ["Disable unnecessary services", "Use sandboxing"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_package_verify",
                "name": "Package Integrity Verify",
                "description": "Verify installed package integrity",
                "command_template": "rpm -Va | grep -E '^..5|^S' || dpkg -V",
                "examples": [
                    "debsums -c",
                    "rpm -V coreutils"
                ],
                "performance_hints": ["Regular verification", "Check critical packages"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            
            # Process and Memory Security
            {
                "id": "sec_sys_process_monitor",
                "name": "Suspicious Process Monitor",
                "description": "Monitor for suspicious process activity",
                "command_template": "ps auxf | grep -E 'defunct|<[^>]*>'",
                "examples": [
                    "ps aux --sort=-%cpu | head",
                    "pstree -p | grep -A5 -B5 suspicious"
                ],
                "performance_hints": ["Baseline normal processes", "Monitor resource usage"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_memory_forensics",
                "name": "Memory Security Analysis",
                "description": "Analyze memory for security threats",
                "command_template": "cat /proc/[0-9]*/maps | grep -E 'rwx|wx' | sort -u",
                "examples": [
                    "grep -r 'exec' /proc/*/status",
                    "volatility -f memory.dump pslist"
                ],
                "performance_hints": ["Check for injection", "Monitor anomalies"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_rootkit_scan",
                "name": "Rootkit Detection Scan",
                "description": "Scan system for rootkits and backdoors",
                "command_template": "rkhunter --check --skip-keypress --report-warnings-only",
                "examples": [
                    "chkrootkit -q",
                    "unhide sys proc"
                ],
                "performance_hints": ["Update signatures", "Run from clean media"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            
            # Additional System Security Commands
            {
                "id": "sec_sys_cron_audit",
                "name": "Cron Job Security Audit",
                "description": "Audit cron jobs for security issues",
                "command_template": "find /etc/cron* /var/spool/cron -type f -exec ls -la {} \\;",
                "examples": [
                    "crontab -l -u root",
                    "systemctl status crond"
                ],
                "performance_hints": ["Check all users", "Monitor changes"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_sudo_audit",
                "name": "Sudo Configuration Audit",
                "description": "Audit sudo configuration and usage",
                "command_template": "grep -v '^#' /etc/sudoers | grep -v '^$'",
                "examples": [
                    "visudo -c",
                    "grep sudo /var/log/auth.log"
                ],
                "performance_hints": ["Use NOPASSWD sparingly", "Log all sudo"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_pam_audit",
                "name": "PAM Configuration Audit",
                "description": "Audit Pluggable Authentication Modules",
                "command_template": "grep -v '^#' /etc/pam.d/* | grep -E 'required|requisite'",
                "examples": [
                    "pam_tally2 --user=root",
                    "grep pam_unix /etc/pam.d/*"
                ],
                "performance_hints": ["Test changes carefully", "Use pam_debug"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_mount_security",
                "name": "Mount Point Security Check",
                "description": "Check mount points for security options",
                "command_template": "mount | grep -E 'noexec|nosuid|nodev'",
                "examples": [
                    "findmnt -t ext4,xfs -o TARGET,FSTYPE,OPTIONS",
                    "grep -v '^#' /etc/fstab"
                ],
                "performance_hints": ["Use security options", "Check removable media"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_user_audit",
                "name": "User Account Audit",
                "description": "Audit user accounts for security issues",
                "command_template": "awk -F: '($3 < 1000) {print $1}' /etc/passwd",
                "examples": [
                    "grep ':0:' /etc/passwd",
                    "awk -F: '($2 == \"\") {print $1}' /etc/shadow"
                ],
                "performance_hints": ["Check for defaults", "Monitor additions"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_ssh_audit",
                "name": "SSH Configuration Audit",
                "description": "Audit SSH server configuration",
                "command_template": "sshd -T | grep -E 'permitrootlogin|passwordauthentication|pubkeyauthentication'",
                "examples": [
                    "grep -v '^#' /etc/ssh/sshd_config | grep -v '^$'",
                    "ssh-audit localhost"
                ],
                "performance_hints": ["Disable root login", "Use key-based auth"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_limits_check",
                "name": "Resource Limits Security",
                "description": "Check system resource limits for security",
                "command_template": "grep -v '^#' /etc/security/limits.conf | grep -v '^$'",
                "examples": [
                    "ulimit -a",
                    "cat /proc/sys/fs/file-max"
                ],
                "performance_hints": ["Set appropriate limits", "Monitor usage"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_tmp_security",
                "name": "Temporary Directory Security",
                "description": "Check temporary directories for security issues",
                "command_template": "find /tmp /var/tmp -type f -mtime +7 -ls",
                "examples": [
                    "ls -la /dev/shm",
                    "mount | grep '/tmp'"
                ],
                "performance_hints": ["Use separate partition", "Enable noexec"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_core_dump",
                "name": "Core Dump Security Check",
                "description": "Check core dump configuration for security",
                "command_template": "sysctl kernel.core_pattern && ulimit -c",
                "examples": [
                    "cat /proc/sys/kernel/core_pattern",
                    "coredumpctl list"
                ],
                "performance_hints": ["Disable if not needed", "Secure storage location"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            },
            {
                "id": "sec_sys_module_security",
                "name": "Kernel Module Security",
                "description": "Check loaded kernel modules for security",
                "command_template": "lsmod | grep -E 'usb|firewire|bluetooth'",
                "examples": [
                    "modprobe -c | grep blacklist",
                    "cat /proc/sys/kernel/modules_disabled"
                ],
                "performance_hints": ["Blacklist unnecessary", "Sign modules"],
                "category": "security_monitoring",
                "subcategory": "system_security"
            }
        ]
    
    @staticmethod
    def get_vulnerability_assessment_commands() -> List[Dict[str, Any]]:
        """Vulnerability Assessment Commands (20 commands)"""
        return [
            # Security Scanning Tools
            {
                "id": "sec_vuln_openvas_scan",
                "name": "OpenVAS Vulnerability Scan",
                "description": "Comprehensive vulnerability scanning with OpenVAS",
                "command_template": "gvm-cli --gmp-username admin --gmp-password pass socket --xml '<create_task><name>Scan</name><target id=\"{target_id}\"/></create_task>'",
                "examples": [
                    "gvm-start && gvm-check-setup",
                    "gvm-cli socket --pretty --xml '<get_tasks/>'"
                ],
                "performance_hints": ["Schedule scans", "Tune scan configs"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment",
                "tags": ["scanning", "vulnerability", "compliance"]
            },
            {
                "id": "sec_vuln_nessus_check",
                "name": "Nessus Scan Status",
                "description": "Check Nessus vulnerability scan status",
                "command_template": "curl -k -H 'X-ApiKeys: {api_key}' https://localhost:8834/scans",
                "examples": [
                    "nessuscli scan-list",
                    "nessuscli report-list"
                ],
                "performance_hints": ["Use scan templates", "Schedule off-hours"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_nikto_scan",
                "name": "Nikto Web Scanner",
                "description": "Web server vulnerability scanning",
                "command_template": "nikto -h {target} -output nikto_report.txt -Format txt",
                "examples": [
                    "nikto -h https://example.com -ssl",
                    "nikto -h 192.168.1.1 -p 80,443"
                ],
                "performance_hints": ["Update signatures", "Use plugins"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            
            # Patch Management
            {
                "id": "sec_vuln_patch_check",
                "name": "System Patch Status",
                "description": "Check system for missing security patches",
                "command_template": "yum check-update --security || apt list --upgradable 2>/dev/null | grep -i security",
                "examples": [
                    "dnf updateinfo list security",
                    "apt-get upgrade -s | grep -i security"
                ],
                "performance_hints": ["Automate patching", "Test before apply"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_kernel_check",
                "name": "Kernel Vulnerability Check",
                "description": "Check kernel version for known vulnerabilities",
                "command_template": "uname -r && curl -s https://www.kernel.org/releases.json | jq '.latest_stable'",
                "examples": [
                    "rpm -q --changelog kernel | grep CVE",
                    "dpkg -l | grep linux-image"
                ],
                "performance_hints": ["Track CVEs", "Plan reboots"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            
            # Penetration Testing
            {
                "id": "sec_vuln_metasploit",
                "name": "Metasploit Framework Check",
                "description": "Check for exploitable vulnerabilities",
                "command_template": "msfconsole -q -x 'db_nmap -sV {target}; hosts; exit'",
                "examples": [
                    "msfconsole -x 'search type:exploit platform:linux'",
                    "msfvenom -l payloads"
                ],
                "performance_hints": ["Update modules", "Use workspace"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_sqlmap",
                "name": "SQL Injection Testing",
                "description": "Test for SQL injection vulnerabilities",
                "command_template": "sqlmap -u '{url}' --batch --risk=1 --level=1",
                "examples": [
                    "sqlmap -u 'http://example.com/page?id=1' --dbs",
                    "sqlmap -r request.txt --batch"
                ],
                "performance_hints": ["Start with low risk", "Use tamper scripts"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            
            # Risk Assessment
            {
                "id": "sec_vuln_lynis_audit",
                "name": "Lynis Security Audit",
                "description": "Comprehensive system security audit",
                "command_template": "lynis audit system --quick",
                "examples": [
                    "lynis audit system",
                    "lynis show details TEST-ID"
                ],
                "performance_hints": ["Review warnings", "Track score"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_oscap_scan",
                "name": "OpenSCAP Compliance Scan",
                "description": "SCAP security compliance scanning",
                "command_template": "oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_standard /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
                "examples": [
                    "oscap oval eval rhel-8-oval.xml",
                    "oscap ds sds-validate scap-ds.xml"
                ],
                "performance_hints": ["Use profiles", "Generate reports"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            
            # Additional Vulnerability Commands
            {
                "id": "sec_vuln_wpscan",
                "name": "WordPress Vulnerability Scan",
                "description": "Scan WordPress sites for vulnerabilities",
                "command_template": "wpscan --url {url} --enumerate vp,vt,u",
                "examples": [
                    "wpscan --url https://example.com --api-token TOKEN",
                    "wpscan --url https://example.com --enumerate p"
                ],
                "performance_hints": ["Use API token", "Check plugins"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_dirb_scan",
                "name": "Directory Brute Force",
                "description": "Discover hidden directories and files",
                "command_template": "dirb {url} /usr/share/wordlists/dirb/common.txt",
                "examples": [
                    "gobuster dir -u http://example.com -w wordlist.txt",
                    "dirsearch -u http://example.com -e php,asp,aspx"
                ],
                "performance_hints": ["Use targeted wordlists", "Limit threads"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_testssl",
                "name": "SSL/TLS Vulnerability Test",
                "description": "Test SSL/TLS implementation for vulnerabilities",
                "command_template": "testssl.sh --fast {hostname}:443",
                "examples": [
                    "testssl.sh --severity HIGH example.com",
                    "sslscan example.com:443"
                ],
                "performance_hints": ["Check all protocols", "Verify ciphers"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_searchsploit",
                "name": "Exploit Database Search",
                "description": "Search for known exploits in exploit database",
                "command_template": "searchsploit {software} {version}",
                "examples": [
                    "searchsploit apache 2.4",
                    "searchsploit -m 12345"
                ],
                "performance_hints": ["Update database", "Verify exploits"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_docker_scan",
                "name": "Docker Security Scan",
                "description": "Scan Docker containers for vulnerabilities",
                "command_template": "docker scan {image} || trivy image {image}",
                "examples": [
                    "docker-bench-security",
                    "clair-scanner --ip 172.17.0.1 image:tag"
                ],
                "performance_hints": ["Scan all layers", "Check base images"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_dependency_check",
                "name": "Dependency Vulnerability Check",
                "description": "Check application dependencies for vulnerabilities",
                "command_template": "dependency-check --project {name} --scan {path}",
                "examples": [
                    "npm audit",
                    "safety check --json"
                ],
                "performance_hints": ["Regular updates", "Use in CI/CD"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_burp_scan",
                "name": "Burp Suite Scan Status",
                "description": "Check Burp Suite scan progress",
                "command_template": "curl -k https://localhost:1337/v0.1/scan/{scan_id}",
                "examples": [
                    "burpsuite --project-file=project.burp",
                    "burpsuite --user-config-file=config.json"
                ],
                "performance_hints": ["Use extensions", "Configure scope"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_zap_scan",
                "name": "OWASP ZAP Security Scan",
                "description": "OWASP ZAP automated security testing",
                "command_template": "zap-cli quick-scan --self-contained -r {url}",
                "examples": [
                    "zap-cli active-scan http://example.com",
                    "zap-cli alerts -l High"
                ],
                "performance_hints": ["Use contexts", "Configure authentication"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_grype_scan",
                "name": "Grype Vulnerability Scanner",
                "description": "Fast vulnerability scanner for containers",
                "command_template": "grype {image} -o json",
                "examples": [
                    "grype dir:/path/to/project",
                    "grype registry:image:tag"
                ],
                "performance_hints": ["Cache results", "Set severity threshold"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_nuclei_scan",
                "name": "Nuclei Template Scanner",
                "description": "Fast template-based vulnerability scanner",
                "command_template": "nuclei -u {url} -t cves/",
                "examples": [
                    "nuclei -l urls.txt -t nuclei-templates/",
                    "nuclei -u https://example.com -severity critical,high"
                ],
                "performance_hints": ["Update templates", "Use tags"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            },
            {
                "id": "sec_vuln_semgrep_scan",
                "name": "Semgrep Code Analysis",
                "description": "Static analysis for security vulnerabilities",
                "command_template": "semgrep --config=auto {path}",
                "examples": [
                    "semgrep --config=p/security-audit",
                    "semgrep --config=p/owasp-top-ten"
                ],
                "performance_hints": ["Use rulesets", "Integrate with CI"],
                "category": "security_monitoring",
                "subcategory": "vulnerability_assessment"
            }
        ]
    
    @staticmethod
    def get_incident_response_commands() -> List[Dict[str, Any]]:
        """Incident Response Commands (20 commands)"""
        return [
            # Security Event Detection
            {
                "id": "sec_ir_event_detection",
                "name": "Security Event Detection",
                "description": "Detect and analyze security events in real-time",
                "command_template": "tail -f /var/log/auth.log | grep -E 'Failed|Invalid|Attack'",
                "examples": [
                    "journalctl -f -u sshd | grep Failed",
                    "tail -f /var/log/messages | grep -i security"
                ],
                "performance_hints": ["Use log aggregation", "Set up alerts"],
                "category": "security_monitoring",
                "subcategory": "incident_response",
                "tags": ["detection", "monitoring", "real-time"]
            },
            {
                "id": "sec_ir_intrusion_analysis",
                "name": "Intrusion Analysis",
                "description": "Analyze potential intrusion attempts",
                "command_template": "grep -E 'su:|sudo:|sshd:' /var/log/auth.log | grep -i 'fail\\|invalid\\|bad'",
                "examples": [
                    "last -f /var/log/btmp | head -50",
                    "aureport --failed"
                ],
                "performance_hints": ["Correlate events", "Check timelines"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            
            # Forensics and Evidence Collection
            {
                "id": "sec_ir_memory_dump",
                "name": "Memory Dump Collection",
                "description": "Capture system memory for forensic analysis",
                "command_template": "dd if=/dev/mem of=memory_dump_$(date +%Y%m%d_%H%M%S).raw bs=1M",
                "examples": [
                    "lime -o memory.lime -f lime",
                    "avml memory.dump"
                ],
                "performance_hints": ["Use kernel modules", "Compress output"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_disk_imaging",
                "name": "Forensic Disk Imaging",
                "description": "Create forensic disk images for analysis",
                "command_template": "dd if=/dev/{device} of=disk_image.raw bs=4M status=progress conv=sync,noerror",
                "examples": [
                    "dcfldd if=/dev/sda of=image.dd hash=md5,sha256",
                    "ewfacquire /dev/sda"
                ],
                "performance_hints": ["Use write blockers", "Verify hashes"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_network_capture",
                "name": "Network Traffic Capture",
                "description": "Capture network traffic for incident analysis",
                "command_template": "tcpdump -i any -w incident_$(date +%Y%m%d_%H%M%S).pcap -C 100 -W 10",
                "examples": [
                    "tcpdump -i eth0 -w capture.pcap 'port 443 or port 80'",
                    "dumpcap -i any -w capture.pcapng"
                ],
                "performance_hints": ["Ring buffer capture", "Filter relevant traffic"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            
            # Threat Hunting
            {
                "id": "sec_ir_process_hunt",
                "name": "Suspicious Process Hunt",
                "description": "Hunt for suspicious processes and connections",
                "command_template": "lsof -i -P | grep -E 'ESTABLISHED|LISTEN' | grep -v '127.0.0.1'",
                "examples": [
                    "netstat -tulpn | grep -v '127.0.0.1'",
                    "ss -tulpn | grep ESTAB"
                ],
                "performance_hints": ["Check against baseline", "Look for anomalies"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_file_hunt",
                "name": "Malicious File Hunt",
                "description": "Search for potentially malicious files",
                "command_template": "find / -type f -mtime -7 -exec file {} \\; | grep -E 'executable|script'",
                "examples": [
                    "find /tmp -type f -perm -o+x",
                    "find / -name '*.php' -mtime -1"
                ],
                "performance_hints": ["Check unusual locations", "Verify file hashes"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_persistence_check",
                "name": "Persistence Mechanism Check",
                "description": "Check for malware persistence mechanisms",
                "command_template": "systemctl list-unit-files | grep enabled | grep -v '\\-\\-'",
                "examples": [
                    "crontab -l -u $(whoami)",
                    "ls -la /etc/systemd/system/"
                ],
                "performance_hints": ["Check all users", "Review startup items"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            
            # Incident Containment
            {
                "id": "sec_ir_isolate_host",
                "name": "Host Network Isolation",
                "description": "Isolate compromised host from network",
                "command_template": "iptables -I INPUT 1 -j DROP && iptables -I OUTPUT 1 -m state --state NEW -j DROP",
                "examples": [
                    "iptables -A INPUT -s 0.0.0.0/0 -j DROP",
                    "ip link set eth0 down"
                ],
                "performance_hints": ["Allow forensic access", "Document actions"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_kill_process",
                "name": "Malicious Process Termination",
                "description": "Terminate identified malicious processes",
                "command_template": "kill -9 {pid} && killall -9 {process_name}",
                "examples": [
                    "pkill -f suspicious_script",
                    "systemctl stop malicious.service"
                ],
                "performance_hints": ["Preserve evidence first", "Check for respawn"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            
            # Additional Incident Response Commands
            {
                "id": "sec_ir_timeline_analysis",
                "name": "Timeline Analysis",
                "description": "Create timeline of system events",
                "command_template": "find / -type f -printf '%T@ %Tc %p\\n' | sort -n | tail -1000",
                "examples": [
                    "ausearch -ts recent -m execve",
                    "journalctl --since '1 hour ago'"
                ],
                "performance_hints": ["Focus on timeframe", "Correlate events"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_hash_collection",
                "name": "File Hash Collection",
                "description": "Collect file hashes for threat intelligence",
                "command_template": "find {path} -type f -exec sha256sum {} \\; > file_hashes.txt",
                "examples": [
                    "md5sum /usr/bin/* > system_hashes.md5",
                    "sha1sum /etc/* 2>/dev/null"
                ],
                "performance_hints": ["Hash critical files", "Compare with known good"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_registry_backup",
                "name": "System Registry Backup",
                "description": "Backup system configuration for analysis",
                "command_template": "tar czf system_config_backup_$(date +%Y%m%d).tar.gz /etc /var/log",
                "examples": [
                    "cp -r /etc /backup/etc_$(date +%Y%m%d)",
                    "rsync -av /var/log/ /backup/logs/"
                ],
                "performance_hints": ["Include timestamps", "Secure backup location"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_connection_analysis",
                "name": "Connection Analysis",
                "description": "Analyze network connections for threats",
                "command_template": "netstat -an | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n",
                "examples": [
                    "ss -tan state established",
                    "lsof -i -n -P | grep ESTABLISHED"
                ],
                "performance_hints": ["Check geographic location", "Identify C2 servers"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_log_correlation",
                "name": "Log Correlation Analysis",
                "description": "Correlate logs across multiple sources",
                "command_template": "grep -h {pattern} /var/log/*.log | sort -k1,2",
                "examples": [
                    "multitail /var/log/auth.log /var/log/syslog",
                    "logtail /var/log/messages"
                ],
                "performance_hints": ["Use SIEM tools", "Create timelines"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_malware_analysis",
                "name": "Basic Malware Analysis",
                "description": "Perform basic static malware analysis",
                "command_template": "strings {file} | grep -E 'http|ftp|ssh|exec|system'",
                "examples": [
                    "file suspicious_file",
                    "hexdump -C suspicious_file | head -50"
                ],
                "performance_hints": ["Use sandbox", "Check VirusTotal"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_user_activity",
                "name": "User Activity Analysis",
                "description": "Analyze user activity during incident",
                "command_template": "last -F -n 50 && w && who -a",
                "examples": [
                    "ac -p",
                    "lastcomm --user username"
                ],
                "performance_hints": ["Check sudo usage", "Review command history"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_autorun_check",
                "name": "Autorun Locations Check",
                "description": "Check all autorun locations for malware",
                "command_template": "ls -la /etc/rc*.d/ /etc/init.d/ /etc/systemd/system/",
                "examples": [
                    "systemctl list-timers",
                    "find /home -name '.bashrc' -exec grep -l 'exec' {} \\;"
                ],
                "performance_hints": ["Check user profiles", "Review all init systems"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_data_exfil_check",
                "name": "Data Exfiltration Check",
                "description": "Check for signs of data exfiltration",
                "command_template": "nethogs -t | grep -E 'ssh|scp|ftp|rsync'",
                "examples": [
                    "iftop -P -n -N",
                    "tcpdump -i any -nn 'dst port 443 and greater 1000'"
                ],
                "performance_hints": ["Monitor large transfers", "Check unusual ports"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            },
            {
                "id": "sec_ir_restore_point",
                "name": "System Restore Point",
                "description": "Create system restore point before remediation",
                "command_template": "tar czf system_restore_$(date +%Y%m%d_%H%M%S).tar.gz --exclude=/proc --exclude=/sys /",
                "examples": [
                    "rsync -av / /backup/$(date +%Y%m%d)/",
                    "dd if=/dev/sda of=/backup/disk.img"
                ],
                "performance_hints": ["Verify backup integrity", "Test restore procedure"],
                "category": "security_monitoring",
                "subcategory": "incident_response"
            }
        ]
    
    @staticmethod
    def get_compliance_auditing_commands() -> List[Dict[str, Any]]:
        """Compliance and Auditing Commands (15 commands)"""
        return [
            # Regulatory Compliance
            {
                "id": "sec_comp_pci_check",
                "name": "PCI DSS Compliance Check",
                "description": "Check system for PCI DSS compliance requirements",
                "command_template": "oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
                "examples": [
                    "grep -r 'credit\\|card' /var/log/",
                    "find / -name '*.log' -exec grep -l 'card' {} \\;"
                ],
                "performance_hints": ["Regular scans", "Document findings"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing",
                "tags": ["compliance", "pci", "audit"]
            },
            {
                "id": "sec_comp_hipaa_audit",
                "name": "HIPAA Compliance Audit",
                "description": "Audit system for HIPAA compliance",
                "command_template": "lynis audit system --profile /etc/lynis/hipaa.prf",
                "examples": [
                    "find / -name '*.pdf' -o -name '*.doc*' | grep -i 'patient\\|medical'",
                    "aureport --user --summary"
                ],
                "performance_hints": ["Encrypt PHI data", "Access controls"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_gdpr_check",
                "name": "GDPR Compliance Check",
                "description": "Check data protection compliance for GDPR",
                "command_template": "find / -type f -name '*.sql' -o -name '*.db' | xargs grep -l 'email\\|phone\\|address'",
                "examples": [
                    "grep -r 'personal\\|private' /var/www/",
                    "find /backup -mtime +365 -name '*.sql'"
                ],
                "performance_hints": ["Data retention policies", "Encryption at rest"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            
            # Security Baseline Validation
            {
                "id": "sec_comp_cis_benchmark",
                "name": "CIS Benchmark Validation",
                "description": "Validate against CIS security benchmarks",
                "command_template": "cis-cat -b benchmarks/CIS_Ubuntu_20.04_Benchmark_v1.0.0-xccdf.xml -p Level1",
                "examples": [
                    "oscap xccdf eval --profile cis /usr/share/xml/scap/ssg/content/ssg-ubuntu2004-ds.xml",
                    "grep -v '^#' /etc/ssh/sshd_config | grep -v '^$'"
                ],
                "performance_hints": ["Automate checks", "Track scores"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_stig_validation",
                "name": "STIG Compliance Validation",
                "description": "Validate against DISA STIG requirements",
                "command_template": "oscap xccdf eval --profile stig /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
                "examples": [
                    "stigviewer -x /path/to/stig.xml",
                    "scap-workbench"
                ],
                "performance_hints": ["Use SCAP content", "Generate reports"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            
            # Audit Trail Management
            {
                "id": "sec_comp_audit_trail",
                "name": "Audit Trail Integrity Check",
                "description": "Verify audit trail integrity and completeness",
                "command_template": "aureport --input-logs --summary && ausearch -m USER_LOGIN --success",
                "examples": [
                    "aureport --auth --failed",
                    "ausearch -m ADD_USER -ts recent"
                ],
                "performance_hints": ["Remote logging", "Tamper protection"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_log_retention",
                "name": "Log Retention Compliance",
                "description": "Check log retention meets compliance requirements",
                "command_template": "find /var/log -name '*.log' -mtime +{days} | wc -l",
                "examples": [
                    "du -sh /var/log/* | sort -hr",
                    "logrotate -d /etc/logrotate.conf"
                ],
                "performance_hints": ["Compress old logs", "Archive securely"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            
            # Additional Compliance Commands
            {
                "id": "sec_comp_password_policy",
                "name": "Password Policy Compliance",
                "description": "Check password policy compliance",
                "command_template": "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs",
                "examples": [
                    "chage -l username",
                    "grep pam_pwquality /etc/pam.d/common-password"
                ],
                "performance_hints": ["Enforce complexity", "Regular rotation"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_access_review",
                "name": "Access Control Review",
                "description": "Review user access controls and permissions",
                "command_template": "find / -type f \\( -perm -4000 -o -perm -2000 \\) -ls",
                "examples": [
                    "getfacl -R /sensitive/data/",
                    "find /home -type f -perm 777"
                ],
                "performance_hints": ["Least privilege", "Regular reviews"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_encryption_audit",
                "name": "Encryption Compliance Audit",
                "description": "Audit encryption usage and compliance",
                "command_template": "dmsetup status | grep crypt && lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,TYPE",
                "examples": [
                    "cryptsetup luksDump /dev/sda2",
                    "find / -name '*.key' -o -name '*.pem'"
                ],
                "performance_hints": ["Full disk encryption", "Key management"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_patch_compliance",
                "name": "Patch Management Compliance",
                "description": "Verify patch management compliance",
                "command_template": "yum history list | head -20 || apt list --installed | grep security",
                "examples": [
                    "rpm -qa --last | head -50",
                    "grep -i security /var/log/yum.log"
                ],
                "performance_hints": ["Regular updates", "Change control"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_backup_compliance",
                "name": "Backup Compliance Verification",
                "description": "Verify backup procedures meet compliance",
                "command_template": "find /backup -name '*.tar.gz' -mtime -30 | wc -l",
                "examples": [
                    "duplicity collection-status file:///backup",
                    "restic -r /backup snapshots"
                ],
                "performance_hints": ["Test restores", "Offsite storage"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_incident_report",
                "name": "Incident Reporting Compliance",
                "description": "Generate compliance incident reports",
                "command_template": "aureport --summary --interpret && last -F | grep -v 'still logged in'",
                "examples": [
                    "aureport --anomaly --start recent",
                    "journalctl -p err -S yesterday"
                ],
                "performance_hints": ["Timely reporting", "Document actions"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_data_classification",
                "name": "Data Classification Audit",
                "description": "Audit data classification compliance",
                "command_template": "find / -name '*.conf' -o -name '*.cfg' | xargs grep -l 'secret\\|confidential\\|private'",
                "examples": [
                    "locate -i confidential",
                    "find /data -type f -exec file {} \\; | grep -i encrypted"
                ],
                "performance_hints": ["Label data properly", "Access based on classification"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            },
            {
                "id": "sec_comp_audit_report",
                "name": "Comprehensive Audit Report",
                "description": "Generate comprehensive compliance audit report",
                "command_template": "oscap xccdf generate report /tmp/oscap-results.xml > compliance_report_$(date +%Y%m%d).html",
                "examples": [
                    "compliance-checker --format html --output report.html",
                    "lynis audit system --report-file audit_$(date +%Y%m%d).txt"
                ],
                "performance_hints": ["Regular reporting", "Track improvements"],
                "category": "security_monitoring",
                "subcategory": "compliance_auditing"
            }
        ]
    
    @staticmethod
    def get_threat_intelligence_commands() -> List[Dict[str, Any]]:
        """Threat Intelligence Commands (10 commands)"""
        return [
            # Threat Feed Integration
            {
                "id": "sec_ti_feed_update",
                "name": "Threat Feed Update",
                "description": "Update threat intelligence feeds",
                "command_template": "curl -s https://rules.emergingthreats.net/open/suricata/emerging-threats.rules.tar.gz | tar xz -C /etc/suricata/rules/",
                "examples": [
                    "wget https://isc.sans.edu/feeds/suspiciousdomains_Low.txt",
                    "git pull https://github.com/stamparm/ipsum"
                ],
                "performance_hints": ["Automate updates", "Validate feeds"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence",
                "tags": ["threat-intel", "feeds", "ioc"]
            },
            {
                "id": "sec_ti_ioc_search",
                "name": "IOC Search",
                "description": "Search system for indicators of compromise",
                "command_template": "grep -r -f /tmp/ioc_list.txt /var/log/",
                "examples": [
                    "find / -name '*.log' -exec grep -H '192.168.1.100' {} \\;",
                    "yara -r /tmp/rules.yar /home/"
                ],
                "performance_hints": ["Use YARA rules", "Index logs"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            
            # Malware Detection
            {
                "id": "sec_ti_malware_scan",
                "name": "Malware Signature Scan",
                "description": "Scan for known malware signatures",
                "command_template": "clamscan -r --infected --bell /",
                "examples": [
                    "freshclam && clamscan -r /home",
                    "maldet -a /var/www"
                ],
                "performance_hints": ["Update signatures", "Schedule scans"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            {
                "id": "sec_ti_hash_lookup",
                "name": "File Hash Reputation Check",
                "description": "Check file hashes against threat intelligence",
                "command_template": "sha256sum {file} | cut -d' ' -f1 | xargs -I {} curl -s https://api.virustotal.com/v3/files/{}",
                "examples": [
                    "md5sum suspicious_file | cut -d' ' -f1",
                    "ssdeep -p suspicious_file"
                ],
                "performance_hints": ["Cache results", "Multiple sources"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            
            # Behavioral Analysis
            {
                "id": "sec_ti_behavior_analysis",
                "name": "Behavioral Anomaly Detection",
                "description": "Detect behavioral anomalies in system activity",
                "command_template": "osquery -A -j 'SELECT * FROM processes WHERE cmdline LIKE \"%eval%\" OR cmdline LIKE \"%base64%\";'",
                "examples": [
                    "sysdig -c spy_users",
                    "falco -r /etc/falco/falco_rules.yaml"
                ],
                "performance_hints": ["Baseline behavior", "Tune rules"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            {
                "id": "sec_ti_dns_intel",
                "name": "DNS Threat Intelligence",
                "description": "Check DNS queries against threat lists",
                "command_template": "dig +short {domain} @8.8.8.8 | grep -f /tmp/malicious_ips.txt",
                "examples": [
                    "host suspicious.domain.com",
                    "nslookup -type=txt _dmarc.domain.com"
                ],
                "performance_hints": ["Use RPZ", "Monitor queries"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            
            # Additional Threat Intelligence Commands
            {
                "id": "sec_ti_url_reputation",
                "name": "URL Reputation Check",
                "description": "Check URLs against reputation databases",
                "command_template": "curl -s 'https://www.urlvoid.com/scan/{url}' | grep -i 'detection\\|blacklist'",
                "examples": [
                    "wget --spider suspicious-url.com",
                    "curl -I suspicious-site.com"
                ],
                "performance_hints": ["Check redirects", "SSL verification"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            {
                "id": "sec_ti_ip_reputation",
                "name": "IP Reputation Lookup",
                "description": "Check IP addresses against threat databases",
                "command_template": "curl -s https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                "examples": [
                    "whois 192.168.1.1",
                    "geoiplookup 8.8.8.8"
                ],
                "performance_hints": ["Bulk lookups", "Cache results"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            {
                "id": "sec_ti_sandbox_submit",
                "name": "Sandbox Analysis Submit",
                "description": "Submit files for sandbox analysis",
                "command_template": "curl -F 'file=@{filename}' https://sandbox.api/analyze",
                "examples": [
                    "cuckoo submit suspicious_file",
                    "vboxmanage startvm MalwareAnalysis"
                ],
                "performance_hints": ["Automated submission", "Result correlation"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            },
            {
                "id": "sec_ti_threat_hunting",
                "name": "Proactive Threat Hunting",
                "description": "Hunt for threats using intelligence data",
                "command_template": "grep -r -E '(cmd\\.exe|powershell\\.exe).*(-enc|-e)' /var/log/",
                "examples": [
                    "find / -name '*.ps1' -mtime -7",
                    "auditctl -l | grep -i execve"
                ],
                "performance_hints": ["Use hypotheses", "Document findings"],
                "category": "security_monitoring",
                "subcategory": "threat_intelligence"
            }
        ]
    
    @staticmethod
    def get_all_security_commands() -> List[Dict[str, Any]]:
        """Get all 115+ security monitoring commands"""
        all_commands = []
        
        # Aggregate all command categories
        all_commands.extend(SecurityMonitoringExpansion.get_network_security_commands())
        all_commands.extend(SecurityMonitoringExpansion.get_system_security_commands())
        all_commands.extend(SecurityMonitoringExpansion.get_vulnerability_assessment_commands())
        all_commands.extend(SecurityMonitoringExpansion.get_incident_response_commands())
        all_commands.extend(SecurityMonitoringExpansion.get_compliance_auditing_commands())
        all_commands.extend(SecurityMonitoringExpansion.get_threat_intelligence_commands())
        
        return all_commands


def main():
    """Test the security monitoring expansion"""
    expansion = SecurityMonitoringExpansion()
    all_commands = expansion.get_all_security_commands()
    
    print(f"Total Security Monitoring Commands: {len(all_commands)}")
    
    # Count by subcategory
    subcategories = {}
    for cmd in all_commands:
        subcat = cmd.get('subcategory', 'unknown')
        subcategories[subcat] = subcategories.get(subcat, 0) + 1
    
    print("\nCommands by Subcategory:")
    for subcat, count in sorted(subcategories.items()):
        print(f"  {subcat}: {count}")
    
    # Verify all commands have required fields
    print("\nValidating command structure...")
    required_fields = ['id', 'name', 'description', 'command_template', 'category']
    
    for i, cmd in enumerate(all_commands):
        for field in required_fields:
            if field not in cmd:
                print(f"  WARNING: Command {i} missing field: {field}")
    
    print("\nSample commands:")
    for i in range(min(5, len(all_commands))):
        cmd = all_commands[i]
        print(f"\n  {cmd['id']}: {cmd['name']}")
        print(f"    Category: {cmd.get('category')}/{cmd.get('subcategory')}")
        print(f"    Command: {cmd['command_template']}")


if __name__ == "__main__":
    main()
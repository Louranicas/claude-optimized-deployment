#!/bin/bash
# Security Hardening Script for Linux Mint
# This script implements comprehensive security hardening procedures

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="/var/log/security_hardening.log"
exec 1> >(tee -a "$LOG_FILE")
exec 2> >(tee -a "$LOG_FILE" >&2)

echo -e "${BLUE}=== Linux Mint Security Hardening Script ===${NC}"
echo "Started at: $(date)"
echo "Log file: $LOG_FILE"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to backup configuration files
backup_config() {
    local file="$1"
    local backup_dir="/root/security_hardening_backups/$(date +%Y%m%d_%H%M%S)"
    
    if [[ -f "$file" ]]; then
        mkdir -p "$backup_dir"
        cp "$file" "$backup_dir/"
        print_status "Backed up $file to $backup_dir"
    fi
}

# Function to update system
update_system() {
    print_status "Updating system packages..."
    apt update && apt upgrade -y
    apt autoremove -y
    apt autoclean
}

# Function to configure automatic security updates
configure_auto_updates() {
    print_status "Configuring automatic security updates..."
    
    apt install -y unattended-upgrades apt-listchanges
    
    backup_config "/etc/apt/apt.conf.d/20auto-upgrades"
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    backup_config "/etc/apt/apt.conf.d/50unattended-upgrades"
    
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Whitelist {
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
Unattended-Upgrade::SyslogEnable "true";
Unattended-Upgrade::SyslogFacility "daemon";
EOF

    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades
}

# Function to configure firewall
configure_firewall() {
    print_status "Configuring firewall (UFW)..."
    
    # Install and enable UFW
    apt install -y ufw
    
    # Reset to defaults
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (customize port if needed)
    read -p "Enter SSH port (default 22): " ssh_port
    ssh_port=${ssh_port:-22}
    ufw allow "$ssh_port"/tcp
    
    # Allow common services (customize as needed)
    read -p "Allow HTTP (port 80)? [y/N]: " allow_http
    if [[ "$allow_http" =~ ^[Yy]$ ]]; then
        ufw allow 80/tcp
    fi
    
    read -p "Allow HTTPS (port 443)? [y/N]: " allow_https
    if [[ "$allow_https" =~ ^[Yy]$ ]]; then
        ufw allow 443/tcp
    fi
    
    # Enable logging
    ufw logging on
    
    # Enable firewall
    ufw --force enable
    
    print_status "Firewall configured and enabled"
}

# Function to secure SSH
secure_ssh() {
    print_status "Securing SSH configuration..."
    
    backup_config "/etc/ssh/sshd_config"
    
    # Generate new SSH host keys
    rm -f /etc/ssh/ssh_host_*
    ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ""
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ""
    
    # Configure SSH settings
    cat > /etc/ssh/sshd_config << 'EOF'
# SSH Security Configuration

# Protocol and encryption
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Key exchange, ciphers, and MACs
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

# Authentication
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Connection settings
Port 22
AddressFamily inet
ListenAddress 0.0.0.0
MaxAuthTries 3
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2

# Security settings
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PermitUserEnvironment no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Banner
Banner /etc/ssh/banner

# Subsystem
Subsystem sftp /usr/lib/openssh/sftp-server -l INFO

# Only allow specific users (uncomment and modify as needed)
# AllowUsers user1 user2
# AllowGroups ssh-users

# Deny specific users
# DenyUsers baduser1 baduser2
EOF

    # Create SSH banner
    cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                            SECURITY NOTICE
***************************************************************************
This system is for authorized users only. All activity is monitored and
logged. Unauthorized access is prohibited and will be prosecuted to the
full extent of the law.
***************************************************************************
EOF

    # Set correct permissions
    chmod 644 /etc/ssh/sshd_config
    chmod 644 /etc/ssh/banner
    chmod 600 /etc/ssh/ssh_host_*_key
    chmod 644 /etc/ssh/ssh_host_*_key.pub
    
    # Test SSH configuration
    if sshd -t; then
        systemctl restart sshd
        print_status "SSH configuration updated and service restarted"
    else
        print_error "SSH configuration test failed. Please check the configuration."
        exit 1
    fi
}

# Function to configure system security settings
configure_system_security() {
    print_status "Configuring system security settings..."
    
    # Kernel parameters for security
    backup_config "/etc/sysctl.conf"
    
    cat >> /etc/sysctl.conf << 'EOF'

# Security hardening parameters
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# IPv6 security (disable if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Memory security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1

# File system security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

    # Apply sysctl settings
    sysctl -p
    
    # Configure login definitions
    backup_config "/etc/login.defs"
    
    # Password aging and policies
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   7/' /etc/login.defs
    
    # Umask settings
    sed -i 's/^UMASK.*/UMASK           027/' /etc/login.defs
    
    # Configure limits
    backup_config "/etc/security/limits.conf"
    
    cat >> /etc/security/limits.conf << 'EOF'

# Security limits
* hard core 0
* soft nproc 65536
* hard nproc 65536
* soft nofile 65536
* hard nofile 65536
EOF
}

# Function to install and configure security tools
install_security_tools() {
    print_status "Installing security tools..."
    
    # Essential security tools
    apt install -y \
        fail2ban \
        rkhunter \
        chkrootkit \
        lynis \
        aide \
        apparmor \
        apparmor-utils \
        clamav \
        clamav-daemon \
        logwatch \
        psad \
        tiger \
        debsums
    
    # Configure fail2ban
    backup_config "/etc/fail2ban/jail.local"
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[apache-auth]
enabled = false

[apache-badbots]
enabled = false

[apache-noscript]
enabled = false

[apache-overflows]
enabled = false

[postfix]
enabled = false

[courierauth]
enabled = false
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    
    # Configure AppArmor
    systemctl enable apparmor
    systemctl start apparmor
    aa-enforce /etc/apparmor.d/*
    
    # Update ClamAV
    systemctl stop clamav-freshclam
    freshclam
    systemctl start clamav-freshclam
    systemctl enable clamav-freshclam
    
    # Configure rkhunter
    backup_config "/etc/rkhunter.conf"
    
    # Update rkhunter database
    rkhunter --update
    rkhunter --propupd
    
    # Configure AIDE
    aideinit
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
}

# Function to configure audit logging
configure_audit_logging() {
    print_status "Configuring audit logging..."
    
    apt install -y auditd audispd-plugins
    
    backup_config "/etc/audit/auditd.conf"
    backup_config "/etc/audit/audit.rules"
    
    # Configure audit rules
    cat > /etc/audit/audit.rules << 'EOF'
# Audit rules for security monitoring

# Delete all previous rules
-D

# Buffer Size
-b 8192

# Failure Mode
-f 1

# Audit the audit logs themselves
-w /var/log/audit/ -p wa -k auditlog

# Audit system configuration
-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/sudoers -p wa -k sudoers_changes

# Audit network configuration
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config

# Audit system administration
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Audit file system mounts
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

# Audit file deletions
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Audit privileged commands
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged_commands
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged_commands

# Make the configuration immutable
-e 2
EOF

    systemctl enable auditd
    systemctl start auditd
}

# Function to harden user accounts
harden_user_accounts() {
    print_status "Hardening user accounts..."
    
    # Install password quality library
    apt install -y libpam-pwquality
    
    backup_config "/etc/pam.d/common-password"
    
    # Configure password complexity
    sed -i 's/pam_pwquality.so.*/pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 reject_username enforce_for_root/' /etc/pam.d/common-password
    
    # Lock unused system accounts
    for user in games news uucp proxy www-data backup list irc gnats nobody; do
        if id "$user" &>/dev/null; then
            usermod -L -s /bin/false "$user"
            print_status "Locked account: $user"
        fi
    done
    
    # Set account lockout policy
    backup_config "/etc/pam.d/common-auth"
    
    if ! grep -q "pam_tally2" /etc/pam.d/common-auth; then
        sed -i '/pam_unix.so/a auth required pam_tally2.so deny=5 unlock_time=900 even_deny_root root_unlock_time=60' /etc/pam.d/common-auth
    fi
    
    # Configure automatic logout for inactive sessions
    echo "readonly TMOUT=900" >> /etc/bash.bashrc
    echo "readonly HISTFILE" >> /etc/bash.bashrc
    
    # Secure /tmp and /dev/shm
    if ! grep -q "tmpfs /tmp" /etc/fstab; then
        echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    fi
    
    if ! grep -q "tmpfs /dev/shm" /etc/fstab; then
        echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab
    fi
}

# Function to configure file permissions
secure_file_permissions() {
    print_status "Securing file permissions..."
    
    # Secure important files
    chmod 644 /etc/passwd
    chmod 600 /etc/shadow
    chmod 644 /etc/group
    chmod 600 /boot/grub/grub.cfg
    chmod 600 /etc/ssh/sshd_config
    
    # Remove world-writable files (with caution)
    find / -path /proc -prune -o -type f -perm -002 -exec chmod o-w {} + 2>/dev/null || true
    
    # Find and report SUID/SGID files
    find / -path /proc -prune -o -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} + 2>/dev/null > /root/suid_sgid_files.txt
    print_status "SUID/SGID files listed in /root/suid_sgid_files.txt"
    
    # Secure cron directories
    chmod 700 /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly
    chmod 600 /etc/crontab
    
    # Remove unnecessary packages
    apt autoremove --purge -y
}

# Function to configure log monitoring
configure_log_monitoring() {
    print_status "Configuring log monitoring..."
    
    # Configure logwatch
    backup_config "/etc/logwatch/conf/logwatch.conf"
    
    cat > /etc/logwatch/conf/logwatch.conf << 'EOF'
# Logwatch configuration
MailTo = root
MailFrom = logwatch@localhost
Print = Yes
Save = /var/cache/logwatch
Range = yesterday
Detail = Med
Service = All
mailer = "/usr/sbin/sendmail -t"
EOF

    # Configure log rotation
    backup_config "/etc/logrotate.conf"
    
    cat > /etc/logrotate.d/security << 'EOF'
/var/log/auth.log /var/log/fail2ban.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 640 root adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
}

# Function to create security monitoring script
create_security_monitoring() {
    print_status "Creating security monitoring script..."
    
    cat > /usr/local/bin/security_check.sh << 'EOF'
#!/bin/bash
# Daily security check script

REPORT_FILE="/var/log/daily_security_report.log"
DATE=$(date)

{
    echo "=== Daily Security Report - $DATE ==="
    echo
    
    echo "=== System Updates ==="
    apt list --upgradable 2>/dev/null | head -20
    echo
    
    echo "=== Failed Login Attempts ==="
    grep "Failed password" /var/log/auth.log | tail -10
    echo
    
    echo "=== Root Kit Check ==="
    rkhunter --check --skip-keypress --report-warnings-only
    echo
    
    echo "=== File System Check ==="
    aide --check | head -20
    echo
    
    echo "=== Network Connections ==="
    netstat -tulpn | grep LISTEN
    echo
    
    echo "=== Disk Usage ==="
    df -h
    echo
    
    echo "=== System Load ==="
    uptime
    echo
    
    echo "=== Recent System Changes ==="
    find /etc -type f -mtime -1 -exec ls -l {} \;
    echo
    
} > "$REPORT_FILE"

# Email report if mail is configured
if command -v mail >/dev/null 2>&1; then
    mail -s "Daily Security Report - $(hostname)" root < "$REPORT_FILE"
fi
EOF

    chmod +x /usr/local/bin/security_check.sh
    
    # Add to daily cron
    cat > /etc/cron.daily/security_check << 'EOF'
#!/bin/bash
/usr/local/bin/security_check.sh
EOF
    
    chmod +x /etc/cron.daily/security_check
}

# Function to configure network security
configure_network_security() {
    print_status "Configuring network security..."
    
    # Disable unused network services
    systemctl disable cups-browsed 2>/dev/null || true
    systemctl stop cups-browsed 2>/dev/null || true
    
    # Configure TCP wrappers
    backup_config "/etc/hosts.allow"
    backup_config "/etc/hosts.deny"
    
    cat > /etc/hosts.deny << 'EOF'
# Deny all by default
ALL: ALL
EOF
    
    cat > /etc/hosts.allow << 'EOF'
# Allow SSH from local network (modify as needed)
sshd: 192.168.0.0/16
sshd: 10.0.0.0/8
sshd: 172.16.0.0/12
sshd: 127.0.0.1
EOF
    
    # Install and configure psad (Port Scan Attack Detector)
    if command -v psad >/dev/null 2>&1; then
        backup_config "/etc/psad/psad.conf"
        
        sed -i 's/EMAIL_ADDRESSES.*/EMAIL_ADDRESSES root@localhost;/' /etc/psad/psad.conf
        sed -i 's/HOSTNAME.*/HOSTNAME '$(hostname)';/' /etc/psad/psad.conf
        
        systemctl enable psad
        systemctl start psad
    fi
}

# Function to create security checklist
create_security_checklist() {
    print_status "Creating security checklist..."
    
    cat > /root/security_checklist.txt << 'EOF'
=== Linux Mint Security Hardening Checklist ===

POST-HARDENING MANUAL TASKS:

1. User Management:
   [ ] Create non-root administrative users
   [ ] Set up SSH key authentication
   [ ] Disable password authentication for SSH
   [ ] Review and remove unnecessary user accounts

2. Services Review:
   [ ] Review running services: systemctl list-unit-files --state=enabled
   [ ] Disable unnecessary services
   [ ] Configure service-specific security settings

3. Network Security:
   [ ] Review firewall rules: ufw status verbose
   [ ] Configure port-specific access controls
   [ ] Set up VPN access if needed
   [ ] Review /etc/hosts.allow and /etc/hosts.deny

4. Monitoring:
   [ ] Configure centralized logging if needed
   [ ] Set up email alerts for security events
   [ ] Test backup and recovery procedures
   [ ] Schedule regular security audits

5. Application Security:
   [ ] Review installed applications
   [ ] Configure application-specific security settings
   [ ] Set up application firewalls if needed
   [ ] Configure SELinux/AppArmor profiles

6. Data Protection:
   [ ] Set up disk encryption
   [ ] Configure backup encryption
   [ ] Review file permissions on sensitive data
   [ ] Implement data loss prevention measures

7. Incident Response:
   [ ] Create incident response procedures
   [ ] Set up forensic tools
   [ ] Configure automated responses
   [ ] Test incident response procedures

8. Compliance:
   [ ] Review compliance requirements
   [ ] Configure compliance monitoring
   [ ] Generate compliance reports
   [ ] Schedule compliance audits

=== Security Tools Commands ===

Daily Security Commands:
- System scan: lynis audit system
- Rootkit check: rkhunter --check
- File integrity: aide --check
- Security updates: apt list --upgradable
- Log analysis: logwatch --detail=high

Weekly Security Commands:
- Full system scan: clamscan -r /
- Network scan: nmap -sS localhost
- Password audit: john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow
- Vulnerability scan: nessus (if installed)

Monthly Security Commands:
- Security audit: tiger
- Compliance check: lynis audit dockerfile (if applicable)
- Backup verification: restore test
- Penetration testing: external security assessment

=== Important Files to Monitor ===
- /etc/passwd, /etc/shadow, /etc/group
- /etc/ssh/sshd_config
- /etc/sudoers
- /var/log/auth.log, /var/log/syslog
- /etc/crontab, /etc/cron.*/*

=== Security Contacts ===
- Local Security Team: [TO BE FILLED]
- Incident Response: [TO BE FILLED]
- System Administrator: [TO BE FILLED]

EOF

    print_status "Security checklist created at /root/security_checklist.txt"
}

# Function to generate security report
generate_security_report() {
    print_status "Generating security hardening report..."
    
    REPORT_FILE="/root/security_hardening_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "=== Linux Mint Security Hardening Report ==="
        echo "Generated: $(date)"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Distribution: $(lsb_release -d | cut -f2)"
        echo
        
        echo "=== Hardening Steps Completed ==="
        echo "✓ System packages updated"
        echo "✓ Automatic security updates configured"
        echo "✓ Firewall (UFW) configured and enabled"
        echo "✓ SSH service hardened"
        echo "✓ System security parameters configured"
        echo "✓ Security tools installed and configured"
        echo "✓ Audit logging configured"
        echo "✓ User accounts hardened"
        echo "✓ File permissions secured"
        echo "✓ Log monitoring configured"
        echo "✓ Security monitoring script created"
        echo "✓ Network security configured"
        echo
        
        echo "=== Security Tools Installed ==="
        echo "- fail2ban (intrusion prevention)"
        echo "- rkhunter (rootkit detection)"
        echo "- chkrootkit (rootkit detection)"
        echo "- lynis (security auditing)"
        echo "- aide (file integrity monitoring)"
        echo "- apparmor (mandatory access control)"
        echo "- clamav (antivirus)"
        echo "- logwatch (log analysis)"
        echo "- psad (port scan detection)"
        echo "- auditd (system auditing)"
        echo
        
        echo "=== Current Security Status ==="
        echo "Firewall Status:"
        ufw status
        echo
        
        echo "SSH Configuration:"
        sshd -T | grep -E "(port|permitrootlogin|passwordauthentication|pubkeyauthentication)"
        echo
        
        echo "Fail2ban Status:"
        fail2ban-client status
        echo
        
        echo "Running Services:"
        systemctl list-unit-files --state=enabled --type=service | head -20
        echo
        
        echo "=== Recommendations ==="
        echo "1. Review the security checklist: /root/security_checklist.txt"
        echo "2. Test SSH access with key-based authentication"
        echo "3. Configure email notifications for security alerts"
        echo "4. Schedule regular security audits with Lynis"
        echo "5. Set up centralized logging if managing multiple systems"
        echo "6. Configure backup and disaster recovery procedures"
        echo "7. Implement monitoring for critical system changes"
        echo "8. Consider additional security measures based on threat model"
        echo
        
        echo "=== Next Steps ==="
        echo "1. Reboot the system to ensure all changes take effect"
        echo "2. Test all services and applications"
        echo "3. Verify remote access functionality"
        echo "4. Complete manual security tasks from checklist"
        echo "5. Schedule regular security maintenance"
        
    } > "$REPORT_FILE"
    
    print_status "Security hardening report saved to $REPORT_FILE"
}

# Main execution function
main() {
    print_status "Starting Linux Mint security hardening..."
    
    # Check prerequisites
    check_root
    
    # Create backup directory
    mkdir -p /root/security_hardening_backups
    
    # Execute hardening steps
    update_system
    configure_auto_updates
    configure_firewall
    secure_ssh
    configure_system_security
    install_security_tools
    configure_audit_logging
    harden_user_accounts
    secure_file_permissions
    configure_log_monitoring
    create_security_monitoring
    configure_network_security
    create_security_checklist
    generate_security_report
    
    print_status "Security hardening completed successfully!"
    print_warning "Please review the security checklist and report in /root/"
    print_warning "It is recommended to reboot the system to ensure all changes take effect"
    
    echo
    echo -e "${GREEN}=== Security Hardening Summary ===${NC}"
    echo "✓ System updated and configured for automatic security updates"
    echo "✓ Firewall configured and enabled"
    echo "✓ SSH service hardened with secure configuration"
    echo "✓ Security tools installed and configured"
    echo "✓ System monitoring and logging enhanced"
    echo "✓ User accounts and file permissions secured"
    echo "✓ Network security measures implemented"
    echo
    echo "Review the complete report and checklist in /root/"
    echo "Log file: $LOG_FILE"
}

# Execute main function
main "$@"
#!/bin/bash
# Memory and Storage Optimization for 32GB DDR5 + NVMe SSD + HDD setup
# Optimized for development workloads on high-end AMD system

# Memory optimization settings
optimize_memory() {
    echo "=== Optimizing Memory Settings ==="
    
    # Kernel memory parameters
    cat > /tmp/memory-optimization.conf << 'EOF'
# Memory optimization for 32GB DDR5 system
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.dirty_background_ratio=1
vm.dirty_ratio=50
vm.dirty_writeback_centisecs=100
vm.dirty_expire_centisecs=200
vm.min_free_kbytes=131072
vm.zone_reclaim_mode=0

# Memory overcommit settings
vm.overcommit_memory=1
vm.overcommit_ratio=80

# Huge pages configuration (beneficial for large applications)
vm.nr_hugepages=2048
kernel.shmmax=17179869184
kernel.shmall=4194304

# Network buffer optimization
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.rmem_default=262144
net.core.wmem_default=262144
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
net.ipv4.tcp_congestion_control=bbr

# File system optimization
fs.file-max=2097152
fs.inotify.max_user_watches=1048576
fs.inotify.max_user_instances=1024
fs.inotify.max_queued_events=32768
EOF

    sudo cp /tmp/memory-optimization.conf /etc/sysctl.d/99-memory-optimization.conf
    sudo sysctl -p /etc/sysctl.d/99-memory-optimization.conf
    
    echo "Memory optimization applied"
}

# Storage optimization for NVMe SSD + HDD hybrid setup
optimize_storage() {
    echo "=== Optimizing Storage Configuration ==="
    
    # Detect NVMe and HDD devices
    NVME_DEVICE=$(lsblk -d -n -o NAME,ROTA | grep "0$" | head -1 | awk '{print $1}')
    HDD_DEVICE=$(lsblk -d -n -o NAME,ROTA | grep "1$" | head -1 | awk '{print $1}')
    
    echo "NVMe Device: /dev/$NVME_DEVICE"
    echo "HDD Device: /dev/$HDD_DEVICE"
    
    # NVMe SSD optimizations
    if [ -n "$NVME_DEVICE" ]; then
        echo "Optimizing NVMe SSD..."
        
        # Set I/O scheduler to none/noop for NVMe (best for SSDs)
        echo none | sudo tee /sys/block/$NVME_DEVICE/queue/scheduler
        
        # Disable read-ahead for NVMe (SSDs don't benefit from it)
        sudo blockdev --setra 0 /dev/$NVME_DEVICE
        
        # Set optimal queue depth
        echo 32 | sudo tee /sys/block/$NVME_DEVICE/queue/nr_requests
        
        # Enable NCQ (Native Command Queuing)
        echo 31 | sudo tee /sys/block/$NVME_DEVICE/queue/iosched/quantum
    fi
    
    # HDD optimizations
    if [ -n "$HDD_DEVICE" ]; then
        echo "Optimizing HDD..."
        
        # Set I/O scheduler to deadline for HDD
        echo deadline | sudo tee /sys/block/$HDD_DEVICE/queue/scheduler
        
        # Increase read-ahead for HDD
        sudo blockdev --setra 4096 /dev/$HDD_DEVICE
        
        # Set larger queue depth for HDD
        echo 128 | sudo tee /sys/block/$HDD_DEVICE/queue/nr_requests
    fi
    
    # Create optimized mount options
    cat > /tmp/storage-mounts << 'EOF'
# Optimized mount options for development environment
# Add these to /etc/fstab

# NVMe SSD partitions (replace UUID with actual UUIDs)
# UUID=nvme-root-uuid / ext4 defaults,noatime,discard,commit=120 0 1
# UUID=nvme-home-uuid /home ext4 defaults,noatime,discard,commit=120 0 2

# Development workspace on NVMe (for active projects)
# UUID=nvme-dev-uuid /home/dev ext4 defaults,noatime,discard,commit=60 0 2

# HDD storage (for archives, backups, large files)
# UUID=hdd-storage-uuid /home/storage ext4 defaults,relatime,commit=300 0 2

# tmpfs for build acceleration (uses RAM)
tmpfs /tmp/build tmpfs defaults,size=16G,mode=1777 0 0
tmpfs /tmp/cargo-cache tmpfs defaults,size=8G,mode=1777 0 0
tmpfs /tmp/ccache tmpfs defaults,size=8G,mode=1777 0 0
EOF

    echo "Storage optimization configurations created in /tmp/storage-mounts"
    echo "Review and add appropriate entries to /etc/fstab"
}

# Set up intelligent storage hierarchy
setup_storage_hierarchy() {
    echo "=== Setting up Storage Hierarchy ==="
    
    # Create development directory structure
    mkdir -p ~/dev/{active,archive,cache,tmp}
    mkdir -p ~/storage/{backup,media,docs,downloads}
    
    # Set up symbolic links for optimal placement
    # Active projects on NVMe, archived projects on HDD
    
    # Create cache directories on tmpfs/NVMe
    mkdir -p ~/.cache/{cargo,rustc,ccache,nodejs,pip}
    
    # Environment variables for cache optimization
    cat >> ~/.bashrc << 'EOF'

# Storage hierarchy environment variables
export DEV_ACTIVE="$HOME/dev/active"      # Current projects (NVMe)
export DEV_ARCHIVE="$HOME/dev/archive"    # Old projects (HDD)
export DEV_CACHE="$HOME/dev/cache"        # Build cache (NVMe)
export STORAGE_ROOT="$HOME/storage"       # Long-term storage (HDD)

# Cache locations optimized for speed
export CARGO_HOME="$HOME/.cache/cargo"
export RUSTUP_HOME="$HOME/.cache/rustup"
export CCACHE_DIR="$HOME/.cache/ccache"
export NPM_CONFIG_CACHE="$HOME/.cache/nodejs"
export PIP_CACHE_DIR="$HOME/.cache/pip"

# Use tmpfs for temporary build files
export TMPDIR="/tmp/build"
export CARGO_TARGET_DIR="/tmp/cargo-cache/target"

# Aliases for storage management
alias dev-active='cd $DEV_ACTIVE'
alias dev-archive='cd $DEV_ARCHIVE'
alias storage='cd $STORAGE_ROOT'

# Function to move project to archive (HDD)
archive-project() {
    if [ -z "$1" ]; then
        echo "Usage: archive-project <project-name>"
        return 1
    fi
    
    local project="$1"
    if [ -d "$DEV_ACTIVE/$project" ]; then
        echo "Archiving $project to HDD storage..."
        mv "$DEV_ACTIVE/$project" "$DEV_ARCHIVE/"
        echo "Project $project moved to archive"
    else
        echo "Project $project not found in active development"
    fi
}

# Function to restore project from archive
restore-project() {
    if [ -z "$1" ]; then
        echo "Usage: restore-project <project-name>"
        return 1
    fi
    
    local project="$1"
    if [ -d "$DEV_ARCHIVE/$project" ]; then
        echo "Restoring $project from archive..."
        mv "$DEV_ARCHIVE/$project" "$DEV_ACTIVE/"
        echo "Project $project restored to active development"
    else
        echo "Project $project not found in archive"
    fi
}

# Function to clean development caches
clean-dev-cache() {
    echo "Cleaning development caches..."
    du -sh ~/.cache/* 2>/dev/null | head -10
    
    # Clean Rust cache
    if command -v cargo &> /dev/null; then
        cargo clean
        echo "Cargo cache cleaned"
    fi
    
    # Clean ccache
    if command -v ccache &> /dev/null; then
        ccache -C
        echo "ccache cleaned"
    fi
    
    # Clean npm cache
    if command -v npm &> /dev/null; then
        npm cache clean --force
        echo "npm cache cleaned"
    fi
    
    echo "Cache cleanup complete"
}

# Function to show storage usage
storage-usage() {
    echo "=== Storage Usage Summary ==="
    echo
    echo "Development directories:"
    du -sh ~/dev/* 2>/dev/null
    echo
    echo "Cache directories:"
    du -sh ~/.cache/* 2>/dev/null | head -10
    echo
    echo "Disk usage by filesystem:"
    df -h | grep -E "^/dev|tmpfs"
    echo
    echo "NVMe temperature and health:"
    sudo smartctl -A /dev/nvme0 | grep -E "Temperature|Available_Spare|Percentage_Used" 2>/dev/null || echo "smartctl not available"
}
EOF

    echo "Storage hierarchy configured"
    echo "Available commands:"
    echo "  archive-project <name>  - Move project to HDD archive"
    echo "  restore-project <name>  - Restore project from archive"
    echo "  clean-dev-cache        - Clean all development caches"
    echo "  storage-usage          - Show storage usage summary"
}

# Set up ZRAM for additional memory compression
setup_zram() {
    echo "=== Setting up ZRAM ==="
    
    sudo apt install -y zram-config
    
    # Configure ZRAM for 8GB compressed swap
    cat > /tmp/zram-config << 'EOF'
# ZRAM configuration for 32GB system
# Use 25% of RAM for compressed swap
ZRAM_SIZE="8G"
ZRAM_PRIORITY=100
ZRAM_ALGORITHM="lz4"
EOF

    sudo cp /tmp/zram-config /etc/default/zramswap
    sudo systemctl restart zramswap
    
    echo "ZRAM configured with 8GB compressed swap"
}

# Monitor memory and storage performance
monitor_memory_storage() {
    echo "=== Memory and Storage Monitor ==="
    
    while true; do
        clear
        echo "=== System Memory and Storage Monitor - $(date) ==="
        echo
        
        echo "--- Memory Usage ---"
        free -h
        echo
        
        echo "--- Swap Usage ---"
        swapon --show=NAME,SIZE,USED,PRIO,TYPE
        echo
        
        echo "--- Storage I/O ---"
        iostat -h 1 1 | tail -n +4
        echo
        
        echo "--- Top Memory Consumers ---"
        ps aux --sort=-%mem | head -6 | awk '{printf "%-10s %6s %6s %s\n", $1, $4, $6, $11}'
        echo
        
        echo "--- Disk Usage ---"
        df -h | grep -E "^/dev|tmpfs" | awk '{printf "%-20s %8s %8s %8s %5s %s\n", $1, $2, $3, $4, $5, $6}'
        echo
        
        echo "--- Cache Sizes ---"
        du -sh ~/.cache/* 2>/dev/null | head -5
        
        sleep 3
    done
}

# Create storage optimization service
create_storage_service() {
    echo "=== Creating Storage Optimization Service ==="
    
    cat > /tmp/storage-optimizer.service << 'EOF'
[Unit]
Description=Storage Optimization Service
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/optimize-storage.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    cat > /tmp/optimize-storage.sh << 'EOF'
#!/bin/bash
# Storage optimization script

# Apply I/O scheduler optimizations
for device in /sys/block/nvme*; do
    if [ -d "$device" ]; then
        echo none > "$device/queue/scheduler" 2>/dev/null
        echo 0 > "$device/queue/read_ahead_kb" 2>/dev/null
    fi
done

for device in /sys/block/sd*; do
    if [ -d "$device" ]; then
        echo deadline > "$device/queue/scheduler" 2>/dev/null
        echo 4096 > "$device/queue/read_ahead_kb" 2>/dev/null
    fi
done

# Enable transparent huge pages
echo madvise > /sys/kernel/mm/transparent_hugepage/enabled
echo defer > /sys/kernel/mm/transparent_hugepage/defrag

# Optimize dirty page writeback
echo 100 > /proc/sys/vm/dirty_writeback_centisecs
echo 200 > /proc/sys/vm/dirty_expire_centisecs
EOF

    sudo cp /tmp/optimize-storage.sh /usr/local/bin/optimize-storage.sh
    sudo chmod +x /usr/local/bin/optimize-storage.sh
    sudo cp /tmp/storage-optimizer.service /etc/systemd/system/
    sudo systemctl enable storage-optimizer.service
    
    echo "Storage optimization service created and enabled"
}

# Main execution
echo "Memory and Storage Optimization Suite"
echo "======================================"
echo
echo "Available functions:"
echo "  optimize_memory        - Apply memory optimizations"
echo "  optimize_storage       - Apply storage optimizations"
echo "  setup_storage_hierarchy - Create intelligent storage layout"
echo "  setup_zram            - Configure compressed swap"
echo "  monitor_memory_storage - Start monitoring dashboard"
echo "  create_storage_service - Create optimization service"
echo
echo "Run individual functions or execute this script to apply all optimizations"

# If script is run directly, apply all optimizations
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    echo "Applying all optimizations..."
    optimize_memory
    optimize_storage
    setup_storage_hierarchy
    setup_zram
    create_storage_service
    echo "All optimizations applied!"
fi
#!/bin/bash
# Restore backups created by thread safety fixer

BACKUP_DIR=".thread_safety_backups"

if [ ! -d "$BACKUP_DIR" ]; then
    echo "No backups found"
    exit 1
fi

echo "Restoring files from backup..."

find "$BACKUP_DIR" -name "*.backup" | while read backup; do
    # Get original path
    original="${backup#$BACKUP_DIR/}"
    original="${original%.backup}"
    
    echo "Restoring $original"
    cp "$backup" "$original"
done

echo "✅ Files restored from backup"

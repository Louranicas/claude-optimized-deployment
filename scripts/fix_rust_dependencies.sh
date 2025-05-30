#!/bin/bash
# Fix Rust build dependencies

echo "Installing required system dependencies for Rust build..."

# Check if we're on WSL or Linux
if grep -qi microsoft /proc/version; then
    echo "Detected WSL environment"
    # Install required packages for WSL
    sudo apt-get update
    sudo apt-get install -y pkg-config libssl-dev build-essential
else
    echo "Detected Linux environment"
    # Install for other Linux distros
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y pkg-config libssl-dev build-essential
    elif command -v yum &> /dev/null; then
        sudo yum install -y pkg-config openssl-devel gcc
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm pkg-config openssl base-devel
    else
        echo "Unknown package manager. Please install pkg-config and OpenSSL development libraries manually."
        exit 1
    fi
fi

echo "Dependencies installed successfully!"
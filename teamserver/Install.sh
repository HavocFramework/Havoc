#!/bin/bash

set -e

MYDIR=$(pwd)

# Check if the script is in the "teamserver" directory and adjust the current directory
if [ "$(basename "$MYDIR")" == "teamserver" ]; then
    cd ..
fi

# Check Linux distribution
if [ -x "$(command -v lsb_release)" ]; then
    DISTRIBUTION=$(lsb_release -si)
else
    DISTRIBUTION=$(cat /etc/os-release | grep "^ID=" | cut -d'=' -f2 | tr -d '"')
fi

# Check if DISTRIBUTION is defined
if [ -n "$DISTRIBUTION" ]; then
    if [ "$DISTRIBUTION" == "Ubuntu" ] || [ "$DISTRIBUTION" == "Debian" ]; then
        echo "Installing required packages on $DISTRIBUTION..."
        sudo apt -qq --yes install golang-go nasm mingw-w64 wget >/dev/null 2>&1 || { echo "Error: Failed to install required packages."; exit 1; }
    else
        echo "Warning: Unsupported distribution: $DISTRIBUTION. Please manual install the required packages."
    fi
else
    echo "Warning: Failed to determine the OS. Please manual install the required packages."
fi
    
# Check and download cross-compiler packages if not present
if [ ! -d "data/x86_64-w64-mingw32-cross" ]; then
    # Check if wget is available
    if ! command -v wget &>/dev/null; then
        echo "Error: wget is not installed. Please install wget and run the script again."
        exit 1
    fi

    # Create data directory if it doesn't exist
    if [ ! -d "data" ]; then
        mkdir data || { echo "Error: Failed to create directory 'data'"; exit 1; }
    fi

    # Download and extract x86_64-w64-mingw32-cross.tgz
    if [ ! -f /tmp/mingw-musl-64.tgz ]; then
        wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-64.tgz || { echo "Error: Failed to download https://musl.cc/x86_64-w64-mingw32-cross.tgz"; exit 1; }
    fi
    tar zxf /tmp/mingw-musl-64.tgz -C data || { echo "Error: Failed to extract /tmp/mingw-musl-64.tgz"; exit 1; }

    # Download and extract i686-w64-mingw32-cross.tgz
    if [ ! -f /tmp/mingw-musl-32.tgz ]; then
        wget https://musl.cc/i686-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-32.tgz || { echo "Error: Failed to download https://musl.cc/i686-w64-mingw32-cross.tgz"; exit 1; }
    fi
    tar zxf /tmp/mingw-musl-32.tgz -C data || { echo "Error: Failed to extract /tmp/mingw-musl-32.tgz"; exit 1; }
fi

cd "$MYDIR"

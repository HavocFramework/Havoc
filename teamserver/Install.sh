#!/bin/bash
set -e

# Install required dependencies
sudo apt -qq --yes install golang-go nasm mingw-w64 wget >/dev/null 2>&1

# Ensure data directory exists
[ -d "data" ] || mkdir data

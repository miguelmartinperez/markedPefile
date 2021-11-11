#!/bin/bash

# Dependencies
systemdeps="git"

# Install system dependencies
apt-get install -y $systemdeps

# Pefile
git clone --depth 1 https://github.com/miguelmartinperez/pefile.git

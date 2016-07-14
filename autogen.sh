#!/bin/sh

find $(pwd) -name configure.ac | xargs touch

# Regenerate configuration files
mkdir -vp m4 inih/m4 || exit 1
autoreconf -i --force -I m4 || exit 1


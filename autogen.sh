#!/bin/sh -x

# Regenerate configuration files
(cd ./ndpi/ && ./autogen.sh)
find $(pwd) -name configure.ac | xargs touch
mkdir -vp m4 inih/m4 || exit 1

autoreconf -i --force -I m4 || exit 1


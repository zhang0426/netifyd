#!/bin/sh -x

# Regenerate configuration files
(cd ./libs/ndpi/ && ./autogen.sh)
find $(pwd) -name configure.ac | xargs touch
mkdir -vp m4 libs/inih/m4 || exit 1

autoreconf -i --force -I m4 || exit 1


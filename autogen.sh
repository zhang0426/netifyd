#!/bin/sh -x

SUBDIRS="libs/gperftools libs/ndpi"

# Regenerate configuration files
for d in $SUBDIRS; do
    (cd $d && ./autogen.sh)
done

find $(pwd) -name configure.ac | xargs touch
mkdir -vp m4 libs/inih/m4 || exit 1

autoreconf -i --force -I m4 || exit 1


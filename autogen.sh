#!/bin/sh

# Autogen bits from ndpi/autogen.sh
NDPI_MAJOR="2"
NDPI_MINOR="1"
NDPI_PATCH="0"
NDPI_VERSION_SHORT="$NDPI_MAJOR.$NDPI_MINOR.$NDPI_PATCH"

cat ndpi/configure.seed | sed "s/@NDPI_MAJOR@/$NDPI_MAJOR/g" | sed "s/@NDPI_MINOR@/$NDPI_MINOR/g" | sed "s/@NDPI_PATCH@/$NDPI_PATCH/g" | sed "s/@NDPI_VERSION_SHORT@/$NDPI_VERSION_SHORT/g" > ndpi/configure.ac

# Regenerate configuration files
find $(pwd) -name configure.ac | xargs touch
mkdir -vp m4 inih/m4 || exit 1
autoreconf -i --force -I m4 || exit 1


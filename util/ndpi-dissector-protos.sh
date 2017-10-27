#!/bin/bash

egrep NDPI_PROTOCOL ndpi/src/lib/protocols/$1 |\
    sed -e 's/^.*NDPI_PROTOCOL_\([A-Z0-9_]*\).*$/case NDPI_PROTOCOL_\1:/g' |\
    sort | uniq | egrep -v '(NDPI_PROTOCOL_UNKNOWN|NDPI_PROTOCOL_BITMASK)'


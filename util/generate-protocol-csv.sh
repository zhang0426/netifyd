#!/bin/bash

my_dir=$(dirname "$0")
src_dir=$(readlink --canonicalize "$my_dir/../src")

if [ ! -x "$src_dir/netifyd" ]; then
	echo "$src_dir/netifyd: Not found."
	exit 1
fi

echo "id,\"protocol\""
$src_dir/netifyd -P | awk '{ printf "%d,\"%s\"\n", $1, $2 }' | sed -e 's/_/ /g'

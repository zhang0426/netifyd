#!/bin/bash

# View a real-time JSON stream of flow detections and statistics from a local
# Netify Agent socket.
#
# See README-JSON-example-socket.md for details.

SOCKET_PATH=${SOCKET_PATH:-/var/run/netifyd/netifyd.sock}
BASE_PATH="$(realpath $(dirname "$0"))"

if ! which nc >/dev/null 2>&1; then
    echo "The netcat (nc) command was not found.  Please install netcat."
    exit 1
fi

if ! which jq >/dev/null 2>&1; then
    echo "The jq command was not found.  Please install jq"
    exit 1
fi

echo "Netify Agent real-time JSON stream example."
echo "Connecting to: ${SOCKET_PATH}"
echo "ENTER to start, CTRL-C to quit."

read

while true; do
    if [ ! -S "${SOCKET_PATH}" ]; then
        echo "Socket path not found: ${SOCKET_PATH}"
        echo "Waiting for Netify Agent to start..."
        sleep 1
        continue
    fi

    echo "timestamp,digest,local_ip,local_port,other_ip,other_port,protocol,application" |\
        tee json-socket-example.csv
    nc -U ${SOCKET_PATH} | jq -r -f ${BASE_PATH}/json-socket-filter.jq |\
    while read stamp digest local_ip local_port other_ip other_port protocol application; do
        printf "\"%s\",%s,%s:%s,%s:%s,%s,%s\n" \
            "$(TZ=UTC date -d @$(echo ${stamp} / 1000 | bc -l) '+%F %T.%3N')" \
            $(echo ${digest} | cut -c-5) \
            ${local_ip} ${local_port} \
            ${other_ip} ${other_port} \
            ${protocol} ${application} | tee -a json-socket-example.csv
    done
done

exit 0

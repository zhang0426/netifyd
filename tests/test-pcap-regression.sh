#!/bin/bash

ND_PCAPS=$(find "${TESTDIR}/pcap/" -name '*.cap.gz' | sort)
NDPI_PCAPS=$(sort "${TESTDIR}/ndpi-pcap-files.txt" | egrep -v '^#' | xargs -n 1 -i find "${TESTDIR}/../libs/ndpi/tests/pcap" -name '{}*cap' | egrep -v -- '-test.cap$')

PCAPS="$(echo ${ND_PCAPS} ${NDPI_PCAPS} | sort)"

CONF="${TESTDIR}/netifyd-test-pcap.conf"
SINK_CONF="${TESTDIR}/../deploy/netify-sink.conf"
NETWORK=192.168.242.0/24

export LD_LIBRARY_PATH="${TESTDIR}/../src/.libs/"

echo -e "\nStarting capture tests..."

for PCAP in $PCAPS; do
    BASE=$(echo $PCAP | sed -e 's/\.[pc]*ap.*$//')
    LOG=$(printf "%s/test-pcap-logs/%s.log" ${TESTDIR} $(basename ${BASE}))
    if echo $PCAP | egrep -q '\.gz$'; then
        zcat $PCAP > ${BASE}-test.cap || exit $?
    else
        cat $PCAP > ${BASE}-test.cap || exit $?
    fi
    echo $(basename "${BASE}")
    sudo LD_LIBRARY_PATH="${TESTDIR}/../src/.libs/" ../src/.libs/netifyd -t -c $CONF -f $SINK_CONF -I lo,${BASE}-test.cap -A $NETWORK -T ${LOG} || exit $?
    rm -f ${BASE}-test.cap
    echo
done

echo "Capture test complete."

exit 0

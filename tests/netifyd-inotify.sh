# Scan a directory for PCAP files and run Netify Agent on them.
# Optionally hang around for more capture files to appear
# (requires inotifywait from the inotify-tools package).

# Directory to search for pcap files
PCAP_DIRECTORY="/tmp"

# Log directory.
# Netify Agent output will be logged here using the basename of
# the input pcap file plus a timestamp.
LOG_DIRECTORY="/tmp/netify-pcap-logs"

# Wait for new capture files?
WAIT_FOR_CAPTURES="yes"

# Local address(es).
# Since this is an offline capture, we can't get this information
# dynamically from interface. Specify more than one, comma-delimited
# (no whitespace).
LOCAL_ADDRESSES="192.168.1.0/24"

# Delete pcap file after processing?
DELETE_AFTER="yes"

# Dummy interface to use.
# Need to attach to a real interface, loopback (lo) is suitable.
DUMMY_INTERFACE="lo"

# Alternate configuration file.
# Use the system default (/etc/netifyd.conf) if not needed.
ALTERNATE_CONF="/etc/netifyd.conf"

netifyd_process() {
    PCAP="$1"
    BASE="$(echo $(basename ${PCAP}) | sed -e 's/\.[pc]*ap.*$//')"
    LOG="$(printf "%s/%s-%s.log" ${LOG_DIRECTORY} ${BASE} $(date '+%s'))"

    /usr/sbin/netifyd \
        -t -c "${ALTERNATE_CONF}" \
        -I ${DUMMY_INTERFACE},"${PCAP}" \
        -A ${LOCAL_ADDRESSES} -T "${LOG}" || exit $?

    [ "${DELETE_AFTER}" == "yes" ] && rm -vf "${PCAP}"
}

netifyd_process_inotify() {
    while read PCAP; do
        [ -z "${PCAP}" ] && break

        PCAP_PATH="${PCAP_DIRECTORY}/${PCAP}"
        [ ! -f "$PCAP_PATH" ] && break

        echo "Processing from inotify: ${PCAP_PATH}"
        netifyd_process "${PCAP_PATH}"
    done
}

if [ ! -d "${LOG_DIRECTORY}" ]; then
    mkdir -vp "${LOG_DIRECTORY}" || exit 1
fi

if [ ! -d "${PCAP_DIRECTORY}" ]; then
    echo "Capture directory does not exist: ${PCAP_DIRECTORY}"
    exit 1
fi

# XXX: Not whitespace friendly.
PCAPS=$(find ${PCAP_DIRECTORY} -iname '*.pcap' -o -iname '*.cap')

for PCAP in ${PCAPS}; do
    echo "Processing from find: ${PCAP}"
    netifyd_process ${PCAP}
done

[ "${WAIT_FOR_CAPTURES}" != "yes" ] && exit 0

inotifywait -q -m -e create,moved_to --format %f "${PCAP_DIRECTORY}" |\
    egrep --line-buffered '\.[pc]+ap$' |\
    netifyd_process_inotify

exit 0

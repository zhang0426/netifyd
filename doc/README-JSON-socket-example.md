Netify Agent JSON Socket Example
================================

Requirements
------------

The JSON socket example script requires:
- Netcat (nc)
- jq
- Basic/Bench Calculator (bc)
- sudo
- A running Netify Agent configured with either a local UNIX.

Configuration
-------------

By default the example script will attempt to connect to a local UNIX socket (`/var/run/netifyd/netifyd.sock`).  Export an alternate value to SOCKET_PATH to override, such as:

```sh
# SOCKET_PATH=/tmp/netify.sock sudo ./json-socket-example.sh
```

Overview
--------

The example script will connect to the specified Netify Agent using Netcat (nc).  The JSON stream will be read and parsed by `jq`.  The results are lightly processed to be output to CSV format.  To view the raw JSON stream from a running Netify Agent, and example command line could be:
```sh
# sudo nc -U /var/run/netifyd/netifyd.sock | jq . -C
```

Notes
-----

- The example script can be aborted with CTRL-C.
- The output is buffered by the shell so lines will be queued and flushed in a "bursty" nature.

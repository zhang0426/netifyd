Netify Daemon
=============
[![Build Status](https://travis-ci.org/eglooca/netify-daemon.png?branch=master)](https://travis-ci.org/eglooca/netify-daemon)

Deep Packet Inspection Server
-----------------------------

[Netify](https://www.egloo.ca/products/netify) is a deep packet inspection server.  [nDPI](http://www.ntop.org/products/deep-packet-inspection/ndpi/) (OpenDPI) is used to detect protocols and services (applications).

Netify provides visibility into the traffic on your network along with the option to take an active role (on supported devices) in stopping/shaping undesirable traffic from recurring on your network.


Build Requirements
------------------

Netify requires the following third-party packages:
- libcurl
- libjson-c
- libmnl
- libnetfilter-conntrack
- libpcap
- zlib

Runtime Requirements
--------------------

Ensure that the nfnetlink and nf_conntrack_netlink kernel modules are loaded.

Download Source
---------------

When cloning the source tree, ensure you use `--recursive` to include all
sub-modules.

Configuring Source
------------------

```
# ./autoconf.sh
# ./configure --prefix=/usr/local
```


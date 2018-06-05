Netify Agent
============

Deep Packet Inspection Server
-----------------------------

The [Netify](https://www.egloo.ca/products/netify) Agent is a deep packet inspection service.  [nDPI](http://www.ntop.org/products/deep-packet-inspection/ndpi/) (formerly OpenDPI) is the engine used to detect network protocols and applications.

The Netify Agent coupled with Netify Cloud processing improves network traffic visibility along with the option (on supported platforms) to take an active role in policing and bandwidth shaping specific network protocols and applications.

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

Download Packages
-----------------

Currently you can download binary packages for the following OS distributions:
- [ClearOS](https://www.clearos.com/products/purchase/clearos-marketplace-apps#cloud)
- [CentOS](http://software.opensuse.org/download.html?project=home%3Aegloo&package=netifyd)
- [Debian](http://software.opensuse.org/download.html?project=home%3Aegloo&package=netifyd)
- [Fedora](http://software.opensuse.org/download.html?project=home%3Aegloo&package=netifyd)
- [Ubuntu](http://software.opensuse.org/download.html?project=home%3Aegloo&package=netifyd)

Configuring/Building From Source
--------------------------------

Read the appropriate documentation in the doc directory, prefixed with: BUILD-*

Generally the process is:
```
# ./autogen.sh
# ./configure
# make
```


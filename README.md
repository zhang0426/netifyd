Netify Daemon
=============
Deep Packet Inspection Server
-----------------------------

Netify is a deep packet inspection server based off of
[nDPI](www.ntop.org/products/deep-packet-inspection/ndpi/) (OpenDPI).

Download Source
---------------

When cloning the source tree, ensure you use `--recursive` to include all
sub-modules.

Configuring Source
------------------

```
# ./autoconf.sh
# ./configure --prefix=/usr/local --enable-netify-sink --with-pic=inih,ndpi
```


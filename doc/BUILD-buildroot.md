Buildroot Notes
===============

Environment
-----------
```
export PKG_CONFIG=[BUILDROOT_BASE]/output/host/bin/pkg-config
export PATH=$PATH:[BUILDROOT_BASE]/output/host/bin
```
Configure Buildroot
-------------------

```
# make menuconfig
```

Configure Netify Agent
----------------------

```
# ./configure --disable-shared --enable-static --disable-json-c --build=x86_64-pc-linux-gnu --host=mips-linux --without-systemdsystemunitdir --disable-ncurses --disable-libtcmalloc
```

Examples
--------

Ubiquiti USG 3P
```
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --sharedstatedir=/var/lib --disable-shared --enable-static --disable-json-c --build=x86_64-pc-linux-gnu --host=mips-linux --without-systemdsystemunitdir --disable-ncurses --disable-libtcmalloc PKG_CONFIG=$BUILDROOT/target-usg-3p/output/host/bin/pkg-config

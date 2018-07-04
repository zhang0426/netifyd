Building for CentOS/ClearOS 6.x
===============================

CentOS/ClearOS 6.x ships with an old GCC compiler (4.4.x).  The Netify Agent
needs GCC 4.7.x or above for atomic variables (atomic_bool<>).

Installing Newer Compiler/binutils
----------------------------------

Skip to Configure Environment if this was done previously.

One of the CentOS developers maintains a repository with updated GCC and
binutils packages.  These can be installed alongside the existing offical
GCC/binutils packages.  The procedure to setup a compatible environment is as
follows:
```
# cd /etc/yum.repos.d/
# sudo wget http://people.centos.org/tru/devtools-2/devtools-2.repo
# sudo yum clean all
# sudo yum --enablerepo=testing-devtools-2-centos-6 install devtoolset-2-gcc devtoolset-2-gcc-c++ devtoolset-2-binutils
```

Configure Environment
---------------------

Execute the following to enable the new compiler and binutils.  This needs to
be run before building an RPM or compiling locally:
```
# scl enable devtoolset-2 bash
```

Clone Netify Agent Source
-------------------------
```
# git clone --recursive https://gitlab.com/netify.ai/public/netify-agent.git
# cd netify-agent
```

Build RPM: Prepare Source Archive
---------------------------------
```
# ./autogen.sh
# ./configure --disable-conntrack --disable-netlink --disable-ncurses
# make dist-gzip
# mv netifyd-<version>.tar.gz ~/rpmbuild/SOURCES
# rpmbuild -ba netifyd.spec --with local_netlink
```

Build From Source: Clone Netify Agent Source
--------------------------------------------
```
# unset PKG_CONFIG_PATH

# git clone git://git.netfilter.org/libmnl
# (cd libmnl && ./autogen.sh && ./configure --prefix=$(pwd) --disable-shared --enable-static && make && ln -s src lib)

# git clone git://git.netfilter.org/libnfnetlink
# (cd libnfnetlink && ./autogen.sh && ./configure --prefix=$(pwd) --disable-shared --enable-static && make && ln -s src lib)

# export PKG_CONFIG_PATH=$(pwd)/libmnl:$(pwd)/libnfnetlink

# git clone git://git.netfilter.org/libnetfilter_conntrack
# (cd libnetfilter_conntrack && ./autogen.sh && ./configure --prefix=$(pwd) --disable-shared --enable-static && make && ln -s src lib)

# export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/libnetfilter_conntrack
```

Configure and Compile Netify Agent Source
-----------------------------------------
```
# ./autogen.sh
# ./configure --disable-ncurses
# make
```

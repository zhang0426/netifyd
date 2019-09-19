# OpenWrt Official Packages Feed Build Notes

The easiest way to build the latest official release of the Netify Agent is to do so from the official OpenWrt packages feed.

1. Clone the OpenWrt source:

  `# git clone https://github.com/openwrt/openwrt.git openwrt`

2. Enable the packages repository in: feeds.conf

3. Update packages feed:

  `# ./scripts/feeds update packages`

4. Install the Netify Agent package source:

  `# ./scripts/feeds install netifyd`

5. Configure OpenWrt, enable netifyd under Network:

  `# make menuconfig`
  
6. Build image and packages:

  `# make`

# OpenWrt Manual Build Notes

Working guide for building the Netify Agent into an OpenWrt image.

1. Clone the OpenWrt source:

  `# git clone https://github.com/openwrt/openwrt.git openwrt`
  
2. Clone the Netify Agent into the OpenWrt top-level directory:

  `# cd openwrt`
  `# git clone --recursive https://gitlab.com/netify.ai/public/netify-agent.git`
  
3. Create a custom feeds configuration file.  Adjust the path to your environment:

  `# echo "src-link netify /home/dsokoloski/openwrt/netify-agent/openwrt" >> feeds.conf`
  
4. Prepare Netify Agent build environment:

  `# (cd netify-agent && ./autogent.sh && ./configure --without-systemdsystemunitdir)`
  
5. Update and install all feeds:

  `# ./scripts/feeds update -a && ./scripts/feeds install -a`
  
6. Configure OpenWrt and enable netifyd from: __Network > netifyd__

  `# make menuconfig`
  
7. Build OpenWrt image:

  `# make`

To update the Netify Agent source after changes:

1. Update package feed:

  `# ./scripts/feeds update netify && ./scripts/feeds install -a -p netify`
  
2. Deselect and then reselect netifyd from Network section (if OpenWrt Makefile.in has changed DEPENDS).

3. Clean old copy:

  `# make package/netifyd/clean`
  
4. Build new image:

  `# make`

Useful links:

- https://openwrt.org/docs/guide-developer/start

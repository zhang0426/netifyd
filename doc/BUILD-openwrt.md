# OpenWrt Official Packages Feed Build Notes

The easiest way to build the latest official release of the Netify Agent is to do so from the official OpenWrt packages feed.

1. Clone the OpenWrt source:

  `# git clone https://github.com/openwrt/openwrt.git openwrt`

2. Enable the packages repository in: feeds.conf

3. Update packages feed:

  `# ./scripts/feeds update packages`

4. Install the Netify Agent package source:

  `# ./scripts/feeds install netifyd`

5. Configure OpenWrt and enable the Netify Agent under: __Network > netifyd__

  `# make menuconfig`
  
6. Build image and packages:

  `# make`

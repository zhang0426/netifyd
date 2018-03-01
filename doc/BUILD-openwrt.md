# OpenWrt Build Notes

Working guide for building the Netify Agent into an OpenWrt image.

1. Clone the OpenWrt source:
  `# git clone https://github.com/openwrt/openwrt.git openwrt`
2. Clone the Netify Agent into the OpenWrt top-level directory:
  `# cd openwrt`
  `# git clone --recursive git@github.com:eglooca/netify-daemon.git`
3. Create a custom feeds configuration file.  Adjust the path to your environment:
  `# echo "src-link netify /home/dsokoloski/openwrt/netify-daemon/openwrt" >> feeds.conf`
4. Prepare Netify Agent build environment:
  `# (cd netify-daemon && ./autogent.sh && ./configure --without-systemdsystemunitdir)`
5. Update and install all feeds:
  `# ./scripts/feeds update -a && ./scripts/feeds install -a`
6. Configure OpenWrt and enable netifyd from: Network > netifyd
  `# make menuconfig`
7. Build OpenWrt image:
  `# make`

To update the Netify Agent source after changes:

1. Update package feed:
  `# ./scripts/feeds update netify && ./scripts/feeds install -a -p netify`
2. Deselect and then reselect netifyd from Network section (if OpenWrt Makefile.in has changed DEPENDS):
3. Clean old copy:
  `# make package/netifyd/clean`
4. Build new image:
  `# make`

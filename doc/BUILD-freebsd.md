# FreeBSD 10x/11x Build Notes

1. Install required build packages:

  `# sudo pkg install auto-tools git gmake pkgconf json-c google-perftools`

2. Clone source (recursive):

  `# git clone --recursive git@gitlab.com:netify.ai/public/netify-agent.git`

3. Configure (cd netify-agent):

  `# ./autogen.sh && ./configure --disable-conntrack --disable-inotify CC=clang CXX=clang++`

4. Build (optionally adjust jobs for number of CPUs + 1):

  `# gmake -j 5`

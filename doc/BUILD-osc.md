Building via OpenSUSE Build Service
===================================

- Must be done from a Debian/Ubuntu system (I use 16.04).
- Always regenerate: `./autogen.sh`
- Configure using: `./configure --prefix=/usr --includedir=\${prefix}/include --mandir=\${prefix}/share/man --sysconfdir=/etc --localstatedir=/var`
- Always: make clean
- Generate the debian package files: make -C deploy/debian

# FreeBSD 10x/11x Build Notes

## Manual Builds

1. Install required build packages:
```
  # pkg add http://pkg.freebsd.org/freebsd:11:x86:64/release_2/All/json-c-0.13.txz
  # pkg install auto-tools git gmake pkgconf google-perftools
```
2. Clone source (recursive):

```
  # git clone --recursive git@gitlab.com:netify.ai/public/netify-agent.git
```

3. Configure (cd netify-agent):

```
  # ./autogen.sh && ./configure --disable-conntrack --disable-inotify CC=clang CXX=clang++ MAKE=gmake
```
To build a debug version with AddressSanitizer:
```
  # ./autogen.sh && ./configure --disable-conntrack --disable-inotify --disable-libtcmalloc CC=clang CXX=clang++ CFLAGS='-O1 -fsnitize=address -fno-omit-frame-pointer' CXXFLAGS='-O1 -fsanitize=address -fno-omit-frame-pointer' MAKE=gmake
```
4. Build (optionally adjust jobs for number of CPUs + 1):
```
  # gmake -j 5
```

## FreeBSD Packages (txz)

1. Follow steps 1 - 3 if not already done.

2. Build package:
```
  # gmake deploy-freebsd
```
To build a debug version with AddressSanitizer:
```
  # gmake deploy-freebsd-debug
```

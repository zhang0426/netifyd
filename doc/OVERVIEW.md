Netify Technical Overview
=========================

- current image foot-print (flash)
    - executable: 530KB (x86-64 ELF glibc)
    - executable: 400KB (ARM Cortex A15 ELF / MUSL)
    - + ~200KB additional packaged files
    - < 1MB after installation

    - required run-time storage:
        - DNS cache; dynamic configuration content (application defs):
            250KB - 500KB (nominal home env)

    - dependencies:
        - libc / libstdc++
        - libpcap (Packet capture library)
        - libmnl (optional; minimal Netlink library)
        - libnetfilter-conntrack (optional; connection tracking library for NAT gateways)
        - zlib (JSON payload compression)
        - libcurl (w/SSL: mTLS, OpenSSL, etc.)

- current unoptimized RAM requirements:
    - 40-60MB (nominal home env)
        = ~500 application entries (Radix trees)
        = 7KB per flow (default 30s idle flow TTL)
    - JSON push ring buffer
        = Configurable; default: 2MB

- current test platforms:
    - Linux PC (RHEL, CentOS, ClearOS, Debian, Ubuntu, Gentoo) (x86; 1GB+)
    - Raspbian: Raspberry Pi Model 2 (ARMv7; Cortex-A7; 512GB)
    - Raspbian: Raspberry Pi Model 3 (ARMv8; Cortex-A53; 1GB)
    - EdgeOS (Debian / Proprietary): Ubiquiti ERLite-3 (MIPS64; Cavium Octeon+; 512MB)
    - LEDE / OpenWrt: TP-Link Archer C2600 (ARMv7; Qualcomm Atheros IPQ806X; 512MB)
    - FreeBSD 10.x PC (pfSense 2.x) (x86; 1GB+)


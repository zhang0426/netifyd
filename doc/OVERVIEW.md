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
        - libjson-c (JSON encoding of cloud payloads)
        - zlib (JSON payload compression)
        - libcurl (w/SSL: mTLS, OpenSSL, etc.)

- current unoptimized RAM requirements:
    - 40-60MB (nominal home env)
        = ~500 application entries (Radix trees)
        = 7KB per flow (default 30s idle flow TTL)
    - JSON push ring buffer
        = Configurable; default: 2MB

- current test platforms:
    - Linux x86 32 & 64bit (RHEL; CentOS; ClearOS; Debian; Ubuntu; Gentoo)
    - LEDE / OpenWrt (ARM, MIPS): TP-Link Archer C2600, Pete's MIPS flash-router
    - Raspberry Pi


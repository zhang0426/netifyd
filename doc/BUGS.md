Known Bugs & Issues
===================

Unclassified Applications
-------------------------

Just a list of "should-be-classified" applications:

- ADDED: *.gvt1.com: Google update service

Network Interfaces Configured with /32 Netmask
----------------------------------------------
Certain environments (ex: Google Cloud) configure VPS guest interfaces with a
/32 (255.255.255.255) netmask resulting in the broadcast address being the
same as the assigned IP address.  This breaks the agent's address
classification logic where all flows with that local/broadcast address are
classified as 'broadcast'.

Google Hangouts
---------------
Because we remove all application definitions from nDPI and define our own,
Google Hangout detection is broken.  Several solutions to be investigated.

Memory Leak - libCURL/NSS
-------------------------

- There is a known run-time memory leak in libnss < 3.34.0-0.1.beta1
- Affected: ClearOS/CentOS/RHEL = 6.*
  https://bugzilla.redhat.com/show_bug.cgi?id=1057388
- Affected: ClearOS/CentOS/RHEL < 7.5
  https://bugzilla.redhat.com/show_bug.cgi?id=1395803
- Solutions:
    - Disable SSL peer verification (BAD!)
    - Use built-in libcurl with OpenSSL back-end (SAD!).

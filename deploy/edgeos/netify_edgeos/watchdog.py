#!/usr/bin/python -Es

import os
import sys
import time
import netify_edgeos as eos

if __name__ == '__main__':
    if not eos.netifyd_is_running():
        sys.exit(eos.service_ctl('netifyd', 'start'))

    path_wd_upload = '/var/run/netifyd/upload.wd';
    if not os.path.exists(path_wd_upload):
        sys.exit(0)

    stat = os.stat(path_wd_upload)

    if time.time() - 30 > stat['st_mtime']:
        sys.exit(eos.service_ctl('netifyd', 'restart'))

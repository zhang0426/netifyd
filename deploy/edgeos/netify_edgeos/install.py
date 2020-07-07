#!/usr/bin/python -Es

import os
import sys
import glob
import time
import shutil
import netify_edgeos as eos

def nd_mkdir(path):
    if not os.path.isdir(path):
        print('Creating directory %s...' %(path))
        os.makedirs(path)

def nd_copy_files(src, dst='/'):
    files = []
    conf_files = [
        '/etc/netifyd.conf',
        '/etc/netify.d/netify-sink.conf',
        '/etc/default/netifyd'
    ]
    src_glob = glob.glob(src)

    for path in src_glob:
        if os.path.isdir(path):
            for root, dirname, filenames in os.walk(path):
                for file in filenames:
                    files.append('%s/%s' %(root, file))
        else:
            files.append(path)

    for file in files:
        dst_path = file.split('/')
        dst_path.pop(0)
        dst_join = '/'
        dst_path = dst + dst_join.join(dst_path)
        dir_name = os.path.dirname(dst_path)
        nd_mkdir(dir_name)

        if os.path.exists(dst_path) and dst_path in conf_files:
            print('Skipping %s...' %(file))
        else:
            print('%s %s to %s...' %(
                'Updating' if os.path.exists(dst_path) else 'Installing',
                file,
                dst_path
            ))
            shutil.copy2(file, dst_path)

if __name__ == '__main__':
    print('\nNetify Agent Installer for UniFi Security Gateway')
    print('-------------------------------------------------\n')

    if os.geteuid() != 0:
        print('Installer must be run as super-user (root).\n')
        sys.exit(1)

    mca_conf = eos.mca_dump(False)
    mca_inform = eos.mca_dump()

    if type(mca_conf) is not dict or type(mca_inform) is not dict:
        sys.exit(-1)

    model = eos.model_name(mca_inform)
    print('Detected model: %s (%s)' %(
        eos.model_name(mca_inform, False),
        model
    ))
    print('Detected EdgeOS (vyatta) version: %s' %(
        eos.version(mca_inform)
    ))

    netifyd_options = eos.netifyd_autodetect(mca_conf)
    print('Detected network options: %s' %(
        netifyd_options
    ))

    print

    if eos.netifyd_is_running():
        print('Stopping the Netify Agent:')
        eos.service_ctl('netifyd', 'stop')

    nd_copy_files('./etc/*')
    nd_copy_files('./usr/*')

    nd_mkdir('/var/run/netifyd')

    print

    eos.netifyd_provision() and sys.exit(1)

    print

    eos.service_ctl('netifyd', 'start') and sys.exit(1)
    eos.service_ctl('cron', 'restart') and sys.exit(1)

    sys.stdout.write('\nWaiting for Netify Agent to become ready')
    sys.stdout.flush()

    for i in range(3):
        time.sleep(1)
        sys.stdout.write('.')
        sys.stdout.flush()

    print
    if eos.netifyd_is_running():
        eos.netifyd_status()

        print('\nSink/provisioning status will be available in 15 seconds...')
        print('To check current status, run:\n')
        print('# sudo /usr/sbin/netifyd --status\n')
    else:
        print('Something went wrong :(')
        print('Try starting the Netify Agent in debug mode:')
        print('# sudo /usr/sbin/netifyd -d %s\n' %(netifyd_options))
        sys.exit(1)

    sys.exit(0)

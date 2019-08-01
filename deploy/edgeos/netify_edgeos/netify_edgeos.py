#!/usr/bin/python -Es

import os
import json
import subprocess

def mca_dump(inform=True):
    data = -1

    try:
        result = subprocess.check_output(
            ['/usr/bin/mca-ctrl', '-t',
                'dump' if inform else 'dump-cfg'],
            universal_newlines=True
        )

        data = json.loads(result)

    except subprocess.CalledProcessError as e:
        print("Error retrieving MCA %s dump."
            %('inform' if inform else 'configuration')
        )
        return e.returncode

    return data

def model_name(mca_inform, short=True):
    key = 'model' if short else 'model_display'
    if key in mca_inform:
        return mca_inform[key]
    return 'Unknown'

def version(mca_inform):
    if 'version' in mca_inform:
        return mca_inform['version']
    return 'Unknown'

def service_ctl(service, oper):
    try:
        if oper == 'start':
            print('Starting service: ' + service)
        elif oper == 'stop':
            print('Stopping service: ' + service)
        elif oper == 'restart':
            print('Restarting service: ' + service)

        result = subprocess.call(
            ['/etc/init.d/' + service, oper]
        )

    except OSError as e:
        print('OS Error: %s' %(e.strerror))
        return -1
    except subprocess.CalledProcessError as e:
        print('Error executing %s init: %s' %(service, oper))
        return e.returncode

    return result

def netifyd_autodetect(mca_conf):
    nd_opts = []
    wan_count = 0
    for ifn in sorted(mca_conf['interfaces']['ethernet']):
        is_pppoe = True if 'pppoe' in mca_conf['interfaces']['ethernet'][ifn] else False
        role = mca_conf['interfaces']['ethernet'][ifn]['firewall']['local']['name'][0:3]
        if role == 'LAN':
            nd_opts.append('-I %s' %(ifn))
        elif role == 'WAN':
            wan_count += 1
            nd_opts.append('-E %s' %(ifn))
            if is_pppoe:
                nd_opts.append('-N pppoe%s' %(
                    next(iter(mca_conf['interfaces']['ethernet'][ifn]['pppoe']))
                ))

    s = ' '
    return ('' if wan_count > 0 else '-t ') + s.join(nd_opts)

def netifyd_is_running():
    pid_path = '/var/run/netifyd/netifyd.pid'
    if not os.path.exists(pid_path):
        return False

    pid = 0
    try:
        with open(pid_path, 'r') as hf:
            pid = hf.read().strip()
    except:
        return False

    proc_exe_path = '/proc/%s/exe' %(pid)
    if not os.path.exists(proc_exe_path):
        return False
    if not os.path.islink(proc_exe_path):
        return False

    exe_path = os.readlink(proc_exe_path)

    if os.path.basename(exe_path) != 'netifyd':
        return False

    return True

def netifyd_provision():
    try:
        result = subprocess.call(
            ['/usr/sbin/netifyd', '--provision']
        )

    except subprocess.CalledProcessError as e:
        print('Error provisioning netifyd.')
        return e.returncode

    return result

def netifyd_status():
    try:
        result = subprocess.call(
            ['/usr/sbin/netifyd', '--status']
        )

    except subprocess.CalledProcessError as e:
        print('Error retrieving netifyd status.')
        return e.returncode

    return result

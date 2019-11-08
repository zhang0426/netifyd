#!/usr/local/bin/python2.7 -Es

import os
import sys
import xml.etree.ElementTree as et

if __name__ == '__main__':
    opts = []
    wan_count = 0
    tree = et.parse('/conf.default/config.xml')
    root = tree.getroot()
    ifaces = root.find('interfaces')

    for iface in ifaces.findall('wan'):
        if iface.find('enable') is not None:
            name = iface.find('if').text
            opts.append('-E %s' %(name))

    for iface in ifaces.findall('lan'):
        if iface.find('enable') is not None:
            name = iface.find('if').text
            opts.append('-I %s' %(name))

    s = ' '
    print('%s%s' %('' if wan_count > 0 else '-t ', s.join(opts)))

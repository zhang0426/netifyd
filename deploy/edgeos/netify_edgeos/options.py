#!/usr/bin/python -Es

import os
import sys
import netify_edgeos as eos

if __name__ == '__main__':
	mca_conf = eos.mca_dump(False)
	print(eos.netifyd_autodetect(mca_conf))

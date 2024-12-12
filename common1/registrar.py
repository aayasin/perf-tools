#!/usr/bin/env python
# Copyright (c) 2020-2024, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# common registry for global names, parameters etc. E.g. filenames
#
from __future__ import print_function
__author__ = 'ayasin'

import os, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import tma

extensions = {
  'stat': 'perf_stat-r3',
  'info': 'toplev-mvl2',
  'tree': 'toplev-vl%d' % tma.get('num-levels'),      
}

def name(what, ext='log'):
  e = extensions[what]
  return '.'.join(('', e, ext))

def log2csv(f):
  return f.replace('.log', '.csv')


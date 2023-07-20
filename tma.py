#!/usr/bin/env python
# Copyright (c) 2020-2023, Intel Corporation
# Author: Ahmad Yasin
#
#   This program is free software; you can redistribute it and/or modify it under the terms and conditions of the
# GNU General Public License, version 2, as published by the Free Software Foundation.
#   This program is distributed in the hope it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

# Inteface to the Top-down Microarchitecture Analysis (TMA) logic
#
from __future__ import print_function
__author__ = 'ayasin'

import common as C, pmu

def fixed_metrics():
  events, flags = 'instructions,cycles,ref-cycles', None
  if pmu.perfmetrics():
    prefix = ',topdown-'
    events += prefix.join([',{slots', 'retiring', 'bad-spec', 'fe-bound', 'be-bound'])
    if pmu.goldencove():
      events += prefix.join(['', 'heavy-ops', 'br-mispredict', 'fetch-lat', 'mem-bound}'])
      flags = ' --td-level=2'
    else:  events += '}'
    if pmu.hybrid(): events = events.replace(prefix, '/,cpu_core/topdown-').replace('}', '/}').replace('{slots/', '{slots')
  return events, flags

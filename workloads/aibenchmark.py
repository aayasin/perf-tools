#!/usr/bin/env python3
# wrapper to ease use of ai-benahcmark
# Author: Ahmad Yasin
# edited: Dec 2024
#
from __future__ import print_function

import os, sys
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + '/..')
import common as C

from ai_benchmark import AIBenchmark

# TODO:
#   - support particular tests_ids in newer versions of AIBenchmark.run()
#

def run(x):
    try:
        ai = AIBenchmark(use_CPU=True)
        if x == 'all':
            results = ai.run()
        elif x == 'inference':
            results = ai.run_inference()
        else:
            results = ai.run_micro()
    except Exception as e:
        print(f"Exception suppressed: {e}")
        sys.exit(0)
    return results

def install():
    from common import exe_cmd as exe
    for c in ('pip install ai_benchmark', 'pip uninstall numpy', 'pip install numpy==1.23.5'):
        exe(c, debug=1)

def main():
  arg = C.arg(1, 'run')
  if arg == 'install':
      install()
      return
  run(C.arg(2, 'micro'))

if __name__ == "__main__":
  main()


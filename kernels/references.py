#!/usr/bin/env python
# Author: Ahmad Yasin
# edited: Sep. 2021
Papers = {
  'MGM':      'A Metric-Guided Method for Discovering Impactful Features and Architectural Insights for Skylake-Based Processors. Ahmad Yasin, Jawad Haj-Yahya, Yosi Ben-Asher, Avi Mendelson. TACO 2019 and HiPEAC 2020.',
  'ICL-PMU':  'How TMA Addresses Challenges in Modern Servers and Enhancements Coming in IceLake. Ahmad Yasin. Scalable Tools Workshop, Utah, July 2018.',
}

Comments = {
  'MGM': 'fp-add-lat exposes the execution latency while fp-add-bw expose the throughput of a floating-point vector ADD instruction (e.g.)',
  'ICL-PMU': 'Demonstrates utilization of the extra counters in Icelake\'s PMU.'
  '\nIt collects TMA level 1 as well as FP arithmetic events where an HPC/ML developer may seek to see the high-level bottleneck as well as measure GFLOPs.'
  '\nProfile with (requires new perf tool):'
  '\n  perf stat -e instructions,cycles,ref-cycles,{slots,topdown-retiring,topdown-bad-spec,topdown-fe-bound,topdown-be-bound},fp_arith_inst_retired.128b_packed_double,fp_arith_inst_retired.128b_packed_single,fp_arith_inst_retired.256b_packed_double,fp_arith_inst_retired.256b_packed_single,fp_arith_inst_retired.512b_packed_double,fp_arith_inst_retired.512b_packed_single,fp_arith_inst_retired.scalar_double,fp_arith_inst_retired.scalar_single # on ICL onwards'
  '\n  perf stat -e instructions,cycles,ref-cycles,topdown-fetch-bubbles,topdown-recovery-bubbles,topdown-slots-issued,topdown-slots-retired,topdown-total-slots,fp_arith_inst_retired.128b_packed_double,fp_arith_inst_retired.128b_packed_single,fp_arith_inst_retired.256b_packed_double,fp_arith_inst_retired.256b_packed_single,fp_arith_inst_retired.512b_packed_double,fp_arith_inst_retired.512b_packed_single,fp_arith_inst_retired.scalar_double,fp_arith_inst_retired.scalar_single # on Xeon prior to ICL'
  '\nURL: https://dyninst.github.io/scalable_tools_workshop/petascale2018/assets/slides/TMA%20addressing%20challenges%20in%20Icelake%20-%20Ahmad%20Yasin.pdf',
}


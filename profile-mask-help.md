## Help for profile-steps in the profile command
	This is the bitmask argument --profile-mask <hex-value> (or -pm) of do.py
	Bits of multiple steps can be set in same run
	
   mask | profile-step                                       | additional [optional] arguments
------- | -------------------------------------------------- | -------------------------------
1 | logging setup details                              | 
2 | per-app counting 3 runs                            | [--repeat 3]
4 | system-wide counting                               | 
8 | sampling w/ stacks                                 | [--tune :sample:1]
10 | topdown full tree + All Bottlenecks                | 
20 | topdown primary, 2-levels 3 runs                   | [--repeat 3 --tune :levels:2]
40 | topdown auto-drilldown                             | 
80 | topdown-mvl6 no multiplexing                       | 
100 | sampling-LBR                                       | [--tune :sample:2]
200 | sampling-PEBS on FRONTEND_RETIRED.ANY_DSB_MISS     | --tune :sample:3
400 | sampling-LDLAT                                     | 
1000 | Info metrics                                       | 
2000 | topdown FE Bottlenecks                             | 
4000 | TMA sampling (MTL with 23 events)                  | 
8000 | topdown Auto-Detect group                          | 
10000 | bottlenecks-view                                   | 
20000 | over-time counting at 10ms interval                | [--tune :interval:10]
40000 | tracing MSRs                                       | setup-all --tune :msr:1
80000 | sampling-PT                                        | 
100000 | FlameGraph                                         | setup-all --tune :flameg:1
200000 | Pipeline view every 1000ms                         | setup-all [--tune :interval:1000]


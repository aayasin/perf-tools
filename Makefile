.PHONY: clean clean-all help
AP = CLTRAMP3D
APP = taskset 0x4 ./$(AP)
CC = clang
CLONE = git clone --recurse-submodules https://github.com/aayasin/perf-tools
CMD = profile
CPU = $(shell ./pmu.py CPU)
DO = ./do.py # Use e.g. DO="do.py --perf /my/perf" to init things, or DO_SUFF to override things
DO1 = $(DO) $(CMD) -a "$(APP)" --tune :loops:10
DO2 = $(DO) $(CMD) -a 'workloads/BC.sh 3'
FAIL = (echo "failed! $$?"; exit 1)
MAKE = make --no-print-directory
METRIC = -m IpCall
MGR = sudo $(shell python -c 'import common; print(common.os_installer())') -y -q
NUM_THREADS = $(shell grep ^cpu\\scores /proc/cpuinfo | uniq |  awk '{print $$4}')
PM = $(shell python -c 'import common; print("0x%x" % common.PROF_MASK_DEF)')
PY2 = python2.7
PY3 = python3
RERUN = -pm 0x80
SHELL := /bin/bash
SHOW = tee
SKIP_EX = false # Skip extra checks
ST = --toplev-args ' --single-thread --frequency --metric-group +Summary'
TEST_LBR_PERF = 1

all: tramp3d-v4
	@echo done
../perf:
	$(DO) build-perf
cpuid:
	$(MGR) -o Acquire::http::proxy=false install cpuid
git:
	$(MGR) install git
openmp:
	$(MGR) install libomp-dev
gcc11:
	$(MGR) update
	$(MGR) install gcc-11
	sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 --slave /usr/bin/g++ g++ /usr/bin/g++-11 --slave /usr/bin/gcov gcov /usr/bin/gcov-11
	gcc --version
PKG=curl clang libstdc++-12-dev stress-ng
install: /usr/bin/python openmp tramp3d-v4
	make -s -C workloads/mmm install
	$(MGR) install $(PKG)
install1:
	$(MGR) install $(PKG)
link-python:
	sudo ln -f -s $$(find /usr/bin -name 'python[1-9]*' -executable | grep -E -v config | sort -n -tn -k3 | tail -1) /usr/bin/python
diff:
	git diff | grep -v '^\-' | less
intel:
	git clone https://gitlab.devtools.intel.com/micros/dtlb
	cd dtlb; ./build.sh
	#git clone https://github.com/intel-innersource/applications.benchmarking.cpu-micros.inst-lat-bw
	#wget https://downloadmirror.intel.com/763324/mlc_v3.10.tgz
tramp3d-v4: pmu-tools/workloads/CLTRAMP3D /usr/bin/clang++
	cd pmu-tools/workloads; ./CLTRAMP3D; cp tramp3d-v4.cpp CLTRAMP3D ../..; rm tramp3d-v4.cpp
	sed -i "s/11 tramp3d-v4.cpp/11 tramp3d-v4.cpp -o $@/" CLTRAMP3D
	./CLTRAMP3D

run-mem-bw:
	make -s -C workloads/mmm run-textbook > /dev/null
	@echo $(DO) profile -a workloads/mmm/m0-n8192-u01.llv -s1 --tune :perf-stat:\"\'-C2\'\" # for profiling
test-mem-bw: run-mem-bw
	sleep 2s
	set -o pipefail; $(DO) profile -s3 $(ST) -o $< $(RERUN) | $(SHOW)
	grep -q 'Backend_Bound.Memory_Bound.DRAM_Bound.MEM_Bandwidth' $<.toplev-mvl6-nomux.log
	kill -9 `pidof m0-n8192-u01.llv`
	@echo 1 | tee $< > $@
run-mt:
	./omp-bin.sh $(NUM_THREADS) ./workloads/mmm/m9b8IZ-x256-n8448-u01.llv &
test-mt: run-mt
	sleep 2s
	set -o pipefail; $(DO) profile -s1 $(RERUN) | $(SHOW)
	kill -9 `pidof m9b8IZ-x256-n8448-u01.llv`

# TODO:
# * let all test-* targets depends on do.py
# Keep next test-* targets sorted alphabet

AZ_PM = '112 --tune :az-Mispredictions:5 :az-Instruction_Fetch_BW:5' # stress for testing
test-analyze:
	$(MAKE) test-bc2     CMD='profile analyze' PM=$(AZ_PM)
	$(MAKE) test-default CMD=analyze PM=$(AZ_PM) TEST_LBR_PERF=0
test-bc2:
	$(DO2) -pm $(PM) | $(SHOW)

CPUIDI = 200000000
test-bottlenecks: kernels/cpuid
	$(DO1) -pm 10 --tune :help:0 :forgive:2
	grep Bottleneck cpuid-$(CPUIDI).toplev-vl6.log | sort -n -k4 | tail -1 | grep --color Irregular_Overhead
test-build:
	$(DO) build profile -a datadep -g " -n120 -i 'add %r11,%r12'" -ki 20e6 -e FRONTEND_RETIRED.DSB_MISS -n '+Core_Bound*' -pm 22 | $(SHOW)
	grep -q 'Backend_Bound.Core_Bound.Ports_Utilization.Ports_Utilized_1' datadep-20e6.toplev-vl2.log
	grep Time datadep-20e6.toplev-vl2.log
	$(SKIP_EX) || ( set -o pipefail; ./do.py profile -a './kernels/datadep 20000001' -e FRONTEND_RETIRED.DSB_MISS --tune :interval:50 \
	    -pm 20006 -r 1 | $(SHOW) ) # tests ocperf -e (w/ old perf tool) in all perf-stat steps, --repeat, :interval
test-default:
	$(DO1) -pm $(PM) $(DO_SUFF)
ifeq ($(TEST_LBR_PERF), 1)
	#sync; echo 3 | sudo tee /proc/sys/vm/drop_caches; sleep 3
	info=$$(ls -1tr *info.log | tail -1); echo "info=$$info"; grep '^LBR samples' $$info | awk -F 'samples/s: ' '{print $$2}' | \
	    awk -F '}' '{print $$1}' | awk '{if ($$1 > 30) exit 0; else exit 1}' || $(FAIL)
endif
test-default-track-perf:
	$(MAKE) test-default PM=313e    # tests default non-MUX sensitive profile-steps
	@mkdir -p perf-trk
	info=$$(ls -1tr *info.log | tail -1); grep ^LBR $$info; cp $$info perf-trk/$$(date +"%Y-%m-%d").$$info
	$(DO1) --toplev-args ' --no-multiplex --frequency --metric-group +Summary' -pm 1010 # carefully tests MUX sensitive profile-steps
	@echo 1 > $@
test-edge-inst:
	$(DO1) --tune :perf-lbr:\"'-j any,save_type -e instructions:ppp'\" -pm 100 > /dev/null 2>&1 || $(FAIL)

FSI = 400000000
test-false-sharing: kernels/false-sharing
	$(DO) profile --tune :help:0 -a "$< $(FSI)" -pm 40
	grep -E -q '^BE.*False_Sharing.*<==' $<-$(FSI)-out.txt

CPUS = ICX SPR SPR-HBM TGL ADL
test-forcecpu:
	passed=true; set -x;\
	for cpu in $(CPUS); do \
        FORCECPU=$$cpu $(DO) $(CMD) -a "./workloads/BC.sh 7 $$cpu" -pm 19112 --tune :loops:0 :help:0 \
        -e FRONTEND_RETIRED.ANY_DSB_MISS $(DO_SUFF) 2>&1 || { passed=false; break; }; done;\
	$$passed || $(FAIL)
	FORCECPU=SPR $(DO) $(CMD) -a "./workloads/BC.sh 7 SPR-slow0" -pm 100 --tune :imix:0x3f :loops:0 :help:0 $(DO_SUFF)
test-metric:
	RUN_NLOOP=1 $(DO) profile $(METRIC) --stdout -pm 2
	RUN_NLOOP=1 $(DO) profile -pm 40 | $(SHOW)

SLI = 1000000
CCB = $(shell echo $(CC) | rev | cut -d/ -f1 | rev)
test-srcline: lbr/lbr.py do.py common.py
	cd kernels && $(CC) -g -O2 pagefault.c -o pagefault-$(CCB)
	$(DO) $(CMD) -a './kernels/pagefault-$(CCB) $(SLI)' -pm 100 --tune :srcline:1 $(DO_SUFF) > $@ 2>&1
	grep -q 'srcline: pagefault.c;43' pagefault-$(CCB)-$(SLI)*info.log || $(FAIL)
test-stats: stats.py test-default-track-perf
	./stats.py $(AP).toplev-vl6-perf.csv && test -f $(AP).$(CPU).stat
	@echo 1 > $@

TS_A = ./$< cfg1 cfg2 -a ./run.sh --tune :loops:0 -s7 -v1 $(DO_SUFF)
TS_B = STUDY_MODE=all-misp ./$< cfg1 cfg2 -a ./pmu-tools/workloads/BC2s --tune :forgive:2 $(DO_SUFF)
TS_C = STUDY_MODE=dsb-bw ./$< cfg1 cfg2 -t2 -a ./run.sh --tune :loops:0 -s7 -v1 $(DO_SUFF)
TS_D = STUDY_MODE=mem-bw ./$< cfg1 cfg2 -t3 -a ./run.sh --tune :loops:0 -s27 -v1 $(DO_SUFF)
test-study: study.py stats.py run.sh do.py
	rm -f ./{.,}{{run,BC2s}-cfg*,$(AP)-s*}
	@echo $(TS_A) > $@
	$(TS_A) >> $@ 2>&1 || $(FAIL)
	@tail $@
	test -f run-cfg1-t1.$(CPU).stat && test -f run-cfg2-t1.$(CPU).stat
	test -f run-cfg1-t1_run-cfg2-t1.stats.log
	@echo $(TS_B) >> $@
	$(TS_B) >> $@ 2>&1
	test -f BC2s-cfg1-t1-b-e*nameBR_MISP_RETIRED*.perf.data.ips*.log
	test -f BC2s-cfg2-t1-b-e*nameBR_MISP_RETIRED*.perf.data.ips*.log
	test -f BC2s-cfg1-t1_BC2s-cfg2-t1.stats.log
	@echo $(TS_C) >> $@
	$(TS_C) >> $@ 2>&1
	@echo $(TS_D) >> $@
	$(TS_D) >> $@ 2>&1

TMI = 80000000
define check_tripcount
grep Loop#$(1) tripcount-mean-$(TMI)*info.log | awk -F 'tripcount-mean: ' '{print $$2}' | \
awk -F ',' '{print $$1}' | awk 'BEGIN {lower=$(2); upper=$(3)} {if ($$1 >= lower && $$1 <= upper) exit 0; \
else exit 1}' || $(FAIL)
endef
test-tripcount-mean: lbr/lbr.py do.py lbr/x86.py
	gcc -g -O2 kernels/tripcount-mean.c -o kernels/tripcount-mean
	$(DO) log $(CMD) -a './kernels/tripcount-mean $(TMI)' -pm 100 $(DO_SUFF) > /dev/null 2>&1
	$(call check_tripcount,1,90,110)
	$(call check_tripcount,2,60,80)

test-windows:
	python < scripts/test-windows.py

clean-all: clean
	rm tramp3d-v4{,.cpp} CLTRAMP3D
lint: *.py kernels/*.py
	grep flake8 .github/workflows/pylint.yml | tail -1 > /tmp/1.sh
	. /tmp/1.sh | tee .pylint.log | cut -d: -f1 | sort | uniq -c | sort -nr | ./ptage
	. /tmp/1.sh | cut -d' ' -f2 | sort | uniq -c | sort -n | ./ptage | tail

list:
	@grep '^[^#[:space:]].*:' Makefile | cut -d: -f1 | sort #| tr '\n' ' '

lspmu:
	@python -c 'import pmu; print(pmu.name())'
	@lscpu | grep -E 'Model name|Vendor'

help: do-help.txt
do-help.txt: do.py common.py pmu.py tma.py
	./pmu.py
	./$< -h > $@ && sed -i 's|/.*pmu-tools|./pmu-tools|' $@
	$(DO) profile --tune :flameg:1 :forgive:1 :help:-1 :msr:1 :tma-group:"'Auto-Detect'" :sample:3 --mode profile \
	    -pm ffffff > /dev/null && cat profile-mask-help.md

update:
	$(DO) tools-update -v1

PT=perf-tools.1
clean:
	rm -rf {run,BC,datadep,$(AP),openssl,CLTRAMP3D[.\-]}*{csv,data,old,log,txt} \
	    $(PT) run-mem-bw setup-system-* test-{default-track-perf,dir,mem-bw,srcline,stats,study} .CLTRAMP3D*cmd .ipc_*.txt
post-push:
	$(CLONE) $(PT) && cd $(PT) && ./do.py setup-perf log && cd .. && rm -rf $(PT)   # tests a fresh clone

pre-push: help
	$(DO) version log help -m GFLOPs --tune :msr:1          # tests help of metric; version; prompts for sudo password
	$(MAKE) test-mem-bw SHOW="grep --color -E '.*<=='"      # tests sys-wide + topdown tree; MEM_Bandwidth in L5
	$(MAKE) test-metric SHOW="grep --color -E '^|Ret.*<=='" # tests perf -M IpCall & colored TMA, then toplev --drilldown
	$(DO) log                                               # prompt for sudo soon after
	$(MAKE) test-bc2 PM=40 SHOW="grep --color -E '^|Mispredict'"	# tests topdown across-tree tagging; Mispredict
	echo skip: $(MAKE) test-false-sharing                              # tests topdown ~overlap in Threshold attribute
	$(MAKE) test-bottlenecks AP="./kernels/cpuid $(CPUIDI)" # tests Bottlenecks View
	$(MAKE) test-build SHOW="grep --color -E '^|build|DSB|Ports'" # tests build command, perf -e, toplev --nodes; Ports_*
	rm -f run-mem-bw && $(MAKE) test-mem-bw RERUN='-pm 400 -v1'   # tests load-latency profile-step + verbose:1
	$(MAKE) test-default-track-perf                         # tests default profile-steps, track LBR speed
	$(MAKE) test-stats                                      # tests stats module
	$(MAKE) test-analyze                                    # tests analyze module
	$(DO) profile -a './workloads/BC.sh 9' -d1 > BC-9.log 2>&1 || $(FAIL) # tests --delay
	$(DO) prof-no-mux -a './workloads/BC.sh 1' -pm 82 && test -f BC-1.$(CPU).stat   # tests prof-no-aux command
	$(MAKE) test-default DO_SUFF="--tune :calibrate:1 :loops:0 :msr:1 :perf-filter:0 :perf-annotate:0 :sample:3 :size:1\
	    -o $(AP)-u $(DO_SUFF)" CMD='suspend-smt profile tar' PM=3931a &&\
	    test -f $(AP)-u.perf_stat-I10.csv && test -f $(AP)-u.toplev-vl2-Fed.log && test -f $(AP)-u.$(CPU).results.tar.gz\
	    # tests unfiltered- calibrated-sampling; PEBS, tma group, bottlenecks-view & over-time profile-steps, tar command
	$(MAKE) test-default APP=./$(AP) CMD="log profile" PM=313e DO_SUFF="--tune :perf-stat:\"' -a'\" :perf-record:\"' -a -g'\" \
	    :perf-lbr:\"'-a -j any,save_type -e r20c4:ppp -c 90001'\" :perf-filter:0 -o $(AP)-a"   # tests sys-wide non-MUX profile-steps
	mkdir -p test-dir; cd test-dir; ln -sf ../common.py && \
	    make test-default APP=../pmu-tools/workloads/BC2s DO=../do.py -f ../Makefile > ../test-dir.log 2>&1\
	    # tests default from another directory, toplev describe
	@cp -r test-dir{,0}; cd test-dir0; ../do.py clean; ls -l # tests clean command
	$(MAKE) test-study                                      # tests study script (errors only)
	$(MAKE) test-srcline                                    # tests srcline loop stat
	$(MAKE) test-tripcount-mean                             # tests tripcount-mean calculation
	$(MAKE) test-forcecpu                                   # tests force cpu option
	$(MAKE) test-edge-inst					# tests sampling by instructions
	$(PY3) $(DO) log profile --tune :forgive:0 -pm 10 > .do-forgive.log 2>&1
	$(PY3) $(DO) profile > .do.log 2>&1 || $(FAIL)          # tests default profile-steps (errors only)
	$(DO) setup-all profile --tune :loop-ideal-ipc:1 -pm 300 > .do-ideal-ipc.log 2>&1 || $(FAIL) # tests setup-all, ideal-IPC
	time $(DO) profile -a "openssl speed rsa2048" --tune :loops:9 :time:2 > openssl.log 2>&1 || $(FAIL)
	$(PY2) ./do.py profile -v3 > .do-$(PY2).log 2>&1 || $(FAIL) # tests default w/ python2 (errors only)

.PHONY: clean clean-all help
AP = CLTRAMP3D
APP = taskset 0x4 ./$(AP)
CMD = profile
CPU = $(shell ./pmu.py CPU)
DO = ./do.py
DO1 = $(DO) $(CMD) -a "$(APP)" --tune :loops:10 $(DO_ARGS)
DO2 = $(DO) profile -a 'workloads/BC.sh 3' $(DO_ARGS)
FAIL = (echo "failed! $$?"; exit 1)
MAKE = make --no-print-directory
METRIC = -m IpCall
MGR = sudo $(shell python -c 'import common; print(common.os_installer())') -y -q
NUM_THREADS = $(shell grep ^cpu\\scores /proc/cpuinfo | uniq |  awk '{print $$4}')
PM = $(shell python -c 'import common; print("0x%x" % common.PROF_MASK_DEF)')
PY2 = python2.7
PY3 = python3.6
RERUN = -pm 0x80
SHELL := /bin/bash
SHOW = tee
ST = --toplev-args ' --single-thread --frequency --metric-group +Summary'

all: tramp3d-v4
	@echo done
git:
	$(MGR) install git
openmp:
	$(MGR) install libomp-dev
gcc11:
	$(MGR) update
	$(MGR) install gcc-11
	sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-11 110 --slave /usr/bin/g++ g++ /usr/bin/g++-11 --slave /usr/bin/gcov gcov /usr/bin/gcov-11
	gcc --version
install: link-python llvm openmp
	make -s -C workloads/mmm install
link-python:
	sudo ln -f -s $(shell find /usr/bin -name 'python[1-9]*' -executable | egrep -v config | sort -n -tn -k3 | tail -1) /usr/bin/python
llvm:
	$(MGR) -y -q install curl clang
diff:
	git diff | grep -v '^\-' | less
intel:
	git clone https://gitlab.devtools.intel.com/micros/dtlb
	cd dtlb; ./build.sh
	#git clone https://github.com/intel-innersource/applications.benchmarking.cpu-micros.inst-lat-bw
	#wget https://downloadmirror.intel.com/763324/mlc_v3.10.tgz
tramp3d-v4: pmu-tools/workloads/CLTRAMP3D
	cd pmu-tools/workloads; ./CLTRAMP3D; cp tramp3d-v4.cpp CLTRAMP3D ../..; rm tramp3d-v4.cpp
	sed -i "s/11 tramp3d-v4.cpp/11 tramp3d-v4.cpp -o $@/" CLTRAMP3D
	./CLTRAMP3D
run-mem-bw:
	make -s -C workloads/mmm run-textbook > /dev/null
	@echo $(DO) profile -a workloads/mmm/m0-n8192-u01.llv -s1 --tune :perf-stat:\"\'-C2\'\" # for profiling
test-mem-bw: run-mem-bw
	sleep 2s
	set -o pipefail; $(DO) profile -s2 $(ST) -o $< $(RERUN) | $(SHOW)
	kill -9 `pidof m0-n8192-u01.llv`
run-mt:
	./omp-bin.sh $(NUM_THREADS) ./workloads/mmm/m9b8IZ-x256-n8448-u01.llv &
test-mt: run-mt
	sleep 2s
	set -o pipefail; $(DO) profile -s1 $(RERUN) | $(SHOW)
	kill -9 `pidof m9b8IZ-x256-n8448-u01.llv`
test-bc2:
	$(DO2) -pm 40 | $(SHOW)
test-metric:
	$(DO) profile $(METRIC) --stdout -pm 2
	$(DO) profile -pm 40 | $(SHOW)

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
	@lscpu | grep 'Model name'

help: do-help.txt
do-help.txt: do.py common.py pmu.py
	./pmu.py
	./$< -h > $@ && sed -i 's|/home/admin1/ayasin/perf-tools|\.|' $@
	$(DO) profile --tune :flameg:1 :forgive:1 :help:-1 :msr:1 :tma-group:"'Auto-Detect'" :sample:3 --mode profile \
	    -pm fffff > /dev/null && cat profile-mask-help.md

update:
	$(DO) tools-update -v1
test-build:
	$(DO) build profile -a datadep -g " -n120 -i 'add %r11,%r12'" -ki 20e6 -e FRONTEND_RETIRED.DSB_MISS -n '+Core_Bound*' -pm 22 | $(SHOW)
	grep Time datadep-20e6.toplev-vl2.log
	./do.py profile -a './kernels/datadep 20000001' -e FRONTEND_RETIRED.DSB_MISS --tune :interval:50 \
	    -pm 10006 -r 1 | $(SHOW) # tests ocperf -e (w/ old perf tool) in all perf-stat steps, --repeat, :interval
test-default:
	$(DO1) -pm $(PM)
test-study: study.py stats.py run.sh do.py
	rm -f ./{.,}{{run,BC2s}-cfg*,$(AP)-s*}
	@echo ./$< cfg1 cfg2 -a ./run.sh --tune :loops:0 -v1 > $@
	./$< cfg1 cfg2 -a ./run.sh --tune :loops:0 -v1 >> $@ 2>&1 || $(FAIL)
	@tail $@
	test -f run-cfg1-t1.$(CPU).stat && test -f run-cfg2-t1.$(CPU).stat
	@echo ./$< cfg1 cfg2 -a ./pmu-tools/workloads/BC2s --mode all-misp >> $@
	./$< cfg1 cfg2 -a ./pmu-tools/workloads/BC2s --mode all-misp >> $@ 2>&1
	test -f BC2s-cfg1-t1-b-eevent0xc5umask0nameBR_MISP_RETIREDppp-c20003.perf.data.ips.log
	test -f BC2s-cfg2-t1-b-eevent0xc5umask0nameBR_MISP_RETIREDppp-c20003.perf.data.ips.log
test-stats: stats.py
	@$(MAKE) test-default APP="$(APP) s" PM=1012 > /dev/null 2>&1
	./stats.py $(AP)-s.toplev-vl6-perf.csv && test -f $(AP)-s.$(CPU).stat
test-srcline: lbr.py do.py common.py
	cd kernels && clang -g -O2 pagefault.c -o pagefault-clang > /dev/null 2>&1
	$(DO) $(CMD) -a './kernels/pagefault-clang 1000000' -pm 100 --tune :loop-srcline:1 > /dev/null 2>&1
	grep -q 'srcline: pagefault.c;43' pagefault-clang-1000000*info.log || $(FAIL)

clean:
	rm -rf {run,BC,datadep,$(AP),openssl}*{csv,data,old,log,txt} test-{dir,study} .CLTRAMP3D-u*cmd
pre-push: help
	$(DO) version log help -m GFLOPs --tune :msr:1          # tests help of metric; version; prompts for sudo password
	$(MAKE) test-mem-bw SHOW="grep --color -E '.*<=='"      # tests sys-wide + topdown tree; MEM_Bandwidth in L5
	$(MAKE) test-metric SHOW="grep --color -E '^|Ret.*<=='" # tests perf -M IpCall & colored TMA, then toplev --drilldown
	$(DO) log                                               # prompt for sudo soon after
	$(MAKE) test-bc2 SHOW="grep --color -E '^|Mispredict'"	# tests topdown across-tree tagging; Mispredict
	$(MAKE) test-build SHOW="grep --color -E '^|build|DSB|Ports'" # tests build command, perf -e, toplev --nodes; Ports_*
	$(MAKE) test-mem-bw RERUN='-pm 400 -v1'                 # tests load-latency profile-step + verbose:1
	$(MAKE) test-default PM=313e                            # tests default non-MUX sensitive profile-steps
	$(DO1) --toplev-args ' --no-multiplex --frequency \
	    --metric-group +Summary' -pm 1010                   # carefully tests MUX sensitive profile-steps
	$(DO) profile -a './workloads/BC.sh 7' -d1 > BC-7.log 2>&1 || $(FAIL) # tests --delay
	$(DO) prof-no-mux -a './workloads/BC.sh 1' -pm 82 && test -f BC-1.$(CPU).stat   # tests prof-no-aux command
	$(MAKE) test-default DO_ARGS=":calibrate:1 :loops:0 :msr:1 :perf-filter:0 :sample:3 :size:1 -o $(AP)-u $(DO_ARGS)" \
	    CMD='suspend-smt profile tar' PM=1931a &&\
	    test -f $(AP)-u.perf_stat-I10.csv && test -f $(AP)-u.toplev-vvvl2.log && test -f $(AP)-u.$(CPU).results.tar.gz\
	    # tests unfiltered- calibrated-sampling; PEBS, tma group & over-time profile-steps, tar command
	mkdir test-dir; cd test-dir; ln -s ../run.sh; ln -s ../common.py; make test-default APP=../pmu-tools/workloads/BC2s \
	    DO=../do.py -f ../Makefile > ../test-dir.log 2>&1   # tests default from another directory, toplev describe
	@cp -r test-dir{,0}; cd test-dir0; ../do.py clean; ls -l # tests clean command
	$(MAKE) test-study                                      # tests study script (errors only)
	$(MAKE) test-stats                                      # tests stats module
	$(MAKE) test-srcline                                    # tests srcline loop stat
	$(PY3) $(DO) profile --tune :forgive:0 -pm 10 > .do-forgive.log 2>&1  || echo skip
	$(PY3) $(DO) profile > .do.log 2>&1 || $(FAIL)          # tests default profile-steps (errors only)
	$(DO) setup-all profile --tune :loop-ideal-ipc:1 -pm 300 > .do-ideal-ipc.log 2>&1 || $(FAIL) # tests setup-all, ideal-IPC
	$(PY2) $(DO) profile --tune :time:2 -v3 > .do-time2.log 2>&1 || $(FAIL) # tests default w/ :time (errors only)
	time $(DO) profile -a "openssl speed rsa2048" --tune :loops:9 :time:2 > openssl.log 2>&1 || $(FAIL)

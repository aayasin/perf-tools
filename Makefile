DO = ./do.py
ST = --toplev-args ' --single-thread --frequency --metric-group +Summary'
APP = taskset 0x4 ./CLTRAMP3D
DO1 = $(DO) profile -a "$(APP)" --tune :loops:10 $(DO_ARGS)
DO2 = $(DO) profile -a pmu-tools/workloads/BC2s $(DO_ARGS)
FAIL = (echo "failed! $$?"; exit 1)
RERUN = -pm 0x80
MAKE = make --no-print-directory
MGR = sudo $(shell python -c 'import common; print(common.os_installer())')
SHELL := /bin/bash
SHOW = tee
NUM_THREADS = $(shell grep ^cpu\\scores /proc/cpuinfo | uniq |  awk '{print $$4}')

all: tramp3d-v4
	@echo done
git:
	$(MGR) -y -q install git
install: link-python llvm
	make -s -C workloads/mmm install
link-python:
	sudo ln -f -s $(shell find /usr/bin -name 'python[1-9]*' -executable | egrep -v config | sort -n -tn -k3 | tail -1) /usr/bin/python
llvm:
	$(MGR) -y -q install curl clang

intel:
	git clone https://gitlab.devtools.intel.com/micros/dtlb
	cd dtlb; ./build.sh
	git clone https://github.com/intel-innersource/applications.benchmarking.cpu-micros.inst-lat-bw
	wget https://downloadmirror.intel.com/763324/mlc_v3.10.tgz
tramp3d-v4: pmu-tools/workloads/CLTRAMP3D
	cd pmu-tools/workloads; ./CLTRAMP3D; cp tramp3d-v4.cpp CLTRAMP3D ../..; rm tramp3d-v4.cpp
	sed -i "s/11 tramp3d-v4.cpp/11 tramp3d-v4.cpp -o $@/" CLTRAMP3D
	./CLTRAMP3D
run-mem-bw:
	make -s -C workloads/mmm run-textbook > /dev/null
test-mem-bw: run-mem-bw
	sleep 2s
	set -o pipefail; $(DO) profile -s2 $(ST) $(RERUN) | $(SHOW)
	kill -9 `pidof m0-n8192-u01.llv`
run-mt:
	./omp-bin.sh $(NUM_THREADS) ./workloads/mmm/m9b8IZ-x256-n8448-u01.llv &
test-mt: run-mt
	sleep 2s
	set -o pipefail; $(DO) profile -s1 $(RERUN) | $(SHOW)
	kill -9 `pidof m9b8IZ-x256-n8448-u01.llv`
test-bc2:
	$(DO2) -pm 42 | $(SHOW)
test-metric:
	$(DO) profile -m IpCall --stdout -pm 2
	$(DO) profile -pm 40 | $(SHOW)

clean:
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
do-help.txt: do.py
	./$^ -h > $@

update:
	$(DO) tools-update -v1
test-build:
	$(DO) build profile -a datadep -g " -n120 -i 'add %r11,%r12'" -ki 20e6 -e FRONTEND_RETIRED.DSB_MISS \
	-n '+Core_Bound*' -pm 22
test-default:
	$(DO1) -pm 0x317f
test-study:
	rm -f run-cfg*
	./study.py cfg1 cfg2 -a ./run.sh --tune :loops:0 -v1 > .study.log 2>&1 || $(FAIL)

pre-push: help tramp3d-v4
	rm -rf {run,BC2s,datadep,CLTRAMP3D}*{csv,data,old,log,txt} test-dir
	$(DO) help -m GFLOPs --tune :help:1
	$(MAKE) test-mem-bw SHOW="grep --color -E '.*<=='" 	    # tests sys-wide + topdown tree; MEM_Bandwidth in L5
	$(MAKE) test-metric SHOW="grep --color -E '^|Ret.*<=='" # tests perf -M IpCall, toplev --drilldown
	$(MAKE) test-bc2 SHOW="grep --color -E '^|Mispredict'"	# tests topdown across-tree tagging; Mispredict
	$(MAKE) test-build                                      # tests build command, perf -e, toplev --nodes; Ports_Utilized_1
	$(MAKE) test-mem-bw RERUN='-pm 400 -v1'                 # tests load-latency profile-step + verbose:1
	$(MAKE) test-default                                    # tests default non-MUX sensitive commands
	mkdir test-dir; cd test-dir; make -f ../Makefile test-default \
	    DO=../do.py APP=../pmu-tools/workloads/BC2s         # tests default from another directory, toplev describe
	$(DO1) --toplev-args ' --no-multiplex --frequency \
	    --metric-group +Summary' -pm 1010                   # carefully tests MUX sensitive commands
	$(MAKE) test-study                                      # tests study script (errors only)
	$(DO1) > .do.log 2>&1 || $(FAIL)                        # tests default profile-steps (errors only)

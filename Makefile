.PHONY: clean clean-all help
AP = CLTRAMP3D
APP = taskset 0x4 ./$(AP)
AP_MT = perf bench numa mem -p 16 -C0-15
CC = clang
CPP = /usr/bin/clang++
CLONE = git clone --recurse-submodules https://github.com/aayasin/perf-tools
CMD = profile
CPU = $(shell ./pmu.py CPU)
DO = ./do.py # Use e.g. DO="do.py --perf /my/perf" to init things, or DO_SUFF to override things
DO1 = $(DO) $(CMD) -a "$(APP)" --tune :loops:10
DO2 = $(DO) $(CMD) -a 'workloads/BC.sh 3'
FAIL = (echo 'failed! $$?'; exit 1)
JAVA = java
MAKE = make --no-print-directory
METRIC = -m IpCall
MGR = sudo $(shell python -c 'import common; print(common.os_installer())') -y -q
NUM_THREADS = $(shell grep ^cpu\\scores /proc/cpuinfo | uniq |  awk '{print $$4}')
OPT = -static -fcf-protection=none
PM = $(shell python -c 'import common; print("0x%x" % common.PROF_MASK_DEF)')
PY2 = python2.7
PY3 = python3
RERUN = -pm 0x80
SHELL := /bin/bash
SHOW = tee
SKIP_EX = false # Skip extra checks
SS = 4
ST = --toplev-args ' --single-thread --frequency --metric-group +Summary'
TEST_LBR_PERF = 1
TEST_MEM_Bandwidth = 1
TREE_C=$(shell python -c 'from common1 import registrar as r; print(r.name("tree", "csv"))')
TREE_L=$(shell python -c 'from common1 import registrar as r; print(r.name("tree"))')

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
install-python3.12:
	wget https://www.python.org/ftp/python/3.12.0/Python-3.12.0.tgz
	tar -xf Python-3.12.0.tgz
	cd Python-3.12.0 && export PYTHON_CFLAGS='-fno-omit-frame-pointer -mno-omit-leaf-frame-pointer' && ./configure --enable-optimizations && make -j `nproc` && realpath python
link-python:
	sudo ln -f -s $$(find /usr/bin -name 'python[1-9]*' -executable | grep -E -v config | sort -n -tn -k3 | tail -1) /usr/bin/python
diff:
	git diff | grep -v '^\-' | less
intel:
	git clone https://gitlab.devtools.intel.com/micros/dtlb
	cd dtlb; ./build.sh
	#git clone https://github.com/intel-innersource/applications.benchmarking.cpu-micros.inst-lat-bw
	#wget https://downloadmirror.intel.com/763324/mlc_v3.10.tgz
workloads/permute: workloads/src/permute.cpp $(CPP)
	$(CPP) -g -std=c++17 $(OPT) $< -o $@
tramp3d-v4: pmu-tools/workloads/CLTRAMP3D $(CPP)
	cd pmu-tools/workloads; ./CLTRAMP3D; cp tramp3d-v4.cpp CLTRAMP3D ../..; rm tramp3d-v4.cpp
	sed -i "s/11 tramp3d-v4.cpp/11 tramp3d-v4.cpp -o $@/" CLTRAMP3D
	./CLTRAMP3D

run-mem-bw:
	make -s -C workloads/mmm run-textbook > /dev/null
	@echo "#" $(DO) profile -a workloads/mmm/m0-n8192-u01.llv -s$(SS) -C2 # for debugging
test-mem-bw: run-mem-bw
	sleep 2s
	set -o pipefail; $(DO) profile -s$(SS) $(ST) -o $< $(RERUN) | $(SHOW)
	./yperf record -o $<-yperf && touch $<-yperf # collect for later
	kill -9 `pidof m0-n8192-u01.llv`
ifeq ($(TEST_MEM_Bandwidth), 1)
	grep -E -q 'Backend_Bound.Memory_Bound.DRAM_Bound.MEM_Bandwidth.*<==' $<.toplev-mvl6-nomux.log
else
	grep -E -q 'Backend_Bound.Memory_Bound.DRAM_Bound.MEM_Bandwidth' $<.toplev-mvl6-nomux.log
endif
	@echo 1 | tee $< > $@
test-yperf: run-mem-bw-yperf workloads/permute
	./yperf record -pm 100 -o permute-yperf -- ./workloads/permute abcdefghijk
	./yperf report -pm 100 -o permute-yperf -- ./workloads/permute abcdefghijk
	./yperf record -pm 102 -o CLTRAMP3D-yperf -- ./CLTRAMP3D
	./yperf report -pm 102 -o CLTRAMP3D-yperf -- ./CLTRAMP3D
	./yperf report -o $<
ifneq ($(CPU), ICX)
	./yperf advise -o $<
	./yperf advise -o permute-yperf
	./yperf advise -o CLTRAMP3D-yperf
	./yperf record -pm 100 -o perf-bench-numa-mem-yperf -C4-7 --tune :calibrate:1 -- $(AP_MT)
	./yperf report -pm 100 -o perf-bench-numa-mem-yperf -C4-7 --tune :calibrate:1 -- $(AP_MT) # fails on ICX!
	./yperf advise -o perf-bench-numa-mem-yperf
endif

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
	$(MAKE) test-bc2     CMD='profile analyze' PM=$(AZ_PM)          DO="$(DO)"
	$(MAKE) test-default CMD=analyze PM=$(AZ_PM) TEST_LBR_PERF=0    DO="$(DO)"
test-bc2:
	$(DO2) -pm $(PM) | $(SHOW)

CPUIDI = 200000000
test-bottlenecks: kernels/cpuid
	$(DO1) -pm 10 --tune :help:0 :forgive:2
	grep Bottleneck cpuid-$(CPUIDI)$(TREE_L) | sed 's/core Bottleneck/Bottleneck/' | sort -n -k4 | tail -1 | grep --color Irregular_Overhead
test-build:
	$(DO) build profile -a datadep -g " -n120 -i 'add %r11,%r12'" -ki 20e6 -e FRONTEND_RETIRED.DSB_MISS -n '+Core_Bound*' -pm 22 | $(SHOW)
	grep -q 'Backend_Bound.Core_Bound.Ports_Utilization.Ports_Utilized_1' datadep-20e6.toplev-vl2.log
	grep Time datadep-20e6.toplev-vl2.log
	$(SKIP_EX) || ( set -o pipefail; $(DO) profile -a './kernels/datadep 20000001' -e FRONTEND_RETIRED.DSB_MISS --tune :interval:50 \
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
	$(DO1) -pm $(PM) --print-only $(DO_SUFF) > test-print-only
	@echo 1 > $@
test-LBR-edge:
	$(DO1) --tune :perf-lbr:\"'-j any,save_type -e instructions:ppp -c 3000001'\" -pm 100 > /dev/null 2>&1 || $(FAIL)
	$(DO1) --tune :perf-lbr:\"'-j any,save_type -e cycles:p -c 2000001'\" -pm 100 > /dev/null 2>&1 || $(FAIL)

install-jit:
	$(MAKE) install1 PKG="openjdk-17-jdk openjdk-17-jre xterm"
	#cd .. && git clone https://github.com/jvm-profiling-tools/perf-map-agent && cd perf-map-agent && export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 && cmake . && make && echo "Successfully built perf-map-agent"
	#cd .. && git clone https://github.com/brendangregg/FlameGraph && cd FlameGraph && export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64 && sed -i -e "s|JAVA_HOME=\${JAVA_HOME:-.*|JAVA_HOME=\${JAVA_HOME:-/usr/lib/jvm/java-17-openjdk-amd64}|g;s|AGENT_HOME=\${AGENT_HOME:-.*|AGENT_HOME=\${AGENT_HOME:-../perf-map-agent}|g" jmaps
JAVA_CMD = $(JAVA) -XX:+PrintFlagsFinal -XX:+PreserveFramePointer -agentpath:$(shell tail -1 find-jvmti.txt)
run-jit: ./workloads/CryptoBench.java
	$(DO) profile --tune :perf-jit:1 -s1 -pm 4 #hack to create jvmti.txt file
	$(JAVA_CMD) $< 999 2>&1 > $@ &
	#$(JAVA)c $< # useful in newer JAVA versions
	#$(JAVA_CMD) workloads.CryptoBench 999 2>&1 > $@ &
	@echo $(JAVA_CMD) $< 999 >> java-s$(SS)-out.txt
	pidof java
	xterm -T "java $<" -e "tail -f $@" &
DO_JIT = $(DO) $(CMD) -pm 1333a --tune :perf-jit:1 :run:"'scripts/sleep @1 run-jit'" :forgive:2 :help:0 :sample:3 :perf-pebs:"'-b -e cpu/event=0xc2,umask=0x2,inv=1,cmask=1,name=UOPS_RETIRED.STALLS/pp -c 90001'" -s$(SS) -a java-s$(SS)
test-jit: run-jit
	sleep 20
	$(DO_JIT) --mode profile
	@grep UseAVX run-jit | tee -a java-s$(SS)-out.txt
	$(DO_JIT) --mode process -pm 8 &
	$(DO_JIT) --mode process -pm 200 &
	$(DO_JIT) --mode process -pm 102
	$(MAKE) test-jit-analyze CMD=analyze
	$(MAKE) kill-jit
test-jit-analyze:
	$(DO_JIT)
kill-jit: run-jit
	kill -9 `pidof java`
	mv run-jit{,.$$PPID}
	echo run-jit.$$PPID >> java-s$(SS)-out.txt

FSI = 400000000
test-false-sharing: kernels/false-sharing
	$(DO) profile --tune :help:0 -a "$< $(FSI)" -pm 40
	grep -E -q '^BE.*False_Sharing.*<==' $<-$(FSI)-out.txt

CPUS = GNR LNL ICX SPR SPR-HBM TGL ADL
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
	./stats.py $(AP)$(TREE_C) && test -f $(AP).$(CPU).stat
	@echo 1 > $@

TS_A = ./$< cfg1 cfg2 -a ./run.sh --tune :loops:0 -sm 7 -v1 $(DO_SUFF)
TS_B = STUDY_MODE=all-misp ./$< cfg1 cfg2 -a ./pmu-tools/workloads/BC2s --tune :forgive:2 $(DO_SUFF)
TS_C = STUDY_MODE=dsb-bw ./$< cfg1 cfg2 -t2 -a ./run.sh --tune :loops:0 -sm 7 -v1 $(DO_SUFF)
TS_D = STUDY_MODE=mem-bw ./$< cfg1 cfg2 -t3 -a ./run.sh --tune :loops:0 -sm 27 -v1 $(DO_SUFF)
TS_E = STUDY_MODE=code-l2pf LBR_VERBOSE=0x10 ./$< s1 s2 -a ./$(AP) --score IpUnknown_Branch --tune :loops:0 -sm 3 -v1 $(DO_SUFF)
test-study: study.py stats.py run.sh do.py
	rm -f ./{.,}{{run,BC2s}-cfg*,$(AP)-s*}
	@echo $(TS_A) > $@
	$(TS_A) >> $@ 2>&1 || $(FAIL)
	@tail $@
	test -f run-cfg1-t1.$(CPU).stat && test -f run-cfg2-t1.$(CPU).stat
	test -f run-cfg1-t1_run-cfg2-t1.stats.log
	@echo $(TS_B) >> $@
	$(TS_B) >> $@ 2>&1
	#amiri: test -f BC2s-cfg1-t1-b-e*nameBR_MISP_RETIRED*.perf.data.ip*.log
	grep -q '\-paths\-' BC2s-cfg2-t1-b-e*nameBR_MISP_RETIRED*.perf.data.ip*.log
	test -f BC2s-cfg1-t1_BC2s-cfg2-t1.stats.log
	#amiri @echo $(TS_C) >> $@
	#$(TS_C) >> $@ 2>&1
	@echo $(TS_D) >> $@
	$(TS_D) >> $@ 2>&1
	@echo $(TS_E) >> $@
	$(TS_E) >> $@ 2>&1
	grep -q '^callchain' $(AP)-s[12]-t1-b*FRONTEND_RETIRED*.ip*.log

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

blender_barbershop_arls_baseline-c4000003.perf.script.gz:
	wget https://github.com/user-attachments/assets/967ec1db-a481-4923-8517-def77e20b58d && mv 967ec1db-a481-4923-8517-def77e20b58d $@
test-windows: blender_barbershop_arls_baseline-c4000003.perf.script.gz
	$(DO) process-win -a $<
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

L = 11
PMUTOOLS = $(shell python -c 'import common; print(common.dirname())')/pmu-tools
TMA_V = $(shell $(DO) version --pmu-tools $(PMUTOOLS) | cut -d= -f7)
test-pmu-tools: do.py pmu.py
	RUN_NLOOP=$(L) PMUTOOLS=$(PMUTOOLS) $(DO) --pmu-tools $(PMUTOOLS) profile --tune :help:0  -pm 82 -o python-nomux-l$(L)-tma$(TMA_V) $(DO_SUFF)
	RUN_NLOOP=$(L) PMUTOOLS=$(PMUTOOLS) $(DO) --pmu-tools $(PMUTOOLS) profile --tune :help:0  -pm 1012 -o python-l$(L)-tma$(TMA_V) $(DO_SUFF)

PT=perf-tools.1
clean:
	rm -rf {$(AP),`echo $(AP_MT)|sed 's/ /-/g'`,CLTRAMP3D[.\-],BC,datadep,openssl,pagefault,permute,run}*{csv,data,old,log,txt,json,.tar.gz} \
	    $(PT) run-mem-bw* setup-system-* test-{default-track-perf,dir,ideal-ipc,mem-bw,srcline,stats,study} .CLTRAMP3D*cmd .ipc_*.txt
	rm -f .prepush_state.cmd
post-push:
	$(CLONE) $(PT) && cd $(PT) && ./do.py setup-perf log && cd .. && rm -rf $(PT)   # tests a fresh clone

PRE_PUSH_CMDS := \
    "echo 'testing help of metric; version; prompts for sudo password' && $(DO) version log help -m GFLOPs --tune :msr:1" \
    "echo 'testing sys-wide + topdown tree; MEM_Bandwidth in L5' && $(MAKE) test-mem-bw SHOW=\"grep --color -E '.*<=='\"" \
    "echo 'testing perf -M IpCall & colored TMA, then toplev --drilldown' && $(MAKE) test-metric SHOW=\"grep --color -E '^|Ret.*<=='\"" \
    "echo 'prompting for sudo soon1' && $(DO) log" \
    "echo 'testing topdown across-tree tagging; Mispredict' && $(MAKE) test-bc2 PM=40 SHOW=\"grep --color -E '^|Mispredict'\"" \
    "echo 'testing topdown ~overlap in Threshold attribute' && echo skip: $(MAKE) test-false-sharin" \
    "echo 'testing Bottlenecks View' && $(MAKE) test-bottlenecks AP=\"./kernels/cpuid $(CPUIDI)\"" \
    "echo 'testing build command, perf -e, toplev --nodes; Ports_*' && $(MAKE) test-build SHOW=\"grep --color -E '^|build|DSB|Ports'\"" \
    "echo 'testing load-latency profile-step + verbose:1' && rm -f run-mem-bw && $(MAKE) test-mem-bw RERUN='-pm 400 -v1'" \
    "echo 'building CLTRAMP3D workload for upcoming tests' && $(MAKE) tramp3d-v4" \
    "echo 'testing default profile-steps, tracks LBR speed' && $(MAKE) test-default-track-perf" \
    "echo 'testing stats module' && $(MAKE) test-stats" \
    "echo 'testing analyze module' && $(MAKE) test-analyze" \
    "echo 'prompting for sudo soon2' && $(DO) log" \
    "echo 'running the yperf profiler' && $(MAKE) test-yperf" \
    "echo 'testing --cpu' && $(DO) profile -C4-7 -pm 11116 -a \"$(AP_MT)\" > AP-mt.log 2>&1 || $(FAIL)" \
    "echo 'testing --delay' && $(DO) profile -a './workloads/BC.sh 9' -d1 > BC-9.log 2>&1 || $(FAIL)" \
    "echo 'testing prof-no-mux command' && $(DO) prof-no-mux -a './workloads/BC.sh 1' -pm 82 && test -f BC-1.$(CPU).stat" \
    "echo 'testing unfiltered-calibrated-sampling; PEBS, tma group, bottlenecks-view, pipeline-view & over-time profile-steps, tar command' && \
      $(MAKE) test-default DO_SUFF=\"--tune :calibrate:-1 :loops:0 :msr:1 :perf-filter:0 :perf-annotate:0 :sample:3 :size:1 \
      -o $(AP)-u $(DO_SUFF)\" CMD='suspend-smt profile tar' PM=23931a && test -f $(AP)-u.$(CPU).results.tar.gz && \
      test -f $(AP)-u.perf_stat-I10.csv && test -f $(AP)-u.toplev-vl2-Fed.log && \
      test -f $(AP)-u.perf_stat-r1-I1000.pipeline.log" \
    "echo 'prompting for sudo soon3' && $(DO) log" \
    "echo 'testing Windows support' && $(MAKE) test-windows" \
    "echo 'testing sys-wide non-MUX profile-steps' && \
     $(MAKE) test-default APP=./$(AP) CMD=\"log profile\" PM=313e DO_SUFF=\"--tune :perf-stat:\\\"' -a'\\\" :perf-record:\\\"' -a -g'\\\" \
     :perf-lbr:\\\"'-a -j any,save_type -e r20c4:ppp -c 90001'\\\" :perf-filter:0 -o $(AP)-a\"" \
    "echo 'testing default from another directory, toplev describe' && mkdir -p test-dir; cd test-dir; ln -sf ../common.py && \
     make test-default APP=../pmu-tools/workloads/COMPILE10s DO=../do.py -f ../Makefile > ../test-dir.log 2>&1" \
    "echo 'testing clean command' && cp -r test-dir test-dir0; cd test-dir0; ../do.py clean; ls -l" \
    "echo 'testing study script (errors only)' $(MAKE) test-study" \
    "echo 'testing srcline stat' && $(MAKE) test-srcline" \
    "echo 'testing tripcount-mean calculation' && $(MAKE) test-tripcount-mean" \
    "echo 'testing sampling by instructions' && $(MAKE) test-LBR-edge" \
    "echo 'testing pipeline-view sys-wide idle' && $(DO) profile -pm 200000 -s 30 -o pipeline-view -v1 " \
    "$(PY3) $(DO) log profile --tune :forgive:0 -pm 10 > .do-forgive.log 2>&1" \
    "echo 'testing default profile-steps (errors only)' && $(PY3) $(DO) profile > .do.log 2>&1 || $(FAIL)" \
    "echo 'testing setup-all, ideal-IPC' && $(DO) setup-all profile --tune :loop-ideal-ipc:0x3 -pm 300 -o test-ideal-ipc > test-ideal-ipc 2>&1 || $(FAIL)" \
    "echo 'timing openssl' && time $(DO) profile -a \"openssl speed rsa2048\" --tune :loops:9 :time:2 > openssl.log 2>&1 || $(FAIL)" \
    "echo 'testing default w/ python2 (errors only)' && $(PY2) ./do.py profile -v3 > .do-$(PY2).log 2>&1 || $(FAIL)"

pre-push: help
	@for cmd in $(PRE_PUSH_CMDS); do \
		if ! grep -Fxq "$$cmd" .prepush_state.cmd 2>/dev/null; then \
			/bin/bash -c "$$cmd" || exit 1; \
			echo "$$cmd" >> .prepush_state.cmd; \
		fi; \
	done


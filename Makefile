DO = ./do.py
PM = 0x80
MGR = sudo apt
SHOW = tee
NUM_THREADS = $(shell grep ^cpu\\scores /proc/cpuinfo | uniq |  awk '{print $$4}')

all: tramp3d-v4
	@echo done
install: link-python llvm
	make -s -C workloads/mmm install
link-python:
	sudo ln -f -s $(shell find /usr/bin -name 'python[1-9]*' -executable | egrep -v config | sort -n -tn -k3 | tail -1) /usr/bin/python
llvm:
	$(MGR) -y -q install curl clang

intel:
	git clone https://gitlab.devtools.intel.com/micros/dtlb
	cd dtlb; ./build.sh
tramp3d-v4: pmu-tools/workloads/CLTRAMP3D
	cd pmu-tools/workloads; ./CLTRAMP3D; cp tramp3d-v4.cpp CLTRAMP3D ../..; rm tramp3d-v4.cpp
	sed -i "s/11 tramp3d-v4.cpp/11 tramp3d-v4.cpp -o $@/" CLTRAMP3D
	./CLTRAMP3D
run-mem-bw:
	make -s -C workloads/mmm run-textbook > /dev/null
test-mem-bw: run-mem-bw
	sleep 2s
	$(DO) profile -s1 -pm $(PM) | $(SHOW)
	kill -9 `pidof m0-n8192-u01.llv`
run-mt:
	./omp-bin.sh $(NUM_THREADS) ./workloads/mmm/m9b8IZ-x256-n8448-u01.llv &
test-mt: run-mt
	sleep 2s
	$(DO) profile -s1 -pm $(PM) | $(SHOW)
	kill -9 `pidof m9b8IZ-x256-n8448-u01.llv`

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
do-help.txt: $(DO)
	./$^ -h > $@

pre-push: help tramp3d-v4
	$(DO) help -m GFLOPs
	make test-mem-bw SHOW="grep --color -E '.*<=='" 	# tests sys-wide + topdown tree; MEM_Bandwidth in L5
	$(DO) profile -m IpCall --stdout -pm 42				# tests perf -M + toplev --drilldown
	$(DO) profile -a pmu-tools/workloads/BC2s -pm 42	# tests topdown across-tree tagging
	$(DO) profile -a ./CLTRAMP3D --tune :loops:20		# tests default commands

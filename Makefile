DO = ./do.py
PM = 0x80
SHOW = tee

all: tramp3d-v4
	@echo done
install:
	sudo apt -y -q install curl clang
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
clean:
	rm tramp3d-v4{,.cpp} CLTRAMP3D
list:
	@grep '^[^#[:space:]].*:' Makefile | cut -d: -f1 | sort #| tr '\n' ' '

lspmu:
	@python -c 'import pmu; print(pmu.name())'
	@lscpu | grep 'Model name'

help: do-help.txt
do-help.txt: $(DO)
	./$^ -h > $@


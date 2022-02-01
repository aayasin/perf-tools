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
test-mem-bw:
	make -s -C workloads/mmm run-textbook > /dev/null
	sleep 2s
	./do.py profile -s1 -pm 80 | $(SHOW)
	kill -9 `pidof m0-n8192-u01.llv`
clean:
	rm tramp3d-v4{,.cpp} CLTRAMP3D

help: do-help.txt
do-help.txt: do.py
	./$^ -h > $@


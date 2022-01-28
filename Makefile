all: tramp3d-v4
	@echo done
install:
	sudo apt -y -q install curl clang
tramp3d-v4: pmu-tools/workloads/CLTRAMP3D
	cd pmu-tools/workloads; ./CLTRAMP3D; cp tramp3d-v4.cpp CLTRAMP3D ../..; rm tramp3d-v4.cpp
	sed -i "s/11 tramp3d-v4.cpp/11 tramp3d-v4.cpp -o $@/" CLTRAMP3D
	./CLTRAMP3D
clean:
	rm tramp3d-v4{,.cpp} CLTRAMP3D

help: do-help.txt
do-help.txt: do.py
	./$^ -h > $@


MGR = sudo spt
all: run-textbook
	@echo mmm running in background ..
install:
	$(MGR) install libomp-dev
#sudo ln -s /usr/lib64/libomp.so{,.5} #Fedora hack
run-textbook:
	./mmm-textbook.sh &

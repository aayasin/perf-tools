#!/bin/bash
git clone https://github.com/facebookresearch/DCPerf
cd DCPerf/
./benchpress_cli.py install django_workload_default
export JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64/bin
export PATH=$JAVA_HOME:$PATH JAVA=$JAVA_HOME/java
printf "\n-XX:+PreserveFramePointer\n" >> benchmarks/django_workload/apache-cassandra/conf/jvm.options
# likely need to adjust next path per your setup
printf "-agentpath:/usr/lib/linux-tools/5.15.0-127-generic/libperf-jvmti.so\n" >> benchmarks/django_workload/apache-cassandra/conf/jvm.options
./benchpress_cli.py run django_workload_default -r standalone
#./benchmarks/django_workload/bin/run.sh -r standalone -d 5M -i 7 -p 0 -l ./siege.log -s urls.txt -c 127.0.0.1
./benchmarks/django_workload/bin/run.sh -r standalone -d 3M -i 1 -p 0 -l ./siege.log -s urls.txt -c 127.0.0.1 -m 0 -M 0 # disable ICache buster!

#!/bin/sh
if [ $# -le 0 ]; then
	echo $0: must an integer arg
	exit 1
fi
echo "3^${1}15312" | bc > /dev/null

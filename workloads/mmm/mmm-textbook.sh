#!/bin/sh
PIN=${PIN:-0x4}
taskset $PIN ./m0-n8192-u01.llv

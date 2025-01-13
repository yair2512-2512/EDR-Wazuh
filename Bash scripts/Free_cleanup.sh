#!/bin/bash
echo "Cleaning swap memory..."
sync; echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a
echo "Swap memory has been cleared."
top -b -o +%MEM | head -n 10 | awk '{print $1}' | xargs kill -9

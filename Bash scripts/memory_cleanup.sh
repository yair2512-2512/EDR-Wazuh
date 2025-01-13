#!/bin/bash
# This script checks for memory usage and terminates heavy processes, disables related services, and clears memory cache.
MEM_FREE=$(cat /proc/meminfo | grep MemFree | awk '{print $2}')
HEAVY_PROCESSES=$(ps aux --sort=-%mem | awk 'NR<=5{print $2, $3, $11}' | grep -v "PID")

if [ -n "$HEAVY_PROCESSES" ]; then
    echo "Warning: The following processes are using too much memory, killing them now:"
    echo "$HEAVY_PROCESSES"
    
    for pid in $(echo "$HEAVY_PROCESSES" | awk '{print $1}'); do
        kill -9 $pid
        service_name=$(ps -p $pid -o comm=) 
        if [ -n "$service_name" ]; then
            echo "Disabling and masking the service: $service_name"
            sudo systemctl stop $service_name
            sudo systemctl disable $service_name
            sudo systemctl mask $service_name
        fi
    done
fi

echo "Clearing cache to free memory..."
sync; echo 3 > /proc/sys/vm/drop_caches

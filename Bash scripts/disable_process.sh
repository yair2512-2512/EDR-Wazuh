#!/bin/bash
# This script kills a process by PID, prevents its associated service from restarting, and removes related cron jobs.
if [ -z "$1" ]; then
  echo "Please specify the PID of the process."
  exit 1
fi

pid="$1"

if ps -p $pid > /dev/null; then
  echo "Killing the process with PID $pid..."
  kill -9 $pid
  echo "Action completed."

  service_name=$(ps -p $pid -o comm=) 

  if systemctl list-units --type=service | grep -q "$service_name"; then
    echo "Preventing the service from restarting: $service_name"
    systemctl stop "$service_name"
    systemctl disable "$service_name"
  fi

  crontab -l | grep -v "$service_name" | crontab -
  echo "Removed relevant cron jobs."
else
  echo "No process found with PID $pid."
  exit 2
fi


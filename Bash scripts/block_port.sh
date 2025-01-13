#!/bin/bash
# This script terminates processes using a specified port and then blocks the port using UFW.
PORT=$1
PIDS=$(fuser $PORT/tcp 2>/dev/null)
if [ ! -z "$PIDS" ]; then
    echo "Terminating process using port $PORT..."
    for PID in $PIDS; do
        kill -9 $PID
    done
fi
echo "Blocking port $PORT..."
ufw deny $PORT/tcp
echo "Port $PORT is now blocked."

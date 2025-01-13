#!/bin/bash
PORT=$1  
PROCESS_INFO=$(lsof -i :$PORT | grep LISTEN)
if [ -z "$PROCESS_INFO" ]; then
  echo "No process is listening on port $PORT"
  exit 0
fi
PID=$(echo "$PROCESS_INFO" | awk '{print $2}')
PROCESS_NAME=$(echo "$PROCESS_INFO" | awk '{print $1}')
echo "Process $PROCESS_NAME with PID $PID is listening on port $PORT"
HASH=$(sha256sum /proc/$PID/exe | awk '{print $1}')
API_KEY="YOUR_VIRUS_TOTAL_API_KEY"
RESPONSE=$(curl --request GET --url "https://www.virustotal.com/vtapi/v2/file/report?apikey=$API_KEY&resource=$HASH")
POSITIVE_COUNT=$(echo "$RESPONSE" | jq '.positives')
if [ "$POSITIVE_COUNT" -gt 0 ]; then
  echo "The process is identified as malicious! Blocking permanently."
  iptables -A INPUT -p tcp --dport $PORT -j DROP
  kill -9 $PID
  echo "Process $PROCESS_NAME with PID $PID has been terminated and blocked permanently."
else
  echo "The process is not identified as malicious. No need for blocking."
fi

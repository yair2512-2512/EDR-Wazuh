#!/bin/bash
###block-ip.sh###
IP_TO_BLOCK=$1
ufw deny from $IP_TO_BLOCK
ufw reload
echo "IP $IP_TO_BLOCK has been blocked."
#######################################
###block_user.sh###
username=$1
if [ -z "$username" ]; then
  echo "No username provided."
  exit 1
fi
ips=$(grep "Accepted password for $username" /var/log/auth.log | grep -oP 'from \K[\d\.]+' | sort | uniq)
if [ -z "$ips" ]; then
  echo "No successful connection found for user $username."
  exit 1
fi
echo "The IPs for user $username are:"
echo "$ips"
sudo usermod -L $username
echo "User $username has been locked."
echo "Block $username."
sudo pkill -KILL -u $username
for ip in $ips; do
  sudo iptables -A INPUT -s $ip -j DROP
  echo "IP $ip has been blocked from connecting."
done
########################################
###block_usb.sh###
device=$1
if [ -b "/dev/$device" ]; then
    umount /dev/$device
    echo "USB device $device has been unmounted."
    chmod 000 /dev/$device
    echo "USB device $device has been blocked permanently."
else
    echo "Device $device not found."
fi
########################################
###check_module.sh###
VIRUSTOTAL_API_KEY="YOUR_API_KEY_HERE"
module_path_or_name=$1
function is_file_path {
  if [[ -f "$1" ]]; then
    return 0
  else
    return 1
  fi
}
function scan_file {
  file_path=$1
  response=$(curl -s --request POST \
    --url 'https://www.virustotal.com/vtapi/v2/file/scan' \
    --form apikey="$VIRUSTOTAL_API_KEY" \
    --form file=@"$file_path")

  echo "Scan response: $response"
}
if is_file_path "$module_path_or_name"; then
  echo "Parameter is a file path. Scanning the file..."
  scan_file "$module_path_or_name"
else
  echo "Parameter is a module name. Please provide a valid file path."
fi
#######################################
###block-port.sh###
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
#######################################
###check_ip.sh###
src_ip=$1
dst_ip=$2
api_key="YOUR_API_KEY"
url="https://api.abuseipdb.com/api/v2/check"
recipient="your_email@example.com"
subject="Suspicious IP Activity Detected"
send_email() {
  body="An IP has been reported as suspicious with an abuse confidence score of $1. Please investigate."
  echo "$body" | mail -s "$subject" "$recipient"
}
block_ip() {
  ip=$1
  echo "Blocking IP $ip with ufw."
  sudo ufw deny from $ip
}
check_ip() {
  ip=$1
  response=$(curl -s -X GET "$url?ipAddress=$ip" -H "Key: $api_key" -H "Accept: application/json")
  is_abused=$(echo $response | jq '.data.abuseConfidenceScore')
  if [[ $is_abused -gt 50 ]]; then
    echo "IP $ip is suspicious with a confidence score of $is_abused."
    send_email $is_abused
    block_ip $ip
  else
    echo "IP $ip seems clean with a confidence score of $is_abused."
  fi
}
check_ip $src_ip
check_ip $dst_ip
##################################################
###disable_process.sh###
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
############################################
###memory_cleanup.sh###
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
#################################################
###Free_cleanup.sh###
echo "Cleaning swap memory..."
sync; echo 3 > /proc/sys/vm/drop_caches
swapoff -a && swapon -a
echo "Swap memory has been cleared."
top -b -o +%MEM | head -n 10 | awk '{print $1}' | xargs kill -9
################################################
###suspicious_process_handler.sh###
if [ -z "$1" ]; then
  echo "Please provide a process path as an argument."
  exit 1
fi
PROCESS_PATH="$1"
API_KEY="your_virustotal_api_key"  
PROCESS_NAME=$(basename "$PROCESS_PATH") 
  RESPONSE=$(curl -s -X POST \
    --url "https://www.virustotal.com/api/v3/files" \
    -H "x-apikey: $API_KEY" \
    -F "file=@$PROCESS_PATH")
  MALICIOUS=$(echo $RESPONSE | jq '.data.attributes.last_analysis_stats.malicious')
  if [ "$MALICIOUS" -gt 0 ]; then
    echo "Malicious process detected. Taking action..."
    PID=$(ps aux | grep "$PROCESS_NAME" | grep -v "grep" | awk '{print $2}')
    if [ -n "$PID" ]; then
      kill -9 $PID
      echo "Process with PID $PID has been killed."
    else
      echo "Process with name $PROCESS_NAME not found."
    fi
  else
    echo "The process is clean."
  fi
else
  echo "The process is not in a suspicious location."
fi
#####################################################
###port-script.sh###
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
#################################################
###domain_script.sh###
API_KEY="your_virustotal_api_key"
if [ -z "$1" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi
DOMAIN="$1"
response=$(curl -s -X GET \
  "https://www.virustotal.com/api/v3/domains/$DOMAIN" \
  -H "x-apikey: $API_KEY")
malicious=$(echo "$response" | jq '.data.attributes.last_analysis_stats.malicious')
if [ "$malicious" -gt 0 ]; then
    echo "Domain $DOMAIN is malicious! Blocking it..."
    echo "127.0.0.1 $DOMAIN" | sudo tee -a /etc/hosts > /dev/null
    sudo iptables -A OUTPUT -d "$DOMAIN" -j REJECT
    echo "Domain $DOMAIN has been blocked successfully."
else
    echo "Domain $DOMAIN is safe. No action needed."
fi
############################################









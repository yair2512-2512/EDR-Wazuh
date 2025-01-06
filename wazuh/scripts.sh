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
########################################

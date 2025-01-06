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





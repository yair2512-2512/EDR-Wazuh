#!/bin/bash
###block-ip.sh###
IP_TO_BLOCK=$1
ufw deny from $IP_TO_BLOCK
ufw reload
echo "IP $IP_TO_BLOCK has been blocked."
#######################################
###block_user.sh
username=$1
if [ -z "$username" ]; then
  echo "user not found."
  exit 1
fi
sudo usermod -L $username
echo "block $username ."
sudo pkill -KILL -u $username


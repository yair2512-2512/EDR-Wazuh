#!/bin/bash
IP_TO_BLOCK=$1
ufw deny from $IP_TO_BLOCK
ufw reload
echo "IP $IP_TO_BLOCK has been blocked."
###block-ip.sh###



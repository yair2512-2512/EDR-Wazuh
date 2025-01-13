#!/bin/bash
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

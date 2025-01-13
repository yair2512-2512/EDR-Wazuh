#!/bin/bash
# This script scans a file using the VirusTotal API, blocks it if malicious, and deletes it.
API_KEY="your_virustotal_api_key"
FILE_PATH="$1"  
if [ ! -f "$FILE_PATH" ]; then
  echo "File does not exist: $FILE_PATH"
  exit 1
fi
echo "Sending the file to VirusTotal for scanning..."
response=$(curl -s --request POST \
  --url "https://www.virustotal.com/api/v3/files/$(base64 <<< "$FILE_PATH")" \
  --header "x-apikey: $API_KEY")
if [ $? -ne 0 ]; then
  echo "Error receiving response from VirusTotal"
  exit 1
fi
is_malicious=$(echo "$response" | jq -r '.data.attributes.last_analysis_stats.malicious')
if [ "$is_malicious" -gt 0 ]; then
  echo "The file is malicious. Performing action..."
  chmod 000 "$FILE_PATH"
  echo "The file is blocked. Access to it has been denied."
  rm -f "$FILE_PATH"
  echo "The file has been deleted."
  /path/to/isolate_station.sh "$FILE_PATH"
else
  echo "The file is clean according to VirusTotal."
fi

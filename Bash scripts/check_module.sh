#!/bin/bash
# This script scans a file using VirusTotal API if the provided parameter is a file path.
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

#!/bin/bash
# This script restores a deleted file from the backup directory.
BACKUP_DIR="/path/to/backup"
if [ -z "$1" ]; then
  echo "You must specify the name of the deleted file."
  exit 1
fi
DELETED_FILE="$1"
BACKUP_FILE="$BACKUP_DIR/$(basename "$DELETED_FILE")*"
if [ ! -e "$BACKUP_FILE" ]; then
  echo "No backup found for the file $DELETED_FILE"
  exit 1
fi
echo "Restoring the file $DELETED_FILE from backup..."
cp "$BACKUP_FILE" "$(dirname "$DELETED_FILE")"
if [ $? -eq 0 ]; then
  echo "The file has been restored successfully."
else
  echo "Error restoring the file."
  exit 1
fi


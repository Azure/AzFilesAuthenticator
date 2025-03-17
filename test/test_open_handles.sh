#!/bin/bash

# Function to print "BYE" on exit
function on_exit {
    echo "BYE"
}

# Set the trap to call on_exit function on script exit
trap on_exit EXIT

# parse the fileshare path from argument
fileshare_path=$1
file_descriptor=$2

if [ -z "$fileshare_path" ] || [ -z "$file_descriptor" ]; then
    echo "[$file_descriptor] Usage: $0 <fileshare_path> <file_descriptor>"
    exit 1
fi

if [ ! -d "$fileshare_path" ]; then
    echo "[$file_descriptor] Fileshare path does not exist: $fileshare_path"
    exit 1
fi

output_file="$fileshare_path/ritvik/random_file_$file_descriptor"

start_time=$(date +%s)
current_utc_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "[$file_descriptor] Start UTC time: $current_utc_time"
sudo dd if=/dev/urandom of="$output_file" bs=1024 count=10000000
end_time=$(date +%s)
current_utc_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "[$file_descriptor] End UTC time: $current_utc_time"

total_time=$((end_time - start_time))
echo "[$file_descriptor] Total time taken: $total_time seconds"
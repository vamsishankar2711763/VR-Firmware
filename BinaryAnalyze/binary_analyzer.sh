#!/usr/bin/env bash
set -euo pipefail
# Set PATHS
checksec_bin=" "
root_dir=" " 

for firmware_folder in "$root_dir"/q1_v*; do
    [[ -d "$firmware_folder" ]] || continue
    firmware_name=$(basename "$firmware_folder")
    binary_folder="$firmware_folder/binary"

    if [[ ! -d "$binary_folder" ]]; then
        echo "Skipping $firmware_name - No binary folder found."
        continue
    fi

    # Output CSV file inside binary folder
    output_file="${binary_folder}/${firmware_name}_checksec_report.csv"

    # Ensure a fresh CSV file
    > "$output_file"

    # Recursively process all files while excluding CSV reports
    while IFS= read -r -d '' file; do
        [[ "$file" == *.csv ]] && continue  # Skip CSV files

        echo "Processing: $file"

        # Run checksec, and if it fails, log an error and continue
        if ! checksec_output="$("$checksec_bin" --file="$file" --extended --format=csv 2>/dev/null)"; then
            echo "$file,ERROR_PROCESSING" >> "$output_file"
            echo "Error processing: $file"
            continue
        fi

        # Append checksec output to the CSV
        while IFS= read -r line; do
            echo "$file,$line"
        done <<< "$checksec_output" >> "$output_file"

    done < <(find "$binary_folder" -type f ! -name "*.csv" -print0)

    echo "CSV report saved: $output_file"
done

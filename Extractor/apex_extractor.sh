#!/bin/bash

# Base directory containing all firmware folders
BASE_DIR=" "
MOUNT_POINT=" "

# Check if the base directory exists
if [[ ! -d "$BASE_DIR" ]]; then
    echo ">>> ERROR: Base directory $BASE_DIR does not exist!"
    exit 1
fi

# Create the mount point if it doesn't exist
mkdir -p "$MOUNT_POINT"

# Function to extract files
extract_files() {
    local file="$1"
    local output_dir="${file%.*}a"  # Append 'a' to extracted folder name

    echo ">> Found compressed file: $file"
    echo ">> Creating extraction directory: $output_dir"
    mkdir -p "$output_dir"

    echo ">> Extracting: $file to $output_dir"
    if [[ "$file" == *.apex || "$file" == *.capex ]]; then
        unzip -o "$file" -d "$output_dir" && echo ">> Successfully extracted $file"
    else
        unzip -o "$file" -d "$output_dir" || tar -xf "$file" -C "$output_dir"
    fi

    echo ">> Checking for nested compressed files in: $output_dir"
    for nested_file in "$output_dir"/*; do
        if [[ "$nested_file" == *.zip || "$nested_file" == *.jar || "$nested_file" == *.apex || "$nested_file" == *.capex ]]; then
            echo ">>> Found nested compressed file: $nested_file"
            extract_files "$nested_file"
        fi
    done

    if [[ -f "$output_dir/apex_payload.img" ]]; then
        echo ">>> Found apex_payload.img inside $output_dir"
        process_img_files "$output_dir"
    fi

    echo ">> Finished extracting: $file"
}

# Function to process .img files and copy contents
process_img_files() {
    local search_dir="$1"

    echo ">> Searching for .img files in: $search_dir"
    for img_file in "$search_dir"/*.img; do
        if [[ -f "$img_file" ]]; then
            echo ">>> Found .img file: $img_file"
            echo ">>> Mounting $img_file at $MOUNT_POINT"
            
            mount -ro loop "$img_file" "$MOUNT_POINT" && echo ">>> Mounted $img_file successfully"
            
            target_dir="$(dirname "$img_file")"
            chmod -R u+w "$target_dir"
            
            echo ">>> Copying all files from mount point to $target_dir/"
            cp -aT "$MOUNT_POINT" "$target_dir" && echo ">>> Successfully copied all files from $img_file"
            
            echo ">>> Verifying copied files..."
            ls -lah "$target_dir" && echo ">>> Files copied successfully."
            
            echo ">>> Unmounting $img_file"
            umount "$MOUNT_POINT" && echo ">>> Successfully unmounted $img_file"
        fi
    done
}

# Function to process directories recursively
process_directory() {
    local dir="$1"
    echo ">> Entering directory: $dir"

    for item in "$dir"/*; do
        if [[ -f "$item" ]]; then
            filename=$(basename "$item")
            if [[ "$filename" == *.zip || "$filename" == *.jar || "$filename" == *.apex || "$filename" == *.capex ]]; then
                echo ">> Compressed file found: $filename"
                extract_files "$item"
            else
                echo ">> Skipping non-compressed file: $filename"
            fi
        elif [[ -d "$item" ]]; then
            echo ">> Entering subdirectory: $item"
            process_directory "$item"
        fi
    done

    process_img_files "$dir"
}

# Process all firmware folders under BASE_DIR
for firmware_dir in "$BASE_DIR"/*; do
    if [[ -d "$firmware_dir" ]]; then
        echo "===== Processing Firmware Directory: $firmware_dir ====="
        APEX_DIR="$firmware_dir/binary/binary_system/apex"
        if [[ -d "$APEX_DIR" ]]; then
            echo ">> Found 'apex' directory: $APEX_DIR"
            process_directory "$APEX_DIR"
        else
            echo ">> ERROR: No 'apex' directory found in $firmware_dir"
        fi
    fi
    echo "===== Firmware Processing Complete for: $firmware_dir ====="
done

#!/bin/bash

# Base directory containing the folders
base_dir=" "
tool_path=" "

# Check if the tool exists
if [ ! -f "$tool_path" ]; then
    echo "Tool $tool_path not found. Exiting."
    exit 1
fi

# Loop through each folder in the base directory
for folder in "$base_dir"/*; do
    # Check if it's a directory
    if [ -d "$folder" ]; then
        # Check if boot.img exists in the folder
        boot_img="$folder/boot.img"
        if [ -f "$boot_img" ]; then
            echo "Processing $boot_img..."
            # Run the tool on the boot.img file
            "$tool_path" "$boot_img" extract
            if [ $? -ne 0 ]; then
                echo "Error processing $boot_img"
            else
                echo "Successfully processed $boot_img"

                # Move the extracted folder to the current folder
                extracted_folder=" " # Set PATH
                if [ -d "$extracted_folder" ]; then
                    mv "$extracted_folder" "$folder/"
                    if [ $? -eq 0 ]; then
                        echo "Moved extracted folder to $folder"
                    else
                        echo "Failed to move extracted folder to $folder"
                    fi
                else
                    echo "No extracted folder found. Skipping move."
                fi
            fi
        else
            echo "No boot.img found in $folder. Skipping."
        fi
    fi
done

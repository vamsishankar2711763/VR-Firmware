# Base directory containing the folders
# Set PATHS
base_dir=" "
kernel_config_script=" "

# Loop through each folder in the base directory
for folder in "$base_dir"/*; do
    # Check if it's a directory
    if [ -d "$folder" ]; then
        # Extract the folder name
        folder_name=$(basename "$folder")

        # Define the path to the 'extracted/kernel' file
        kernel_file="$folder/extracted/kernel"

        # Check if the 'kernel' file exists
        if [ -f "$kernel_file" ]; then
            # Define the output file path in the extracted folder
            output_file="$folder/extracted/${folder_name}_configuration"

            # Execute the kernel_config.sh script and redirect output
            "$kernel_config_script" "$kernel_file" > "$output_file"

            echo "Processed kernel in $folder. Output saved to $output_file."
        else
            echo "No 'kernel' file found in $folder/extracted. Skipping."
        fi
    fi
done

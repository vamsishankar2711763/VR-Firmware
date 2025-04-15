#!/bin/bash

# Base directory containing all the firmware folders
BASE_DIR=" "

# Function to extract binaries from APK files
extract_apk_binaries() {
    local firmware_dir="$1"
    local apps_dir="${firmware_dir}/apps"
    local output_dir="${firmware_dir}/apps_binaries"
    
    echo "Processing firmware: $firmware_dir"
    
    # Check if apps directory exists
    if [ ! -d "$apps_dir" ]; then
        echo "  Apps directory not found: $apps_dir"
        return
    fi
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    echo "  Created output directory: $output_dir"
    
    # Find all APK files in the apps directory
    find "$apps_dir" -name "*.apk" | while read apk_file; do
        apk_name=$(basename "$apk_file" .apk)
        app_output_dir="${output_dir}/${apk_name}"
        
        echo "  Processing APK: $apk_name"
        
        # Create directory for this APK
        mkdir -p "$app_output_dir"
        
        # Create a temporary directory for extraction
        temp_dir=$(mktemp -d)
        
        # Extract the APK (which is essentially a ZIP file)
        echo "  Extracting APK to temporary directory..."
        unzip -q "$apk_file" -d "$temp_dir" || {
            echo "  Failed to extract APK: $apk_file"
            rm -rf "$temp_dir"
            continue
        }
        
        # Find and copy all binary files from the extracted APK
        echo "  Searching for binaries in the APK..."
        
        # Look for .so files (native libraries)
        find "$temp_dir" -name "*.so" | while read so_file; do
            rel_path=${so_file#$temp_dir/}
            target_dir=$(dirname "${app_output_dir}/${rel_path}")
            
            mkdir -p "$target_dir"
            cp "$so_file" "${app_output_dir}/${rel_path}"
            echo "    Copied library: ${rel_path}"
        done
        
        # Look for binaries in lib directory
        if [ -d "$temp_dir/lib" ]; then
            echo "    Found lib directory, copying all contents..."
            mkdir -p "$app_output_dir/lib"
            cp -r "$temp_dir/lib"/* "$app_output_dir/lib"/ 2>/dev/null || echo "    No files in lib directory"
        fi
        
        # Look for dex files (compiled Android bytecode)
        find "$temp_dir" -name "*.dex" | while read dex_file; do
            rel_path=${dex_file#$temp_dir/}
            target_dir=$(dirname "${app_output_dir}/${rel_path}")
            
            mkdir -p "$target_dir"
            cp "$dex_file" "${app_output_dir}/${rel_path}"
            echo "    Copied DEX file: ${rel_path}"
        done
        
        # Check for specialized directories that might contain binaries
        special_dirs=("assets" "bin" "jni")
        for dir in "${special_dirs[@]}"; do
            if [ -d "$temp_dir/$dir" ]; then
                echo "    Found $dir directory, checking for binaries..."
                find "$temp_dir/$dir" -type f -exec file {} \; | grep -E 'ELF|executable|shared object' | cut -d: -f1 | while read bin_file; do
                    rel_path=${bin_file#$temp_dir/}
                    target_dir=$(dirname "${app_output_dir}/${rel_path}")
                    
                    mkdir -p "$target_dir"
                    cp "$bin_file" "${app_output_dir}/${rel_path}"
                    echo "    Copied binary from $dir: ${rel_path}"
                done
            fi
        done
        
        # Copy AndroidManifest.xml for reference
        if [ -f "$temp_dir/AndroidManifest.xml" ]; then
            cp "$temp_dir/AndroidManifest.xml" "$app_output_dir/"
            echo "    Copied AndroidManifest.xml"
        fi
        
        # Check if any binaries were extracted
        bin_count=$(find "$app_output_dir" -type f | wc -l)
        if [ $bin_count -eq 0 ]; then
            echo "    No binaries found in APK. Copying all files as fallback."
            cp -r "$temp_dir"/* "$app_output_dir"/ 2>/dev/null || echo "    No files to copy"
            bin_count=$(find "$app_output_dir" -type f | wc -l)
            echo "    Copied $bin_count files as fallback"
        else
            echo "    Extracted $bin_count binary files"
        fi
        
        # Clean up temporary directory
        rm -rf "$temp_dir"
    done
    
    # Count total APKs processed
    apk_count=$(find "$apps_dir" -name "*.apk" | wc -l)
    echo "  Processed $apk_count APK files in $firmware_dir"
}

# Main function
main() {
    echo "Starting APK binary extraction..."
    
    # Find all firmware directories
    find "$BASE_DIR" -maxdepth 1 -type d -name "q*_v*" | sort | while read firmware_dir; do
        extract_apk_binaries "$firmware_dir"
        echo "----------------------------------------"
    done
    
    echo "APK binary extraction complete!"
    
    # Print summary
    total_apks=$(find "$BASE_DIR" -name "*.apk" | wc -l)
    total_extracted_dirs=$(find "$BASE_DIR" -path "*/apps_binaries/*" -type d | wc -l)
    total_extracted_files=$(find "$BASE_DIR" -path "*/apps_binaries/*" -type f | wc -l)
    
    echo "Final Summary:"
    echo "  Total APK files found: $total_apks"
    echo "  Total app directories created: $total_extracted_dirs"
    echo "  Total binary files extracted: $total_extracted_files"
}

# Run the main function
main

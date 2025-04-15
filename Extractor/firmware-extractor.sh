#!/bin/bash

# === Set Paths ===
BASE_DIR=""
SDAT2IMG=""
EXTRACTOR=""
MOUNT_BASE=""

# Check required tools
[[ -f "$SDAT2IMG" ]] || { echo "Missing: $SDAT2IMG"; exit 1; }
[[ -x "$EXTRACTOR" ]] || { echo "Missing or not executable: $EXTRACTOR"; exit 1; }

# === Step 1: Unzip all firmware ZIPs ===
for ZIP_FILE in "$BASE_DIR"/*.zip; do
    ZIP_NAME=$(basename "$ZIP_FILE" .zip)
    EXTRACT_DIR="$BASE_DIR/$ZIP_NAME"

    echo "Unzipping $ZIP_FILE → $EXTRACT_DIR"
    unzip -q "$ZIP_FILE" -d "$EXTRACT_DIR" || continue
done

# === Step 2: Process each extracted folder ===
for FOLDER in "$BASE_DIR"/*; do
    [[ -d "$FOLDER" ]] || continue
    echo "Processing $FOLDER"

    cd "$FOLDER" || continue

    # --- Step 2.1: Extract payload.bin using OTA extractor ---
    if [[ -f "payload.bin" ]]; then
        echo "Extracting payload.bin using ota-extractor"
        "$EXTRACTOR" "payload.bin"
    fi

    # --- Step 2.2: Convert .dat.br to .img if needed ---
    PARTITIONS=("system" "vendor" "product" "odm")
    for PART in "${PARTITIONS[@]}"; do
        BR_FILE="${PART}.new.dat.br"
        DAT_FILE="${PART}.new.dat"
        TRANSFER_LIST="${PART}.transfer.list"
        IMG_FILE="${PART}.img"

        if [[ -f "$BR_FILE" ]]; then
            echo "Decompressing $BR_FILE"
            brotli --decompress --output="$DAT_FILE" "$BR_FILE"
        fi

        if [[ -f "$DAT_FILE" && -f "$TRANSFER_LIST" ]]; then
            echo "Generating $IMG_FILE"
            python3 "$SDAT2IMG" "$TRANSFER_LIST" "$DAT_FILE" "$IMG_FILE"
        fi
    done

    # === Step 3: Mount and extract APKs ===
    IMG_FILES=("system.img" "vendor.img" "product.img" "odm.img" "vendor_dlkm.img" "odm_dlkm.img" "system_ext.img")
    APPS_DIR="$FOLDER/apps"
    mkdir -p "$APPS_DIR"

    for i in "${!IMG_FILES[@]}"; do
        IMG="${IMG_FILES[$i]}"
        MOUNT_POINT="$MOUNT_BASE/point$((i+1))"
        mkdir -p "$MOUNT_POINT"

        if [[ -f "$FOLDER/$IMG" ]]; then
            echo "Mounting $IMG → $MOUNT_POINT"
            sudo mount -o ro,loop "$FOLDER/$IMG" "$MOUNT_POINT" || continue

            echo "Searching for APKs in $IMG"
            APK_LIST=$(sudo find "$MOUNT_POINT" -type f -name "*.apk")
            for APK_PATH in $APK_LIST; do
                sudo cp "$APK_PATH" "$APPS_DIR/"
                echo "Copied: $APK_PATH"
            done

            echo "Unmounting $MOUNT_POINT"
            sudo umount "$MOUNT_POINT"
        else
            echo "$IMG not found in $FOLDER"
        fi
    done

    # === Fix Permissions ===
    sudo chmod 777 "$APPS_DIR"/* 2>/dev/null
    echo "Finished APK extraction for $FOLDER"

done

echo "All firmware packages processed and APKs extracted."

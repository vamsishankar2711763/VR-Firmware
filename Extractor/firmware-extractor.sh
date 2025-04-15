#!/bin/bash

# === Paths ===
BASE_DIR=" " #Set where all the firmware locations are
SDAT2IMG=" " #sdat2img.py script location
EXTRACTOR=" " # payload.bin extractor

# Check for sdat2img.py
if [[ ! -f "$SDAT2IMG" ]]; then
    echo "Error: sdat2img.py not found at $SDAT2IMG"
    exit 1
fi

# Check for ota-extractor
if [[ ! -x "$EXTRACTOR" ]]; then
    echo "Error: ota-extractor not found or not executable at $EXTRACTOR"
    exit 1
fi

cd "$BASE_DIR" || exit

# === Step 1: Unzip all firmware ZIPs ===
for ZIP_FILE in "$BASE_DIR"/*.zip; do
    ZIP_NAME=$(basename "$ZIP_FILE" .zip)
    EXTRACT_DIR="$BASE_DIR/$ZIP_NAME"

    echo "Unzipping $ZIP_FILE to $EXTRACT_DIR"
    unzip -q "$ZIP_FILE" -d "$EXTRACT_DIR" || continue
done

# === Step 2: Process each extracted folder ===
for FOLDER in "$BASE_DIR"/*; do
    [[ -d "$FOLDER" ]] || continue
    echo "Entering $FOLDER"

    cd "$FOLDER" || continue

    # Step 2.1: If payload.bin is present, extract using android-ota-extractor
    if [[ -f "payload.bin" ]]; then
        echo "Running OTA extractor on payload.bin"
        "$EXTRACTOR" "payload.bin"
        echo "Extraction from payload.bin completed"
    fi

    # Step 2.2: Handle .dat.br + transfer.list → .img conversion
    PARTITIONS=("system" "vendor" "product" "odm")
    for PART in "${PARTITIONS[@]}"; do
        BR_FILE="${PART}.new.dat.br"
        DAT_FILE="${PART}.new.dat"
        TRANSFER_LIST="${PART}.transfer.list"
        IMG_FILE="${PART}.img"

        if [[ -f "$BR_FILE" ]]; then
            echo "Decompressing $BR_FILE → $DAT_FILE"
            brotli --decompress --output="$DAT_FILE" "$BR_FILE"
        fi

        if [[ -f "$DAT_FILE" && -f "$TRANSFER_LIST" ]]; then
            echo "Generating $IMG_FILE from $DAT_FILE and $TRANSFER_LIST"
            python3 "$SDAT2IMG" "$TRANSFER_LIST" "$DAT_FILE" "$IMG_FILE"
        else
            echo "Missing files for $PART, skipping IMG generation"
        fi
    done

    echo "Finished processing $FOLDER"
done

echo "All firmware packages processed successfully."

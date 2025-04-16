## Firmware Analysis Toolkit

This repository contains scripts and utilities designed to automate firmware extraction and binary collection for Oculus and Pico devices.

### Components

#### Scraper
- **Purpose**: Scrapes firmware files directly from the Oculus firmware hosting site.
- **Note**: For Pico firmwares, binaries have been manually collected and are not scraped.

####  Extractor Scripts

- **`firmware-extractor.sh`**
  - **Purpose**: Extracts `.img` partitions and APK files from zipped firmware packages.
  - **Also extracts**: App APKs bundled with the firmware.

- **`binary-extractor.sh`**
  - **Purpose**: Extracts ELF binaries from the raw `.img` partition files.

- **`apex-extractor.sh`**
  - **Purpose**: Extracts binaries from `.apex` files located within the partition images.
    
- **`binaries_extractor_from_apk.sh`**
  - **Purpose**: Extracts native binaries (e.g., `.so` files) from APK files.
---

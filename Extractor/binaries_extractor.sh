import os
import subprocess

# Define the base directory and the mount base path
firmware_dir = " "
mount_base = " "

# Function to check and unmount if already mounted
def unmount_if_mounted(mount_point):
    try:
        result = subprocess.run(["mountpoint", "-q", mount_point])
        if result.returncode == 0:  # Mount point is in use
            subprocess.run(["sudo", "umount", mount_point], check=True)
            print(f"Unmounted {mount_point}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to unmount {mount_point}: {e}")

# Helper function to detect file system type using blkid
def detect_filesystem(image_file):
    try:
        result = subprocess.run(["blkid", "-o", "value", "-s", "TYPE", image_file], capture_output=True, text=True, check=True)
        fs_type = result.stdout.strip()

        # Handle ext2 and ext4 as the same
        if fs_type in ["ext4", "ext2"]:
            return "ext4"  # ext4 driver can mount both
        elif fs_type == "squashfs":
            return "squashfs"
        elif fs_type in ["vfat", "fat"]:
            return "vfat"
        else:
            print(f"Unsupported filesystem detected in {image_file}: {fs_type}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"Failed to detect filesystem for {image_file}: {e}")
        return None

# Function to process an image file, mount it, and copy only selected folders
def process_image(image_type, folder):
    firmware_path = os.path.join(firmware_dir, folder)
    image_file = os.path.join(firmware_path, f"{image_type}.img")
    mount_point = mount_base
    binary_folder = os.path.join(firmware_path, "binary")
    binary_subfolder = os.path.join(binary_folder, f"binary_{image_type}")

    # Define the folders to copy based on the image type
    if image_type == "system":
        folders_to_copy = {
            "/system/bin": "bin",
            "/system/lib": "lib",
            "/system/lib64": "lib64",
            "/system/vendor/bin": "vendor_bin",
            "/system/vendor/lib": "vendor_lib",
            "/system/vendor/lib64": "vendor_lib64",
            "/system/apex": "apex"
        }
    else:  # vendor or odm
        folders_to_copy = {
            "/bin": "bin",
            "/lib": "lib",
            "/lib64": "lib64"
        }

    # Check if the image file exists
    if not os.path.exists(image_file):
        print(f"{image_type}.img not found in {folder}. Skipping...")
        return

    # Detect file system type
    fs_type = detect_filesystem(image_file)
    if not fs_type:
        print(f"Cannot process {image_file} due to unsupported or undetected file system.")
        return

    # Unmount if already mounted
    unmount_if_mounted(mount_point)

    # Mount the image file
    try:
        subprocess.run(["sudo", "mount", "-ro", "loop", "-t", fs_type, image_file, mount_point], check=True)
        print(f"Mounted {image_file} to {mount_point} with file system {fs_type}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to mount {image_file}: {e}")
        return

    # Create the binary and binary_subfolder directories if they do not exist
    os.makedirs(binary_subfolder, exist_ok=True)

    # Copy only the specified folders
    for src_folder, dest_folder_name in folders_to_copy.items():
        source_folder = os.path.join(mount_point, src_folder.lstrip("/"))  # Remove leading /
        dest_folder = os.path.join(binary_subfolder, dest_folder_name)  # Keep vendor files separate

        if os.path.exists(source_folder):
            os.makedirs(dest_folder, exist_ok=True)  # Ensure the destination exists

            # Debugging + Copy files using 'cp -a'
            for root, _, files in os.walk(source_folder):
                for file in files:
                    src_file = os.path.join(root, file)
                    rel_path = os.path.relpath(src_file, source_folder)
                    dest_file = os.path.join(dest_folder, rel_path)

                    # Ensure the destination directory exists before copying
                    dest_parent = os.path.dirname(dest_file)
                    os.makedirs(dest_parent, exist_ok=True)  # Create parent directories if missing

                    # Debugging output
                    if not os.path.exists(src_file):
                        print(f"ERROR: Source file missing -> {src_file}")
                    elif not os.access(src_file, os.R_OK):
                        print(f"ERROR: No read permission -> {src_file}")
                    else:
                        try:
                            subprocess.run(["cp", "-a", src_file, dest_file], check=True)
                            print(f"Copied: {src_file} -> {dest_file}")
                        except subprocess.CalledProcessError:
                            print(f"Warning: Failed to copy {src_file}")

            print(f"Copied {source_folder} to {dest_folder}")
        else:
            print(f"Skipping missing folder: {source_folder}")

    # Unmount the image file
    try:
        subprocess.run(["sudo", "umount", mount_point], check=True)
        print(f"Unmounted {mount_point}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to unmount {mount_point}: {e}")

# Process all firmware folders for system, vendor, and odm images
for folder in os.listdir(firmware_dir):
    folder_path = os.path.join(firmware_dir, folder)
    if os.path.isdir(folder_path):
        process_image("system", folder)
        process_image("vendor", folder)
        process_image("odm", folder)


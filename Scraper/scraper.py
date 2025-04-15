import os
import requests
from bs4 import BeautifulSoup

# URL of the page to scrape
BASE_URL = "https://cocaine.trade/Quest_2_firmware"

# Directory to save the downloaded firmware files
DOWNLOAD_DIR = "firmwares"

# Create the download directory if it doesn't exist
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def get_firmware_links(url):
    """
    Parses the webpage to find firmware download links.
    """
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Failed to fetch the webpage. Status code: {response.status_code}")
        return []

    soup = BeautifulSoup(response.content, "html.parser")
    
    # Find all links on the page
    links = soup.find_all("a")
    
    # Filter links to get only firmware files (assuming they end with .zip or similar)
    firmware_links = [link["href"] for link in links if link.get("href") and link["href"].startswith("http")]
    return firmware_links

def download_file(url, save_dir):
    """
    Downloads a file from the given URL and saves it in the specified directory.
    """
    local_filename = os.path.join(save_dir, url.split("/")[-1])
    print(f"Downloading {url}...")
    
    with requests.get(url, stream=True) as response:
        if response.status_code == 200:
            with open(local_filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Saved: {local_filename}")
        else:
            print(f"Failed to download {url}. Status code: {response.status_code}")

def main():
    # Step 1: Get all firmware links
    firmware_links = get_firmware_links(BASE_URL)
    if not firmware_links:
        print("No firmware links found!")
        return

    print(f"Found {len(firmware_links)} firmware links.")

    # Step 2: Download each firmware file
    for link in firmware_links:
        download_file(link, DOWNLOAD_DIR)

if __name__ == "__main__":
    main()


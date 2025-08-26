import requests
import json
import os
import sys

# Elasticsearch settings
base_url = "https://yourbaseurl.com"
headers = {"Content-Type": "application/json"}
chunk_size = 10000  # Fetch all results in one go (up to 10,000)

# Path to the JSON file where the URLs are stored
json_file_path = "urls.json"

def fetch_data(search_string):
    """Fetch the first 10000 entries using the search string"""
    url = f"{base_url}/elastic/links/_search"
    print(f"Fetching data with search string: '{search_string}'")

    response = requests.get(
        url,
        headers=headers,
        params={
            "size": chunk_size,
            "_source": "url",
            "q": search_string,
            "sort": "_id:asc"
        }
    )

    if response.status_code == 200:
        try:
            data = response.json()
            print(f"Fetched {len(data['hits']['hits'])} records.")
            return data
        except requests.exceptions.JSONDecodeError:
            print("Failed to decode JSON response. Stopping fetching...")
            print(response.text)
            return None
    else:
        print(f"Failed to fetch data. Status code: {response.status_code}")
        print(response.text)
        return None

def load_existing_data():
    """Load existing data from the JSON file, if it exists"""
    if os.path.exists(json_file_path):
        with open(json_file_path, "r") as f:
            return set(json.load(f))
    else:
        return set()

def save_data(data):
    """Save the data to the JSON file"""
    with open(json_file_path, "w") as f:
        json.dump(list(data), f)

def main(search_string):
    """Main function to fetch and save data"""
    # Load existing URLs to avoid duplicates
    existing_data = load_existing_data()

    # Fetch data
    data = fetch_data(search_string)

    if data is None:
        print("No data fetched. Exiting...")
        return

    hits = data.get("hits", {}).get("hits", [])

    if not hits:
        print(f"No records found for search string '{search_string}'.")
    else:
        new_urls = set(hit["_source"]["url"] for hit in hits)
        existing_data.update(new_urls)

        # Save the updated list of URLs
        save_data(existing_data)

        print(f"Total unique URLs saved: {len(existing_data)}")

if __name__ == "__main__":
    # Get search string from command line argument or prompt the user
    if len(sys.argv) > 1:
        search_string = sys.argv[1]
    else:
        search_string = input("Enter the search string: ")

    main(search_string)

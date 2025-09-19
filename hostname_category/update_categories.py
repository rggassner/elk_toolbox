update_categories.py 
#!/usr/bin/env python3
import os
import gzip
import json

REPO_DIR = "/opt/categorization/ut1-blacklists"
BASE_DIR = os.path.join(REPO_DIR, "blacklists")
OUTPUT = "/etc/logstash/dictionaries/category/category.json"

# Categories you don’t want to include
IGNORE_CATEGORIES = {
    "shopping",
    "liste_bu",
    "publicite",
    "ai",
    "exceptions_liste_bu",
    "mobile-phone",
    "examen_pix",
    "webmail",
    "press",
    "liste_blanche",
    "update",
    "cleaning",
    "chat",
    "radio",
    "translation",
    "audio-video",
    "forums",
    "bank",
    "sports",
    "filehosting",
    "download",
    "webhosting",
    "tricheur_pix",
    "blog",
    "financial",
    "celebrity",
    "marketingware",
    "jobsearch",
    "social_networks",
    "tricheur",
    "fakenews",
    "dialer",
}

domains_map = {}

# Walk through blacklists
for root, dirs, files in os.walk(BASE_DIR):
    category = os.path.basename(root)

    # Skip ignored categories
    if category in IGNORE_CATEGORIES:
        continue

    for fname in files:
        if not fname.startswith("domains"):
            continue
        path = os.path.join(root, fname)

        # Open plain or gz
        if fname.endswith(".gz"):
            opener = gzip.open
            mode = "rt"
        else:
            opener = open
            mode = "r"

        with opener(path, mode, encoding="utf-8", errors="ignore") as f:
            for line in f:
                domain = line.strip()
                if not domain or domain.startswith("#"):
                    continue
                # Keep first category seen
                if domain not in domains_map:
                    domains_map[domain] = category

# Ensure output dir exists
os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

# Write JSON
with open(OUTPUT, "w", encoding="utf-8") as out:
    json.dump(domains_map, out, indent=2, sort_keys=True)

print(f"JSON written to {OUTPUT}, {len(domains_map)} domains total.")


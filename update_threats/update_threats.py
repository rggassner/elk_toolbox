#!/usr/bin/python3
import requests
import re
import zipfile
import csv
import unicodedata

# Define URL and local file path
url = "https://threatfox.abuse.ch/downloads/hostfile/"
zipurl = "https://threatfox.abuse.ch/export/csv/domains/full/"
local_zip_path = "/opt/threats/threatfox.zip"

# Pattern for matching lines
pattern = re.compile(r"127\.0\.0\.1\s+(.*)")


# --- CLEANING FUNCTION ---
def clean_string(value):
    if not value:
        return ""

    # Normalize unicode to NFC (canonical form)
    value = unicodedata.normalize("NFC", value)

    # Remove control characters (including special ones like \u009D)
    value = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', value)

    # Replace common misencoded characters (such as 'ã©' -> 'é')
    value = value.replace('ã©', 'é').replace('ã‚', 'é').replace('é', 'é')

    # Remove surrounding spaces
    value = value.strip()

    return value


# --- YAML SAFE WRITER ---
def write_yaml_line(file, key, value, quote_value=True):
    key = clean_string(key).replace('"', '\\"')
    value = clean_string(value).replace('"', '\\"')

    if quote_value:
        file.write(f'"{key}": "{value}"\n')
    else:
        file.write(f'"{key}": {value}\n')


# --- FETCH HOSTFILE ---
try:
    with open("/etc/logstash/dictionaries/threats/threats.yml", "w", encoding="utf-8") as f:
        response = requests.get(url)
        response.raise_for_status()

        for raw_line in response.iter_lines():
            line = raw_line.decode("utf-8", errors="ignore")

            match = pattern.match(line)
            if match:
                domain_name = clean_string(match.group(1))
                if domain_name:
                    write_yaml_line(f, domain_name, "YES")

except requests.exceptions.RequestException as e:
    print(f"Error fetching the URL: {e}")


# --- DOWNLOAD ZIP ---
try:
    response = requests.get(zipurl)
    response.raise_for_status()

    with open(local_zip_path, 'wb') as file:
        file.write(response.content)

except requests.exceptions.RequestException as e:
    print(f"Error fetching the URL: {e}")
    exit()


# --- EXTRACT ZIP ---
extract_path = "output"

try:
    with zipfile.ZipFile(local_zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

except zipfile.BadZipFile as e:
    print(f"Error uncompressing the file: {e}")
    exit()


# --- CSV PROCESSING ---
def preprocess_line(line):
    return line.replace(", ", ",")


csv_file_path = 'output/full_domains.csv'

with open(csv_file_path, mode='r', encoding='utf-8', errors='ignore') as csv_file:
    preprocessed_lines = [preprocess_line(line) for line in csv_file]

    csv_reader = csv.reader(preprocessed_lines, delimiter=',', quotechar='"')

    with open("/etc/logstash/dictionaries/threats/malware.yml", "w", encoding="utf-8") as m, \
         open("/etc/logstash/dictionaries/threats/threat_type.yml", "w", encoding="utf-8") as t, \
         open("/etc/logstash/dictionaries/threats/malware_key.yml", "w", encoding="utf-8") as f, \
         open("/etc/logstash/dictionaries/threats/malware_alias.yml", "w", encoding="utf-8") as a, \
         open("/etc/logstash/dictionaries/threats/malware_printable.yml", "w", encoding="utf-8") as p, \
         open("/etc/logstash/dictionaries/threats/confidence_level.yml", "w", encoding="utf-8") as c, \
         open("/etc/logstash/dictionaries/threats/reference.yml", "w", encoding="utf-8") as r:

        for line_number, row in enumerate(csv_reader, start=1):
            if line_number >= 10 and len(row) > 10:

                key = clean_string(row[2])

                if not key:
                    continue

                write_yaml_line(m, key, "YES")
                write_yaml_line(t, key, row[4])
                write_yaml_line(f, key, row[5])
                write_yaml_line(a, key, row[6])
                write_yaml_line(p, key, row[7])

                # confidence is numeric → no quotes
                confidence = clean_string(row[9])
                if confidence.isdigit():
                    write_yaml_line(c, key, confidence, quote_value=False)

                write_yaml_line(r, key, row[10])

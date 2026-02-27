#!/usr/bin/python3
"""
ThreatFox Logstash Dictionary Builder
======================================

This script downloads threat intelligence data from abuse.ch ThreatFox
and converts it into multiple YAML dictionary files suitable for
Logstash lookups.

Workflow overview:

1. Fetches the ThreatFox hostfile containing malicious domains and
   extracts domain names mapped to 127.0.0.1.
2. Writes a YAML dictionary marking each domain as "YES" for
   threat presence detection.
3. Downloads the full ThreatFox domain CSV export (ZIP archive).
4. Extracts the archive locally.
5. Parses the CSV data and generates multiple structured YAML
   dictionaries for Logstash enrichment, including:

   - malware.yml              → Presence indicator
   - threat_type.yml          → Threat classification
   - malware_key.yml          → Malware family key
   - malware_alias.yml        → Alternate malware names
   - malware_printable.yml    → Human-readable label
   - confidence_level.yml     → Confidence score
   - reference.yml            → External references

Key characteristics:

- Automatically retrieves up-to-date intelligence from ThreatFox.
- Performs basic preprocessing to normalize CSV formatting.
- Outputs YAML key-value mappings compatible with Logstash
  dictionary filter lookups.
- Designed for integration into SIEM or pipeline-based
  threat enrichment workflows.

External dependencies:
    - requests
    - csv
    - zipfile
    - re

Output location:
    /etc/logstash/dictionaries/threats/

This script is intended to be run in environments where Logstash
dictionary files are maintained locally and updated periodically.
"""
import csv
import zipfile
import re
import requests
URL = "https://threatfox.abuse.ch/downloads/hostfile/"
ZIPURL = "https://threatfox.abuse.ch/export/csv/domains/full/"
LOCAL_ZIP_PATH = "threatfox.zip"
pattern = re.compile(r"127\.0\.0\.1\s+(.*)")
try:
    f = open("/etc/logstash/dictionaries/threats/threats.yml", "w") #pylint: disable=consider-using-with,unspecified-encoding
    response = requests.get(URL)#pylint: disable=missing-timeout
    response.raise_for_status()
    for line in response.iter_lines(decode_unicode=True):
        if line:
            match = pattern.match(line)
            if match:
                domain_name = match.group(1)
                f.write('"'+domain_name+'": "YES"\n')
    f.close()
except requests.exceptions.RequestException as e:
    print(f"Error fetching the URL: {e}")
try:
    response = requests.get(ZIPURL) #pylint: disable=missing-timeout
    response.raise_for_status()
    with open(LOCAL_ZIP_PATH, 'wb') as file:
        file.write(response.content)
except requests.exceptions.RequestException as e:
    print(f"Error fetching the URL: {e}")
    exit() #pylint: disable=consider-using-sys-exit
EXTRACT_PATH="output"
try:
    with zipfile.ZipFile(LOCAL_ZIP_PATH, 'r') as zip_ref:
        zip_ref.extractall(EXTRACT_PATH)
    print(f"ZIP file extracted to {EXTRACT_PATH}")
except zipfile.BadZipFile as e:
    print(f"Error uncompressing the file: {e}")
def preprocess_line(iline):
    """
    Normalize a line of text by removing spaces after commas.

    This function replaces occurrences of ", " with "," to ensure
    consistent comma-separated formatting. It is useful when preparing
    text for parsing or tokenization where extra whitespace may cause
    inconsistencies.

    Args:
        iline (str): The input line to preprocess.

    Returns:
        str: The normalized line with spaces after commas removed.
    """
    return iline.replace(", ", ",")

CSV_FILE_PATH = 'output/full_domains.csv'
with open(CSV_FILE_PATH, mode='r', newline='', encoding='utf-8') as csv_file:
    preprocessed_lines = [preprocess_line(line) for line in csv_file]
    csv_reader = csv.reader(
            preprocessed_lines,
            delimiter=',',
            quotechar='"',
            quoting=csv.QUOTE_MINIMAL
    )
    m = open("/etc/logstash/dictionaries/threats/malware.yml", "w") #pylint: disable=consider-using-with, unspecified-encoding
    t = open("/etc/logstash/dictionaries/threats/threat_type.yml", "w") #pylint: disable=consider-using-with, unspecified-encoding
    f = open("/etc/logstash/dictionaries/threats/malware_key.yml", "w") #pylint: disable=consider-using-with, unspecified-encoding
    a = open("/etc/logstash/dictionaries/threats/malware_alias.yml", "w") #pylint: disable=consider-using-with, unspecified-encoding
    p = open("/etc/logstash/dictionaries/threats/malware_printable.yml", "w") #pylint: disable=consider-using-with, unspecified-encoding
    c = open("/etc/logstash/dictionaries/threats/confidence_level.yml", "w") #pylint: disable=consider-using-with, unspecified-encoding
    r = open("/etc/logstash/dictionaries/threats/reference.yml", "w") #pylint: disable=consider-using-with, unspecified-encoding
    for line_number, row in enumerate(csv_reader, start=1):
        if line_number >= 10 and len(row)>9 :
            m.write('"'+row[2]+'": "YES"\n')
            t.write('"'+row[2]+'": "'+row[4]+'"\n')
            f.write('"'+row[2]+'": "'+row[5]+'"\n')
            a.write('"'+row[2]+'": "'+row[6]+'"\n')
            p.write('"'+row[2]+'": "'+row[7]+'"\n')
            c.write('"'+row[2]+'": '+row[9]+'\n')
            r.write('"'+row[2]+'": "'+row[10]+'"\n')
    m.close()
    t.close()
    f.close()
    a.close()
    p.close()
    c.close()
    r.close()

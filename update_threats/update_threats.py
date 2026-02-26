#!/usr/bin/python3
import csv
import zipfile
import re
import requests
url = "https://threatfox.abuse.ch/downloads/hostfile/"
zipurl = "https://threatfox.abuse.ch/export/csv/domains/full/"
local_zip_path = "threatfox.zip"
pattern = re.compile(r"127\.0\.0\.1\s+(.*)")
try:
    f = open("/etc/logstash/dictionaries/threats/threats.yml", "w") #pylint: disable=consider-using-with
    response = requests.get(url)
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
    response = requests.get(zipurl)
    response.raise_for_status() 
    with open(local_zip_path, 'wb') as file:
        file.write(response.content)
except requests.exceptions.RequestException as e:
    print(f"Error fetching the URL: {e}")
    exit()
extract_path="output"
try:
    with zipfile.ZipFile(local_zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)
    print(f"ZIP file extracted to {extract_path}")
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
    csv_reader = csv.reader(preprocessed_lines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
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

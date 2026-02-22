#!/usr/bin/python3
import requests
import re
import zipfile
import csv
url = "https://threatfox.abuse.ch/downloads/hostfile/"
zipurl = "https://threatfox.abuse.ch/export/csv/domains/full/"
local_zip_path = "threatfox.zip"
pattern = re.compile(r"127\.0\.0\.1\s+(.*)")
try:
    f = open("/etc/logstash/dictionaries/threats/threats.yml", "w")
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
def preprocess_line(line):
    return line.replace(", ", ",")

csv_file_path = 'output/full_domains.csv'
with open(csv_file_path, mode='r', newline='', encoding='utf-8') as csv_file:
    preprocessed_lines = [preprocess_line(line) for line in csv_file]
    csv_reader = csv.reader(preprocessed_lines, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    m = open("/etc/logstash/dictionaries/threats/malware.yml", "w")
    t = open("/etc/logstash/dictionaries/threats/threat_type.yml", "w")
    f = open("/etc/logstash/dictionaries/threats/malware_key.yml", "w")
    a = open("/etc/logstash/dictionaries/threats/malware_alias.yml", "w")
    p = open("/etc/logstash/dictionaries/threats/malware_printable.yml", "w")
    c = open("/etc/logstash/dictionaries/threats/confidence_level.yml", "w")
    r = open("/etc/logstash/dictionaries/threats/reference.yml", "w")
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




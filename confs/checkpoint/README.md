# Checkpoint Log Pipeline to Kibana

This setup is used to ingest and visualize **Checkpoint firewall logs** in **Kibana**, using **Logstash** to parse and enrich the log data before sending it to **Elasticsearch**.

##  Files in This Repository

### 1. `checkpoint.conf`

This is the **Logstash pipeline configuration** file. It defines how raw Checkpoint logs are received, parsed, enriched, and forwarded to Elasticsearch.

####  Input

```logstash
input {
  tcp {
    port => 5001
    type => checkpoint
  }
}
```

* Listens on TCP port `5001` for incoming logs.
* Assigns logs a type of `"checkpoint"`.

####  Filter

The filter section performs multiple transformations:

* **KV Parsing**: Parses space-separated key-value fields from each log line.
* **Timestamp Handling**: Converts UNIX timestamps to a structured `@timestamp` with proper timezone (`America/Sao_Paulo`).
* **Ruby Enrichment**: Adds custom fields like:

  * `hour_of_day`
  * `day_of_week`
  * `day_of_name`
    ... based on local time.
* **Type Conversion**: Converts numerical fields (like `bytes`, `proto`, `elapsed`) to proper integers.
* **GeoIP Lookup**: Resolves `src` and `dst` IPs to geographical and ASN metadata.
* **TOR Exit Detection**: Checks whether the source IP belongs to the TOR network using a dictionary YAML file.
* **Cleanup**: Removes the raw `message` field after processing.

####  Output

```logstash
output {
  if "" in [type] and [type] == "checkpoint" {
    elasticsearch {
      hosts => ["https://localhost:9200"]
      index => "checkpoint-%{+YYYY}"
      user  => "elastic"
      password => "yourpasswordhere"
      ssl_verification_mode => none
    }
  }
}
```

* Logs are sent to an Elasticsearch index named `checkpoint-<YEAR>`.
* Example: `checkpoint-2025`

---

### 2. `Checkpoint.ndjson`

This is an **NDJSON (Newline Delimited JSON)** file used to **import Kibana visualizations, dashboards, and saved searches**.

* You can import this file via:

  * Kibana → **Stack Management** → **Saved Objects** → **Import**

---

##  Usage Workflow

1. **Start Logstash** with `checkpoint.conf`:

   ```bash
   logstash -f checkpoint.conf
   ```

2. **Send Checkpoint logs** to TCP port `5001`.

3. **Logstash parses and enriches** the logs and stores them in the appropriate `checkpoint-*` index in Elasticsearch.

4. **Import `Checkpoint.ndjson`** into Kibana to get dashboards and visualizations.

5.  You now have a real-time **Checkpoint firewall log monitoring** system powered by the ELK stack!

---

##  Notes

* Make sure the GeoIP ASN database is available at:

  ```
  /opt/maxmind/output/GeoLite2-ASN.mmdb
  ```
* For TOR detection, ensure the dictionary file exists:

  ```
  /etc/logstash/dictionaries/tor_nodes/torexil.yml
  ```
* Update your Elasticsearch credentials in `checkpoint.conf`.

---

 WAF Logging Architecture: 5-Year Retention & TSDS

This document outlines the Elasticsearch configuration for the Web Application Firewall (WAF) logs, designed for **15 days of raw forensic data** and **5 years of downsampled trend data**.

## 1\. Global Cluster Configuration

These settings optimize the environment for a single-node or small-cluster setup.

### Replica Management

HTTP

```
PUT logs-waf*/_settings
{
  "index": {
    "number_of_replicas": 0
  }
}
```

-   **Purpose:** Disables backup copies (replicas).
-   **Why:** In single-node environments, indices stay "Yellow" if they look for a second node. Setting this to `0` ensures "Green" health and allows ILM to process actions without delay.

### ILM Poll Interval

HTTP

```
PUT _cluster/settings
{
  "transient": {
    "indices.lifecycle.poll_interval": "10s"
  }
}
```

-   **Purpose:** Increases the frequency at which Elasticsearch checks lifecycle rules.
-   **Why:** Default is 10 minutes. 10 seconds is better for testing and ensures that the transition from Raw to Downsampled happens immediately once the timer expires.

* * *

## 2\. Index Lifecycle Policy (ILM)

**Name:** `ilm_policy_waf`

This policy automates the data lifecycle across three distinct phases.

| Phase | Action | Trigger (`min_age`) | Description |
| --- | --- | --- | --- |
| **Hot** | Rollover | `0ms` | Rollover occurs when an index is **1 day** old or reaches **50GB**. |
| **Warm** | Downsample | **14 days** | After 14 days in Warm (15 days total), data is squashed into **1-hour** intervals. |
| **Delete** | Delete | **1824 days** | Data is permanently removed after **5 years**. |


JSON

```
PUT _ilm/policy/ilm_policy_waf
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_primary_shard_size": "50gb",
            "max_age": "1d"
          }
        }
      },
      "warm": {
        "min_age": "14d",
        "actions": {
          "downsample": {
            "fixed_interval": "1h"
          }
        }
      },
      "delete": {
        "min_age": "1824d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

* * *

## 3\. Templates

These blueprints ensure every new log index is born with the correct "Time Series" DNA.

### Component Template (Dimensions)

Defines the specific fields that must survive the downsampling process.

JSON

```
PUT _component_template/component_template_waf
{
  "template": {
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "enforcement_action": { "type": "keyword", "time_series_dimension": true },
        "dest_host": { "type": "keyword", "time_series_dimension": true },
        "attack_type": { "type": "keyword", "time_series_dimension": true },
        "client_type": { "type": "keyword", "time_series_dimension": true },
        "response_code": { "type": "keyword", "time_series_dimension": true },
        "method": { "type": "keyword", "time_series_dimension": true }
      }
    }
  }
}
```

### Index Template

Applies settings to any index starting with `logs-waf*`.

JSON

```
PUT _index_template/index_template_waf
{
  "index_patterns": ["logs-waf*"],
  "data_stream": { },
  "priority": 250,
  "composed_of": ["component_template_waf"],
  "template": {
    "settings": {
      "index.mode": "time_series",
      "index.lifecycle.name": "ilm_policy_waf",
      "index.number_of_shards": 2,
      "index.number_of_replicas": 1
    },
    "mappings": {
      "properties": {
        "client_ip": { "type": "ip" },
        "ip_client": { "type": "ip" }
      }
    }
  }
}
```

* * *

## 4\. Maintenance & Monitoring Commands

| Command | Usage |
| --- | --- |
| `GET logs-waf*/_ilm/explain` | Check exactly which stage/step an index is currently in. |
| `GET _data_stream/logs-waf-prod` | View the health and backing indices of the main stream. |
| `GET _cat/indices/logs-waf*?v&h=index,docs.count,store.size` | Monitor index size and document counts. |
| `GET _cat/indices/logs-waf-prod?v&s=index` | View indices sorted by name to track rollover sequence. |


* * *

### Key Operational Notes

1.  **Forensics:** You have 15 days of raw logs. After day 15, you cannot see specific `client_ip` or `uri` values anymore.
2.  **Reporting:** Long-term dashboards (1 month+) will automatically use the downsampled 1-hour data for lightning-fast performance.
3.  **Storage:** Expect a significant drop in storage usage on Day 15 when the first rollover index is downsampled.


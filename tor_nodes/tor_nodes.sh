#!/bin/bash
base_dir="/etc/logstash/dictionaries/tor_nodes"
export http_proxy=http://200.189.113.254:8000
export https_proxy=http://200.189.113.254:8000
curl -vs https://check.torproject.org/exit-addresses 2>&1 | grep ExitAdd | cut -d" " -f2 | awk '{ print "\""$1"\": \"YES\"" '} > $base_dir/torexil.yml

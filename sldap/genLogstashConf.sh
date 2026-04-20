cat genLogstashconf.sh 
#!/bin/bash
DIR="/etc/logstash/dictionaries/sldap"
for file in `ls -1 output_yaml_files/`
do
        attribute=`basename $file .yml`
        echo "                translate"
        echo "                {"
        echo "                        source => \"[user]\""
        echo "                        target => \"[$attribute]\""
        echo "                        dictionary_path => \"$DIR/$file\""
        echo "                }"

done
mkdir -p $DIR
cp output_yaml_files/* $DIR
chown logstash: $DIR/*

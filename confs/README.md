# Performance tips

In some scenarios it might be interesting disabling logstash logging to console, and consequentialy to syslog. It should be enough to keep logstash logs to /var/log/logstash/logstash-plain.log. To achieve it, comment out the following lines in /etc/logstash/log4j2.properties

```
# appender.console.type = Console
# appender.console.name = plain_console
# appender.console.layout.type = PatternLayout
# appender.console.layout.pattern = [%d{ISO8601}][%-5p][%-25c]%notEmpty{[%X{pipeline.id}]}%notEmpty{[%X{plugin.id}]} %m%n
# appender.json_console.type = Console
# appender.json_console.name = json_console
# appender.json_console.layout.type = JSONLayout
# appender.json_console.layout.compact = true
# appender.json_console.layout.eventEol = true
# rootLogger.appenderRef.console.ref = ${sys:ls.log.format}_console
# appender.console_slowlog.type = Console
# appender.console_slowlog.name = plain_console_slowlog
# appender.console_slowlog.layout.type = PatternLayout
# appender.console_slowlog.layout.pattern = [%d{ISO8601}][%-5p][%-25c] %m%n
# appender.json_console_slowlog.type = Console
# appender.json_console_slowlog.name = json_console_slowlog
# appender.json_console_slowlog.layout.type = JSONLayout
# appender.json_console_slowlog.layout.compact = true
# appender.json_console_slowlog.layout.eventEol = true
# logger.slowlog.appenderRef.console_slowlog.ref = ${sys:ls.log.format}_console_slowlog
```

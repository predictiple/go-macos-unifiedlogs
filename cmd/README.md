# A sample binary for parsing unified logs.


This program is able to parse logs and emit them in json or jsonl
output.

Filtering is provided by the VQL library (vfilter)

Example use:

```
./unifiedlog_parser parse /tmp/system_logs.logarchive/ --format json --filter "message_entries =~ 'com.apple.wifip2pd'"

```

The filter expression is any VQL expression which is valid in a WHERE clause.

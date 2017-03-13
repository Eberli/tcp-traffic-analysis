# tcp-traffic-analysis
A tools for analyzing the traffic of TCP packages.

## Usage

```shell
$ tcpdump -s 65535 tcp port 6379 -w redis.pcap -i eth0
$ node ./tcp-traffic-analysis 10.0.0.224 ~/redis.pcap
```

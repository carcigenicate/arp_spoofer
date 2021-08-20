Spoofs ARPs between the provided IP addresses.

It will attempt to convince the hosts at the provided IP addresses, that you are the party they're looking for.

For example, if you provide addresses 192.168.1.2 and 192.168.1.3, it will convince .1.2 that you're .1.3, and .1.3.
that you're .1.2. This will cause traffic being sent between the parties to be sent to you first.

IP forwarding must be enabled on the OS or else the intercepted traffic won't be sent along, and your computer will act
as a black hole.

```
./arpspoof.py --help
uusage: arpspoof.py [-h] [-r] [-t TOTAL_TIME] [-b BURST_DELAY] [-v] ips [ips ...]

positional arguments:
  ips                   The IP addresses to redirect traffic from.

optional arguments:
  -h, --help            show this help message and exit
  -r, --recover_after   Whether to attempt to reverse the ARP cache poisoning afterward.
  -t TOTAL_TIME, --total_time TOTAL_TIME
                        The total amount of time in seconds to run for.
  -b BURST_DELAY, --burst_delay BURST_DELAY
                        The delay in seconds between bursts of ARPs being sent out.
  -v, --verbose         Whether Scapy's verbose output should be show for all operations.
```

For educational purposes only.
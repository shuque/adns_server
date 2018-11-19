# adns_server
A toy authoritative DNS server for experiments

A quick and dirty Python authoritative DNS server, that I've
occasionally used for experimentation (often to simulate the
behavior of some other implementation that exhibits some problem).

### Notes

* dnspython's dns.zone.find_node() gives the wrong result for empty non
  terminals, sigh. This is a consequence of the fact that the zone structure
  is composed of a python dictionary keyed only by names with associated RRsets.
  To workaround this, I use a wrapper class (Zone) that modifies the zone
  object to explicitly include all the empty non-terminals as explicit nodes.
  When I have time, I'll probably implement a tree data structure to hold
  the zone nodes.

### TODO list

* Support daemon mode (in addition to foreground mode)
* Handle wildcards
* Handle EDNS
* Handle DNAME
* Support Zone Transfer
* Better Logging options
* Support DNSSEC
* Support multiple zones
* Support child zone delegations
* Access control

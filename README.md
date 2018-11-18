# adns_server
A toy authoritative DNS server for experiments

A quick and dirty Python authoritative DNS server, that I've
occasionally used for experimentation (often to simulate the
behavior of some other implementation that exhibits some problem).

### Notes

* dnspython's dns.zone.find_node() gives wrong result for empty
  non terminals, sigh. This is a consequence of the fact that the
  zone structure is composed of a python dictionary keyed only
  by names with associated RRsets. TODO: to workaround this, I'll
  have to either use my own different tree-like data structure,
  or add one on top of dns.zone that allows me to efficiently
  search for all nodes including ENTs.

### TODO list

* Port to Python3
* Support daemon mode (in addition to remain attached to foreground mode)
* Access control
* Support Zone Transfer
* Non IN class --> return REFUSED
* Support DNSSEC
* Handle CNAMEs
* Add a tree datastructure on top of dns.zone to deal with ENT properly
* Support multiple zones

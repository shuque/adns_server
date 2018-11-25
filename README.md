# adns_server
Version 0.1  
A toy authoritative DNS server for experiments

A quick and dirty Python authoritative DNS server, that I've
occasionally used for experimentation (often to simulate the
behavior of some other implementation that exhibits some problem).

### Notes

* dnspython's dns.zone.Zone class uses a python dictionary (i.e. hash table)
  to store DNS nodes, and furthermore only stores nodes with associated
  RRsets. This makes it very inefficient for certain important tasks, such
  as locating empty non-terminals and DNAME records. To partially workaround
  this, I use a wrapper class (Zone) that modifies the zone object to
  explicitly search for and include all the empty non-terminals as explicit
  nodes. In some future version of this program, I will re-implement the
  zone with an actual tree data structure.

### TODO list

* Handle EDNS
* Support Zone Transfer
* Support DNSSEC
* Support multiple zones
* Support child zone delegations
* Access control

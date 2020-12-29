# adns_server
Version 0.2.0
A toy authoritative DNS server for experiments

A quick and dirty Python authoritative DNS server, that I've
occasionally used for experimentation.

### Pre-requisites

* Python 3
* The dnspython module (http://www.dnspython.org/)
* PyYAML module


### Usage

```
$ adns_server.py -h
Reading config from: adnsconfig.yaml
adns_server.py version 0.2.2
Usage: adns_server.py [<Options>]

Options:
       -h:        Print usage string
       -c file:   Configuration file (default 'adnsconfig.yaml')
       -d:        Turn on debugging
       -p N:      Listen on port N (default 53)
       -s A:      Bind to server address A (default wildcard address)
       -u uname:  Drop privileges to UID of specified username
                  (if server started running as root)
       -g group:  Drop provileges to GID of specified groupname
                  (if server started running as root)
       -4:        Use IPv4 only
       -6:        Use IPv6 only
       -f:        Remain attached to foreground (default don't)
       -e N:      Max EDNS bufsize in octets for responses we send out.
                  (-e 0 will disable EDNS support)

Note: a configuration file that minimally specifies the zones to load
must be present.
```

### Configuration file

An example configuration file looks like the following. At a minimum
it needs so specify the "zones:" section, defining the zone names and
zone files for each zone that the server will serve.

The configuration file supports additional options beyond what can
be specified via command line switches. Such as contents of the NSID
option, etc.

```
config:
  port: 5309
  user: "named"
  group: "named"
  edns: 1432
  nsid: "dnstest.example.com"
zones:
  - name: "example.com"
    file: "zonefile.example"
  - name: "blah.com"
    file: "zonefile.blah"
```


### TODO list

* Implement some EDNS options
* Support Zone Transfer
* Support DNSSEC

# adns_server

This is a fully functional authoritative DNS server written in Python.
I mainly use it for functional testing and prototyping new protocol
features. It is not intended for production use or high performance
applications.

It serves DNS zones in master file format (e.g. BIND format). For DNSSEC,
it can serve pre-signed master file format zones, both NSEC and NSEC3 (e.g.
zones generated with an offline signer like BIND's dnssec-signzone). It
can also perform online signing with a combined signing key using the
[Compact Denial of Existence](https://datatracker.ietf.org/doc/draft-ietf-dnsop-compact-denial-of-existence/) method.

The 'dnssec: true' parameter must be specified in the configuration file
for signed zones. The 'dynamic_signing: true' and 'private_key: /path/to/privatekey.pem'
options are needed for online signing.


### Pre-requisites

* Python 3
* Python Cryptography module
* The dnspython module, version 2.3 or greater
* sortedcontainers
* PyYAML module
* siphash module (for DNS cookie support)

These can usually be installed via pip:
```
pip install cryptography
pip install 'dnspython>=2.3'
pip install sortedcontainers
pip install pyyaml
pip install siphash
```

### Usage

```
$ adns_server.py -h
Reading config from: adnsconfig.yaml
adns_server.py version 0.4.2
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
option, DNSSEC parameters, etc.

```
config:
  port: 5309
  user: "named"
  group: "named"
  edns: 1432
  minimal_any: false
  nsid: "dnstest.example.com"
zones:
  - name: "example.com"
    file: "zonefile.example"
  - name: "signedzone.com"
    dnssec: true
    file: "zonefile.signedzone"
  - name "onlinesigning.com"
    dnssec: true
    file "zonefile.onlinesigning"
    dynamic_signing: true
    private_key: "/path/to/privatekey.pem"
```

### Key Generation for Online Signing

This repo also includes a small script, genkey.pl, to help generate
DNSSEC keys used for online signing configurations.

```
$ ./genkey.py -h
usage: genkey.py [-h] [-a N] [-f N] zone

positional arguments:
  zone        DNS zone name

optional arguments:
  -h, --help  show this help message and exit
  -a N        DNSSEC algorithm number (default: 13)
  -f N        Value of DNSKEY flags field (default: 257)
  ```

  An example usage to generate an ECDSA NIST P256 (algorithm 13)
  key for example.com follows.

  ```
  $ ./genkey.py example.com
### Private Key file contents:
-----BEGIN PRIVATE KEY-----
XXXXXXX+++++++++++++++++++++REDACTEDKEY+++++++++++++++++XXXXXXXX
XXXXXXX+++++++++++++++++++++REDACTEDKEY+++++++++++++++++XXXXXXXX
XXXXXXX+++++++++++++++++++++REDACTEDKEY+++++++++XXXXXXXX
-----END PRIVATE KEY-----

### DNSKEY RDATA:
257 3 13 oBQvOkuVPdp7Wes6EcWra7UlyI3u9EeM nRd79CSmq4ggIobc7oVPxTq3NhespdTC hZ4gArRqrftxjsUxjP0dOQ==
### DNSKEY keytag: 56959

### DNSKEY RRset:
example.com. 7200 IN DNSKEY 257 3 13 oBQvOkuVPdp7Wes6EcWra7UlyI3u9EeM nRd79CSmq4ggIobc7oVPxTq3NhespdTC hZ4gArRqrftxjsUxjP0dOQ==

### DS record
56959 13 2 ac2c59edcb0d9021d6898e2824cd63fd67c3d8c0b6da69943121b5b5263bdbad
```
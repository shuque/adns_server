"""
Configuration, command-line-argument, and zone-loading layer.

Defines the `Preferences` and `ServerContext` dataclasses, and the
config-file / CLI processing functions that build them at startup.
"""

import os
import sys
import argparse
import syslog
from dataclasses import dataclass, field
from typing import Optional
import yaml

import dns.name
import dns.exception

from adns import __version__
from adns.zone import ZoneDict, zone_from_file
from adns.crypto import load_private_key


PROGNAME = "adns-server"
CONFIG_DEFAULT = 'adnsconfig.yaml'

# Timeouts (seconds)
TCP_TIMEOUT = 5                       # Deadline to read one TCP query (RFC 7766 §8)

# Concurrency
MAX_WORKERS = 256                     # Cap on concurrent query worker threads

@dataclass
class Preferences:                            # pylint: disable=too-many-instance-attributes
    """Server preferences (command line > config file > these defaults)."""

    config: str = CONFIG_DEFAULT           # -c: Configuration file
    debug: bool = False                    # -d: Print debugging output
    server: str = ''                       # -s: server listening address
    server_af: Optional[str] = None        # server's address family if -s set
    port: int = 53                         # -p: port
    username: Optional[str] = None         # username to switch to (if root)
    groupname: Optional[str] = None        # group to switch to (if root)
    daemon: bool = True                    # Become daemon (-f: foreground)
    syslog_fac: int = syslog.LOG_DAEMON    # Syslog facility
    syslog_pri: int = syslog.LOG_INFO      # Syslog priority
    workdir: Optional[str] = None          # -w: Working directory to change to
    workdir_cli: Optional[str] = None      # -w value (wins over config re-read)
    pidfile: Optional[str] = None          # PID file
    edns_udp_max: int = 1432               # -e: Max EDNS UDP payload we send
    edns_udp_adv: int = 1232               # Max EDNS UDP payload we advertise
    tcp_timeout: int = TCP_TIMEOUT         # Deadline to read one TCP query (secs)
    max_workers: int = MAX_WORKERS         # Cap on concurrent worker threads
    nsid: Optional[bytes] = None           # NSID option string
    minimal_any: bool = False              # Minimal ANY (RFC 8482)
    nsec_ideal_predecessor: bool = False   # RFC 4470 ideal (63-octet) predecessor
    cache_stats: bool = False              # Print online sig cache statistics


@dataclass
class ServerContext:
    """
    Per-server runtime state, passed explicitly to the query path.
    Bundles the configured preferences, the loaded zones, and state derived at
    startup (the DNS-cookie secret and the socket dispatch table).
    """
    prefs: Preferences
    zonedict: "ZoneDict"
    cookie_secret: Optional[bytes] = None  # Secret for DNS cookie generation

    # default_factory=dict gives each ServerContext its OWN empty dict. A bare
    # "dispatch: dict = {}" would evaluate the {} once at class-definition time
    # and share that single dict across every instance (the mutable-default
    # trap); dataclasses forbid it. The factory is called per instance instead.
    dispatch: dict = field(default_factory=dict)


def make_arg_parser():
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog=PROGNAME,
        allow_abbrev=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{PROGNAME} version {__version__} - "
                    "An authoritative DNS server",
        epilog="Note: a configuration file that minimally specifies the "
               "zones to load must be present.")

    # Options that override a config-file setting are given no argparse
    # default (they stay None when unsupplied) so the class-level Preferences
    # defaults and any config-file values survive; process_args() copies an
    # option onto Preferences only when it was actually given. Precedence is
    # therefore: command line > config file > Preferences defaults.
    parser.add_argument("--version", action="version",
                        version=f"{PROGNAME} {__version__}")
    parser.add_argument("-c", dest="config", metavar="FILE",
                        help=f"Configuration file (default: {CONFIG_DEFAULT})")
    parser.add_argument("-w", dest="workdir", metavar="DIR",
                        help="Working directory (overrides config workdir)")
    parser.add_argument("-d", dest="debug", action="store_true", default=None,
                        help="Turn on debugging")
    parser.add_argument("-p", dest="port", type=int, metavar="N",
                        help="Listen on port N (default: 53)")
    parser.add_argument("-s", dest="server", metavar="ADDR",
                        help="Bind to server address (default: wildcard)")
    parser.add_argument("-u", dest="username", metavar="USER",
                        help="Drop privileges to UID of specified user "
                             "(if started as root)")
    parser.add_argument("-g", dest="groupname", metavar="GROUP",
                        help="Drop privileges to GID of specified group "
                             "(if started as root)")
    af_group = parser.add_mutually_exclusive_group()
    af_group.add_argument("-4", dest="server_af", action="store_const",
                          const="IPv4", help="Use IPv4 only")
    af_group.add_argument("-6", dest="server_af", action="store_const",
                          const="IPv6", help="Use IPv6 only")
    parser.add_argument("-f", dest="foreground", action="store_true",
                        default=None, help="Remain attached to foreground")
    parser.add_argument("-e", dest="edns_udp_max", type=int, metavar="N",
                        help="Max EDNS bufsize in octets for responses we "
                             "send out (-e 0 disables EDNS support)")
    return parser


def init_config(prefs, zonedict, only_zones=False):
    """Initialize parameters and zone files from config file"""

    with open(prefs.config, 'r', encoding="utf-8") as configfile:
        ydoc = yaml.safe_load(configfile)

    if not only_zones:
        if "config" in ydoc:
            for key, val in ydoc['config'].items():
                if key == 'port':
                    prefs.port = val
                elif key == 'workdir':
                    # A -w on the command line overrides the config value,
                    # and must keep winning across SIGHUP config re-reads.
                    prefs.workdir = prefs.workdir_cli or val
                elif key == 'pidfile':
                    prefs.pidfile = val
                elif key == 'edns':
                    prefs.edns_udp_max = val
                elif key == 'tcp_timeout':
                    prefs.tcp_timeout = val
                elif key == 'max_workers':
                    prefs.max_workers = val
                elif key == 'user':
                    prefs.username = val
                elif key == 'group':
                    prefs.groupname = val
                elif key == 'nsid':
                    prefs.nsid = val.encode()
                elif key == 'minimal_any':
                    prefs.minimal_any = val
                elif key == 'nsec_ideal_predecessor':
                    prefs.nsec_ideal_predecessor = val
                elif key == "cache_stats":
                    prefs.cache_stats = val
                else:
                    print(f"error: unrecognized config option: {key}")
                    sys.exit(1)

    if "zones" in ydoc:
        load_zones(prefs, zonedict, ydoc['zones'])

    if not zonedict.get_zonelist():
        print("error: no zones defined.")
        sys.exit(1)


def load_zones(prefs, zonedict, zonesconfig):
    """Load all zones"""

    for config in zonesconfig:
        zonename = dns.name.from_text(config['name'])
        zone = make_single_zone(prefs, zonename, config)
        zonedict.add(zonename, zone)
    zonedict.set_zonelist()


def make_single_zone(prefs, zonename, config):
    """Read a single zone and return a Zone object"""

    zonefile = config['file']
    if not zonefile.startswith('/') and prefs.workdir:
        zonefile = os.path.join(prefs.workdir, zonefile)
    try:
        zone = zone_from_file(zonename, zonefile)
    except dns.exception.DNSException as exc_info:
        print(f"error: load zone {zonename} failed: {exc_info}")
        sys.exit(1)

    if config.get('dnssec', False):
        zone.init_dnssec()
        if config.get('dynamic_signing', False):
            privatekey_path = config['private_key']
            if not privatekey_path.startswith('/') and prefs.workdir:
                privatekey_path = os.path.join(prefs.workdir, privatekey_path)
            privatekey = load_private_key(privatekey_path)
            zone.init_key(privatekey)
            zone.compact_denial = config.get('compact_denial', False)
    try:
        zone.reject_wildcard_deleg()
    except ValueError as exc_info:
        print(f"error: load zone {zonename} failed: {exc_info}")
        sys.exit(1)
    zone.udp_truncate_all = config.get('udp_truncate_all', False)
    zone.require_server_cookie = config.get('require_server_cookie', False)
    return zone


def set_server_af(prefs, address):
    """Set server's address family"""

    if address.find('.') != -1:
        prefs.server_af = 'IPv4'
    elif address.find(':') != -1:
        prefs.server_af = 'IPv6'
    else:
        raise ValueError(f"{address} isn't a valid address")


def process_args(prefs, zonedict, arguments):
    """Process all command line arguments (command line overrides config)."""

    args = make_arg_parser().parse_args(arguments)

    # Config file and working directory must be settled before init_config(),
    # which reads the config and resolves relative zone/key paths against
    # workdir. workdir_cli records a -w so it keeps winning on SIGHUP re-reads.
    if args.config is not None:
        prefs.config = args.config
    if args.workdir is not None:
        prefs.workdir_cli = args.workdir
        prefs.workdir = args.workdir
    print(f"Reading config from: {prefs.config}")
    init_config(prefs, zonedict)

    if args.debug:
        prefs.debug = True
    if args.port is not None:
        prefs.port = args.port
    if args.server is not None:
        prefs.server = args.server
        set_server_af(prefs, args.server)
    if args.username is not None:
        prefs.username = args.username
    if args.groupname is not None:
        prefs.groupname = args.groupname
    if args.server_af is not None:      # -4/-6 override any -s-derived family
        prefs.server_af = args.server_af
    if args.foreground:
        prefs.daemon = False
    if args.edns_udp_max is not None:
        prefs.edns_udp_max = args.edns_udp_max

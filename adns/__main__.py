"""
Entrypoint for the adns-server console script.
"""

import sys

from adns.config import ServerContext, Preferences, process_args
from adns.zone import ZoneDict
from adns.log import init_logging
from adns.server import setup_server, run_event_loop


def main():
    """Parse arguments, load zones, and run the server event loop."""
    ctx = ServerContext(prefs=Preferences(), zonedict=ZoneDict())
    process_args(ctx.prefs, ctx.zonedict, sys.argv[1:])
    init_logging(ctx.prefs)
    setup_server(ctx)
    run_event_loop(ctx)


if __name__ == '__main__':
    main()

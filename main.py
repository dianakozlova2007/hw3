#!/usr/bin/env python3
import sys
from scapy.config import conf

from parser import parse_args
from portscan import format_result, scan_ports


def main() -> int:
    conf.verb = 0
    args, ports_by_protocol = parse_args()
    try:
        results = scan_ports(
            args.ip, ports_by_protocol, args.timeout, args.guess, args.num_threads
        )
        for result in results:
            print(format_result(result, args.verbose, args.guess), flush=True)
    except PermissionError:
        print("portscan: raw sockets require root privileges", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("portscan: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())

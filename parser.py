import argparse
import ipaddress
import math
from constants import ALL_PORTS, MAX_PORT


def ip_type(string):
    try:
        ip = ipaddress.ip_address(string)
    except ValueError:
        raise argparse.ArgumentTypeError(f'invalid IP address: {string!r}')

    if ip.version != 4:
        raise argparse.ArgumentTypeError('only IPv4 is supported')

    return str(ip)


def timeout_type(string):
    try:
        value = float(string)
    except ValueError:
        raise argparse.ArgumentTypeError(f'invalid timeout: {string!r}')

    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError('timeout must be a positive number')

    return value


def threads_type(string):
    try:
        value = int(string)
    except ValueError:
        raise argparse.ArgumentTypeError(f'invalid number of threads: {string!r}')

    if value < 1:
        raise argparse.ArgumentTypeError('number of threads must be >= 1')

    return value


def spec_type(spec_text):
    protocol, separator, ports_text = spec_text.partition('/')
    protocol = protocol.lower()

    if protocol not in ('tcp', 'udp'):
        raise argparse.ArgumentTypeError(f'unknown protocol in {spec_text!r}')
    if not separator:
        return protocol, set(ALL_PORTS)

    ports = set()
    for port_part in ports_text.split(','):
        first_text, dash, last_text = port_part.partition('-')

        try:
            first_port = int(first_text)
            last_port = int(last_text) if dash else first_port
        except ValueError:
            raise argparse.ArgumentTypeError(
                f'bad port range {port_part!r} in {spec_text!r}')

        if not 1 <= first_port <= last_port <= MAX_PORT:
            raise argparse.ArgumentTypeError(
                f'port out of range: {port_part!r} in {spec_text!r}')

        ports.update(range(first_port, last_port + 1))

    return protocol, ports


def build_parser():
    parser = argparse.ArgumentParser(prog='portscan')
    parser.add_argument('--timeout', type=timeout_type, default=2.0)
    parser.add_argument('-j', '--num-threads', type=threads_type, default=1)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-g', '--guess', action='store_true')
    parser.add_argument('ip', type=ip_type)
    parser.add_argument("specs", nargs="*", type=spec_type, metavar="{tcp|udp}[/PORTS]")
    return parser


def parse_args(command_input=None):
    args = build_parser().parse_args(command_input)

    if not args.specs:
        targets = {"tcp": set(ALL_PORTS), "udp": set(ALL_PORTS)}
    else:
        targets = {}
        for proto, ports in args.specs:
            targets.setdefault(proto, set()).update(ports)

    return args, targets

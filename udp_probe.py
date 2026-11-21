from random import randint

from scapy.all import IP, UDP, ICMP, Raw, Packet, sr1

from constants import (
    MIN_SPORT,
    MAX_SPORT,
    ICMP_DEST_UNREACHABLE,
    ICMP_PORT_UNREACHABLE,
)
from dns_query import build_dns_query
from probe_result import ProbeResult, PortState


def udp_probe(ip: str, port: int, timeout: float) -> ProbeResult:
    request = build_udp_packet(ip, port)
    response = send_and_wait(request, timeout)
    state = classify_response(response)
    return ProbeResult("udp", port, state, None, None)


def build_udp_packet(ip: str, port: int) -> Packet:
    payload = build_dns_query(randint(0, 0xFFFF))
    return IP(dst=ip) / UDP(dport=port, sport=random_sport()) / Raw(load=payload)


def send_and_wait(request: Packet, timeout: float) -> Packet | None:
    return sr1(request, timeout=timeout, verbose=0)


def classify_response(response: Packet | None) -> PortState:
    if response is None:
        return PortState.FILTERED

    icmp_layer = response.getlayer(ICMP)
    if icmp_layer is not None:
        if (icmp_layer.type == ICMP_DEST_UNREACHABLE
                and icmp_layer.code == ICMP_PORT_UNREACHABLE):
            return PortState.CLOSED
        return PortState.FILTERED

    if response.haslayer(UDP):
        return PortState.OPEN

    return PortState.FILTERED


def random_sport() -> int:
    return randint(MIN_SPORT, MAX_SPORT)
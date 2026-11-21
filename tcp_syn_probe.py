from random import randint

from scapy.all import IP, TCP, Packet, send, sr

from constants import (
    MIN_SPORT,
    MAX_SPORT,
    SYN_FLAG,
    RST_FLAG,
    ACK_FLAG,
)
from probe_result import ProbeResult, PortState


def tcp_syn_probe(ip: str, port: int, timeout: float) -> ProbeResult:
    request = build_syn_packet(ip, port)
    exchange = send_and_wait(request, timeout)
    if exchange is None:
        return ProbeResult("tcp", port, PortState.FILTERED, None, None)

    sent_packet, response = exchange

    state = classify_response(response)
    elapsed_ms = None

    if state == PortState.OPEN:
        send_reset(response)
        elapsed_ms = get_elapsed_ms(sent_packet, response)

    return ProbeResult("tcp", port, state, elapsed_ms, None)


def build_syn_packet(ip: str, port: int) -> Packet:
    return IP(dst=ip) / TCP(dport=port, flags="S", sport=random_sport())


def send_and_wait(request: Packet, timeout: float) -> tuple[Packet, Packet] | None:
    answered, _ = sr(request, timeout=timeout, verbose=0)

    if len(answered) == 0:
        return None

    return answered[0]


def classify_response(response: Packet | None) -> PortState:
    tcp_layer = response.getlayer(TCP) if response is not None else None
    if tcp_layer is None:
        return PortState.FILTERED

    flags = int(tcp_layer.flags)

    if flags & RST_FLAG:
        return PortState.CLOSED

    syn_ack = SYN_FLAG | ACK_FLAG
    if flags & syn_ack == syn_ack:
        return PortState.OPEN

    return PortState.FILTERED


def send_reset(response: Packet) -> None:
    reset = IP(dst=response[IP].src) / TCP(
        sport=response[TCP].dport,
        dport=response[TCP].sport,
        seq=response[TCP].ack,
        flags="R",
    )
    send(reset, verbose=0)


def get_elapsed_ms(sent: Packet, response: Packet) -> float:
    return (response.time - sent.sent_time) * 1000


def random_sport() -> int:
    return randint(MIN_SPORT, MAX_SPORT)
import selectors
import socket
import time
from collections import deque
from dataclasses import dataclass
from random import randint

from scapy.all import ICMP, IP, TCP, UDP, Raw
from scapy.layers.inet import UDPerror

from constants import (
    EPOLL_WINDOW_SIZE,
    ICMP_DEST_UNREACHABLE,
    ICMP_PORT_UNREACHABLE,
    MAX_SPORT,
    MIN_SPORT,
    RAW_PACKET_SIZE,
    RAW_RECEIVE_BUFFER_BYTES,
)
from dns_query import build_dns_query
from probe_result import PortState, ProbeResult
from tcp_syn_probe import classify_response as classify_tcp_response


@dataclass(eq=False)
class PendingProbe:
    index: int
    protocol: str
    port: int
    sport: int
    sent_at: float
    deadline: float


class EpollScanner:
    def __init__(self, ip: str, timeout: float):
        self.ip = ip
        self.timeout = timeout
        self.selector = selectors.EpollSelector()
        self.send_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.receive_sockets = [
            self.open_receive_socket(socket.IPPROTO_TCP),
            self.open_receive_socket(socket.IPPROTO_UDP),
            self.open_receive_socket(socket.IPPROTO_ICMP),
        ]
        self.pending = {"tcp": {}, "udp": {}}
        self.deadlines = deque()
        self.results = {}
        self.next_sport = MIN_SPORT


    def __enter__(self):
        return self


    def __exit__(self, *exc_info):
        self.selector.close()
        self.send_socket.close()
        for receive_socket in self.receive_sockets:
            receive_socket.close()


    def scan(self, tasks: list[tuple[str, int]]) -> list[ProbeResult]:
        waiting = deque(enumerate(tasks))

        while waiting or self.in_flight():
            while waiting and self.in_flight() < EPOLL_WINDOW_SIZE:
                index, (protocol, port) = waiting.popleft()
                self.send_probe(index, protocol, port)

            for key, _ in self.selector.select(self.wait_time()):
                self.drain(key.fileobj)

            self.expire_probes()

        return [self.results[index] for index in range(len(tasks))]


    def open_receive_socket(self, protocol_number: int) -> socket.socket:
        receive_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, protocol_number)
        receive_socket.setblocking(False)
        receive_socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_RCVBUF, RAW_RECEIVE_BUFFER_BYTES)
        self.selector.register(receive_socket, selectors.EVENT_READ)
        return receive_socket


    def in_flight(self) -> int:
        return len(self.pending["tcp"]) + len(self.pending["udp"])


    def wait_time(self) -> float:
        if not self.deadlines:
            return 0.0
        return max(0.0, self.deadlines[0].deadline - time.monotonic())


    def allocate_sport(self) -> int:
        while True:
            sport = self.next_sport
            self.next_sport = MIN_SPORT if sport >= MAX_SPORT else sport + 1
            if sport not in self.pending["tcp"] and sport not in self.pending["udp"]:
                return sport


    def build_packet(self, protocol: str, port: int, sport: int):
        if protocol == "tcp":
            return IP(dst=self.ip) / TCP(dport=port, sport=sport, flags="S")
        payload = build_dns_query(randint(0, 0xFFFF))
        return IP(dst=self.ip) / UDP(dport=port, sport=sport) / Raw(load=payload)


    def send_packet(self, packet) -> bool:
        try:
            self.send_socket.sendto(bytes(packet), (self.ip, 0))
        except OSError:
            return False
        return True


    def send_probe(self, index: int, protocol: str, port: int) -> None:
        sport = self.allocate_sport()
        packet = self.build_packet(protocol, port, sport)
        now = time.monotonic()
        probe = PendingProbe(index, protocol, port, sport, now, now + self.timeout)

        self.pending[protocol][sport] = probe
        self.deadlines.append(probe)

        if not self.send_packet(packet):
            self.finish(probe, PortState.FILTERED)


    def send_reset(self, response) -> None:
        reset = IP(dst=self.ip) / TCP(
            sport=response[TCP].dport,
            dport=response[TCP].sport,
            seq=response[TCP].ack,
            flags="R",
        )
        self.send_packet(reset)


    def finish(self, probe: PendingProbe, state: PortState,
               elapsed_ms: float | None = None) -> None:
        self.pending[probe.protocol].pop(probe.sport, None)
        self.results[probe.index] = ProbeResult(
            probe.protocol, probe.port, state, elapsed_ms, None)


    def expire_probes(self) -> None:
        now = time.monotonic()
        while self.deadlines:
            probe = self.deadlines[0]
            if self.pending[probe.protocol].get(probe.sport) is not probe:
                self.deadlines.popleft()
            elif probe.deadline <= now:
                self.deadlines.popleft()
                self.finish(probe, PortState.FILTERED)
            else:
                return

    def drain(self, receive_socket: socket.socket) -> None:
        while True:
            try:
                data = receive_socket.recv(RAW_PACKET_SIZE)
            except BlockingIOError:
                return
            self.handle_packet(IP(data))


    def handle_packet(self, packet) -> None:
        if packet.src != self.ip:
            return

        icmp_layer = packet.getlayer(ICMP)
        if icmp_layer is not None:
            self.handle_icmp(icmp_layer)
            return

        tcp_layer = packet.getlayer(TCP)
        if tcp_layer is not None:
            self.handle_tcp(packet, tcp_layer)
            return

        udp_layer = packet.getlayer(UDP)
        if udp_layer is not None:
            self.handle_udp(udp_layer)


    def handle_tcp(self, packet, tcp_layer) -> None:
        probe = self.pending["tcp"].get(tcp_layer.dport)
        if probe is None or probe.port != tcp_layer.sport:
            return

        state = classify_tcp_response(packet)
        if state == PortState.FILTERED:
            return

        elapsed_ms = None
        if state == PortState.OPEN:
            self.send_reset(packet)
            elapsed_ms = (time.monotonic() - probe.sent_at) * 1000
        self.finish(probe, state, elapsed_ms)


    def handle_udp(self, udp_layer) -> None:
        probe = self.pending["udp"].get(udp_layer.dport)
        if probe is None or probe.port != udp_layer.sport:
            return
        self.finish(probe, PortState.OPEN)


    def handle_icmp(self, icmp_layer) -> None:
        if icmp_layer.type != ICMP_DEST_UNREACHABLE:
            return

        original = icmp_layer.getlayer(UDPerror)
        if original is None:
            return

        probe = self.pending["udp"].get(original.sport)
        if probe is None or probe.port != original.dport:
            return

        if icmp_layer.code == ICMP_PORT_UNREACHABLE:
            self.finish(probe, PortState.CLOSED)
        else:
            self.finish(probe, PortState.FILTERED)
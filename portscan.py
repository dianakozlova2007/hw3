from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Iterator

from app_protocol import detect_app_protocol
from constants import NO_VALUE
from epoll_parallel import EpollScanner
from probe_result import PortState, ProbeResult
from tcp_syn_probe import tcp_syn_probe
from udp_probe import udp_probe

PROBES = {
    "tcp": tcp_syn_probe,
    "udp": udp_probe,
}


def scan_ports(ip: str, ports_by_protocol: dict[str, set[int]], timeout: float,
               guess: bool, num_threads: int) -> Iterator[ProbeResult]:
    tasks = build_tasks(ports_by_protocol)

    if num_threads > 1:
        yield from scan_with_threads(ip, tasks, timeout, guess, num_threads)
    else:
        yield from scan_with_epoll(ip, tasks, timeout, guess)


def build_tasks(ports_by_protocol: dict[str, set[int]]) -> list[tuple[str, int]]:
    return [
        (protocol, port)
        for protocol, ports in ports_by_protocol.items()
        for port in sorted(ports)
    ]


def scan_with_threads(ip: str, tasks: list[tuple[str, int]], timeout: float,
                      guess: bool, num_threads: int) -> Iterator[ProbeResult]:
    def scan_task(task: tuple[str, int]) -> ProbeResult | None:
        protocol, port = task
        result = PROBES[protocol](ip, port, timeout)
        if result.state != PortState.OPEN:
            return None
        return with_app_protocol(ip, result, timeout, guess)

    executor = ThreadPoolExecutor(max_workers=num_threads)
    try:
        for result in executor.map(scan_task, tasks):
            if result is not None:
                yield result
    finally:
        executor.shutdown(wait=False, cancel_futures=True)


def scan_with_epoll(ip: str, tasks: list[tuple[str, int]], timeout: float,
                    guess: bool) -> Iterator[ProbeResult]:
    with EpollScanner(ip, timeout) as scanner:
        results = scanner.scan(tasks)

    for result in results:
        if result.state == PortState.OPEN:
            yield with_app_protocol(ip, result, timeout, guess)


def with_app_protocol(ip: str, result: ProbeResult, timeout: float,
                      guess: bool) -> ProbeResult:
    if not guess:
        return result
    app_protocol = detect_app_protocol(ip, result.port, result.protocol, timeout)
    return replace(result, app_protocol=app_protocol)


def format_result(result: ProbeResult, verbose: bool, guess: bool) -> str:
    columns = [result.protocol.upper(), str(result.port)]

    if verbose:
        columns.append(format_elapsed(result.elapsed_ms))
    if guess:
        columns.append(result.app_protocol or NO_VALUE)

    return " ".join(columns)


def format_elapsed(elapsed_ms: float | None) -> str:
    if elapsed_ms is None:
        return NO_VALUE

    return str(round(elapsed_ms))
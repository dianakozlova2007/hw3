import socket
from random import randint
from secrets import token_hex
from dns_query import build_dns_query

from constants import (
    RECEIVE_BUFFER_SIZE,
    HTTP_REQUEST,
    HTTP_RESPONSE_PREFIX,
    TCP_LENGTH_PREFIX_SIZE,
    ECHO_PAYLOAD_PREFIX,
    DNS_HEADER_SIZE,
    DNS_RESPONSE_BIT,
)


def detect_app_protocol(ip: str, port: int, transport: str, timeout: float) -> str | None:
    checks = (
        ("HTTP", is_http),
        ("DNS", is_dns),
        ("ECHO", is_echo),
    )
    for protocol_name, check in checks:
        if check(ip, port, transport, timeout):
            return protocol_name

    return None


def send_and_receive(ip: str, port: int, transport: str, payload: bytes, timeout: float) -> bytes | None:
    socket_type = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM

    try:
        with socket.socket(socket.AF_INET, socket_type) as connection:
            connection.settimeout(timeout)

            if transport == "tcp":
                connection.connect((ip, port))
                connection.sendall(payload)
            else:
                connection.sendto(payload, (ip, port))

            data = connection.recv(RECEIVE_BUFFER_SIZE)
    except OSError:
        return None

    return data or None


def is_http(ip: str, port: int, transport: str, timeout: float) -> bool:
    if transport != "tcp":
        return False

    response = send_and_receive(ip, port, transport, HTTP_REQUEST, timeout)
    return response is not None and response.startswith(HTTP_RESPONSE_PREFIX)


def is_dns(ip: str, port: int, transport: str, timeout: float) -> bool:
    query_id = randint(0, 0xFFFF)
    query = build_dns_query(query_id)

    if transport == "tcp":
        query = len(query).to_bytes(TCP_LENGTH_PREFIX_SIZE, "big") + query

    response = send_and_receive(ip, port, transport, query, timeout)

    if response is None:
        return False
    if transport == "tcp":
        response = response[TCP_LENGTH_PREFIX_SIZE:]

    return is_dns_response_to(response, query_id)


def is_echo(ip: str, port: int, transport: str, timeout: float) -> bool:
    payload = (ECHO_PAYLOAD_PREFIX + token_hex(8)).encode()
    response = send_and_receive(ip, port, transport, payload, timeout)
    return response == payload


def is_dns_response_to(data: bytes, query_id: int) -> bool:
    if len(data) < DNS_HEADER_SIZE:
        return False

    response_id = int.from_bytes(data[:2], "big")
    is_response = bool(data[2] & DNS_RESPONSE_BIT)
    return response_id == query_id and is_response

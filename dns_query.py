from scapy.layers.dns import DNS, DNSQR
from constants import DNS_QUERY_NAME


def build_dns_query(query_id: int) -> bytes:
    return bytes(DNS(id=query_id, rd=1, qd=DNSQR(qname=DNS_QUERY_NAME)))
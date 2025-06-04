import random
import threading
import time
from scapy.all import IP, TCP, send, RandShort, RandInt, sniff
from math import gcd
from functools import reduce
from datetime import datetime
import copy

# Here we have our tcp probes we sent agains machine
tcp_probes = [
    TCP(
        sport=RandShort(),
        dport=80,
        flags="S",
        seq=RandInt(),
        window=1,
        options=[
            ("WScale", 10),
            ("NOP", None),
            ("MSS", 1460),
            ("Timestamp", (0xFFFFFFFF, 0)),
            ("SAckOK", b""),
        ],
    ),
    TCP(
        sport=RandShort(),
        dport=80,
        flags="S",
        seq=RandInt(),
        window=63,
        options=[
            ("MSS", 1400),
            ("WScale", 0),
            ("SAckOK", b""),
            ("Timestamp", (0xFFFFFFFF, 0)),
            ("EOL", None),
        ],
    ),
    TCP(
        sport=RandShort(),
        dport=80,
        flags="S",
        seq=RandInt(),
        window=4,
        options=[
            ("Timestamp", (0xFFFFFFFF, 0)),
            ("NOP", None),
            ("NOP", None),
            ("WScale", 5),
            ("NOP", None),
            ("MSS", 640),
        ],
    ),
    TCP(
        sport=RandShort(),
        dport=80,
        flags="S",
        seq=RandInt(),
        window=4,
        options=[
            ("SAckOK", b""),
            ("Timestamp", (0xFFFFFFFF, 0)),
            ("WScale", 10),
            ("EOL", None),
        ],
    ),
    TCP(
        sport=RandShort(),
        dport=80,
        flags="S",
        seq=RandInt(),
        window=16,
        options=[
            ("MSS", 536),
            ("SAckOK", b""),
            ("Timestamp", (0xFFFFFFFF, 0)),
            ("WScale", 10),
            ("EOL", None),
        ],
    ),
    TCP(
        sport=RandShort(),
        dport=80,
        flags="S",
        seq=RandInt(),
        window=512,
        options=[("MSS", 265), ("SAckOK", b""), ("Timestamp", (0xFFFFFFFF, 0))],
    ),
]


def init_sport(tcp_probes: list):
    first_sport = random.randint(2 * 10, 2**16 - 2**10)
    last_sport = first_sport
    for tcp_prob in tcp_probes:
        tcp_prob.sport = last_sport
        last_sport += random.randint(2**4, 2**6)
    return tcp_probes


def scan_os(dst_ip):
    if not dst_ip:
        return None

    ip = IP(dst=dst_ip)
    tcp_responses = []
    seq_rates = []

    pck_sent_time = {}
    diff1 = []

    loc_tcp_probes = init_sport([copy.deepcopy(tcp_prob) for tcp_prob in tcp_probes])

    def sniff_responses():
        nonlocal tcp_responses
        tcp_responses = sniff(filter=f"tcp and src host {dst_ip}", timeout=3)

    sniffer_thread = threading.Thread(target=sniff_responses)
    sniffer_thread.start()

    for tcp_res in loc_tcp_probes:
        send(ip / tcp_res, verbose=False)
        time.sleep(0.1)
        pck_sent_time[tcp_res.sport] = datetime.now()

    sniffer_thread.join()

    tcp_responses = sorted(tcp_responses, key=lambda tcp_res: tcp_res.dport)

    print(pck_sent_time)
    for pkt in tcp_responses:
        print(f"{pkt[TCP]} {pkt[TCP].dport}")

    for i in range(1, len(tcp_responses)):
        tcp_res = tcp_responses[i][TCP]
        prev_tcp_res = tcp_responses[i - 1][TCP]
        if prev_tcp_res.seq > tcp_res.seq:
            diff1.append(
                min(
                    prev_tcp_res.seq - tcp_res.seq,
                    (tcp_res.seq + (2**32 - prev_tcp_res.seq)),
                )
            )
        else:
            diff1.append(tcp_res.seq - prev_tcp_res.seq)

        sent_diff = (
            pck_sent_time[tcp_res.dport] - pck_sent_time[prev_tcp_res.dport]
        ).total_seconds()
        print(sent_diff)
        seq_rates.append(diff1[i - 1] / sent_diff)

    print(diff1)
    print(seq_rates)
    print(reduce(gcd, diff1))


def main():
    scan_os("192.168.0.1")


if __name__ == "__main__":
    main()

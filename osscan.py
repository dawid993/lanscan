from scapy.all import IP, TCP, sr1, RandShort, RandInt
from math import gcd
from functools import reduce

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


def scan_os(dst_ip):
    if not dst_ip:
        return None

    ip = IP(dst=dst_ip)
    tcp_res = []

    for tcp_pck in tcp_probes:
        tcp_res.append(sr1(ip / tcp_pck, timeout=0.1))

    diff1 = []

    for i in range(1, len(tcp_probes)):
        tcp_probe = tcp_res[i][TCP]
        prev_tcp_probe = tcp_res[i - 1][TCP]
        # print(tcp_probe.seq, prev_tcp_probe.seq)
        if prev_tcp_probe.seq > tcp_probe.seq:
            diff1.append(
                min(
                    prev_tcp_probe.seq - tcp_probe.seq,
                    (tcp_probe.seq + (2**32 - prev_tcp_probe.seq)),
                )
            )
        else:
            diff1.append(tcp_probe.seq - prev_tcp_probe.seq)

    print(diff1)
    print(reduce(gcd, diff1))


def main():
    scan_os("192.168.0.1")


if __name__ == "__main__":
    main()

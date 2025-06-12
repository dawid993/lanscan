import math
import random
import statistics
import threading
import time
from scapy.all import IP, TCP, send, RandShort, RandInt, sniff, ICMP, Raw, sr1, UDP
from math import gcd
from functools import reduce
from datetime import datetime
import copy

# Here we have our tcp probes we sent agains machine
seq_gen_tcp_probes = [
    TCP(
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
        flags="S",
        seq=RandInt(),
        window=512,
        options=[("MSS", 265), ("SAckOK", b""), ("Timestamp", (0xFFFFFFFF, 0))],
    ),
]

icmp_probes = [
    IP(flags="DF", tos=0)
    / ICMP(type=8, code=9, seq=295)
    / Raw(load=bytes([0x00] * 120)),
    IP(flags="DF", tos=4)
    / ICMP(type=8, code=0, seq=295)
    / Raw(load=bytes([0x00] * 150)),
]

ecn_tcp_probe = TCP(
    sport=RandShort(),  # Random source port
    dport=80,  # Target open port
    flags=0xC2,  # SYN + ECE + CWR
    seq=RandInt(),
    ack=0,
    window=3,
    urgptr=0xF7F5,  # URG pointer set but URG flag NOT set
    reserved=1,  # Set 1 bit before CWR (RFC 3168)
    options=[
        ("WScale", 10),
        ("NOP", None),
        ("MSS", 1460),
        ("SAckOK", b""),
        ("NOP", None),
        ("NOP", None),
    ],
)

udp_probe = UDP(sport=RandShort(), dport=80) / Raw(load=b"C" * 300)

_DEBUG_ENABLED = True


def scan_os(dst_ip, dst_port):
    if not dst_ip or not dst_port:
        return None

    ip = IP(dst=dst_ip)

    tcp_responses, pck_sent_time = run_tcp_seq_probes(seq_gen_tcp_probes, dst_ip, dst_port)
    diff1, seq_rates = calc_diff_and_seq_rates(tcp_responses, pck_sent_time)

    icmp_responses = run_icmp_probes(icmp_probes, dst_ip)

    ecn_tcp_response = sr1(ip / ecn_tcp_probe, timeout=2)
    udp_response = sr1(IP(dst=dst_ip, id=0x1042) / udp_probe)

    if _DEBUG_ENABLED:
        log_tcp_responses(tcp_responses, pck_sent_time)
        log_final_results(seq_rates, diff1)
        print(icmp_responses)
        print(ecn_tcp_response.show())
        print(udp_response.show())

    gcd = calc_gcd(diff1)
    return gcd, calc_isr(seq_rates), calc_sp(seq_rates, gcd)


def run_tcp_seq_probes(tcp_probes, dst_ip, dst_port):
    pck_sent_time = {}
    tcp_responses = []

    loc_tcp_probes = init_seq_tcp_ports([copy.deepcopy(tcp_prob) for tcp_prob in tcp_probes], dst_port)

    def sniff_responses():
        nonlocal tcp_responses
        tcp_responses = sniff(filter=f"tcp and src host {dst_ip}", timeout=3)

    sniffer_thread = threading.Thread(target=sniff_responses)
    sniffer_thread.start()

    ip = IP(dst=dst_ip)
    for tcp_res in loc_tcp_probes:
        send(ip / tcp_res, verbose=False)
        time.sleep(0.1)
        pck_sent_time[tcp_res.sport] = datetime.now()

    sniffer_thread.join()

    tcp_responses = sorted(tcp_responses, key=lambda tcp_res: tcp_res.dport)

    return tcp_responses, pck_sent_time


# In order to track tcp probes we relay on source ports
# We choose port between 1024 and 64512 and increment after each loop by 32 up to 64
def init_seq_tcp_ports(tcp_probes: list, dst_port):
    first_sport = random.randint(2 * 10, 2**16 - 2**10)
    last_sport = first_sport
    for tcp_prob in tcp_probes:
        tcp_prob.sport = last_sport
        tcp_prob.dport = dst_port
        last_sport += random.randint(2**4, 2**6)
    return tcp_probes


def init_icmp_probes(icmp_probes: list, dst_ip):
    loc_icmp_probes = [copy.deepcopy(icmp_probe) for icmp_probe in icmp_probes]
    if len(loc_icmp_probes) < 2:
        raise ValueError("Should be 2 icmp probes")

    ip_id = RandShort()
    icmp_id = RandShort()

    loc_icmp_probes[0][IP].dst = dst_ip
    loc_icmp_probes[0][IP].id = ip_id
    loc_icmp_probes[0][ICMP].id = icmp_id

    loc_icmp_probes[1][IP].dst = dst_ip
    loc_icmp_probes[1][ICMP].id = icmp_id + 1
    loc_icmp_probes[1][ICMP].seq = loc_icmp_probes[0][ICMP].seq + 1

    return loc_icmp_probes


def calc_diff_and_seq_rates(tcp_responses, pck_sent_time):
    seq_rates = []
    diff1 = []

    for tcp_res, prev_tcp_res in zip(tcp_responses[1:], tcp_responses):
        dif1_v = (
            calc_min_diff(tcp_res[TCP], prev_tcp_res[TCP])
            if prev_tcp_res[TCP].seq > tcp_res[TCP].seq
            else tcp_res.seq - prev_tcp_res.seq
        )
        sent_diff = calc_time_diff(pck_sent_time, tcp_res, prev_tcp_res)
        seq_rates.append(dif1_v / sent_diff)
        diff1.append(dif1_v)

    return diff1, seq_rates


def run_icmp_probes(icmp_probes, dst_ip):
    icmp_responses = []
    loc_icmp_probes = init_icmp_probes(
        [copy.deepcopy(tcp_prob) for tcp_prob in icmp_probes], dst_ip
    )

    for icmp_probe in loc_icmp_probes:
        icmp_responses.append(sr1(icmp_probe, timeout=2))

    return icmp_responses


def log_final_results(seq_rates, diff1):
    print(diff1)
    print(seq_rates)


# If interval between request is small then both sends can be the same.
# Then we can have 0 what breaks division
def calc_time_diff(pck_sent_time, tcp_res, prev_tcp_res):
    return max(
        (
            pck_sent_time[tcp_res.dport] - pck_sent_time[prev_tcp_res.dport]
        ).total_seconds(),
        1e-6,
    )


def calc_min_diff(tcp_res, prev_tcp_res):
    return min(
        prev_tcp_res.seq - tcp_res.seq,
        (tcp_res.seq + (2**32 - prev_tcp_res.seq)),
    )


def log_tcp_responses(tcp_responses, pck_sent_time):
    print(f"pck = {pck_sent_time}")
    for pkt in tcp_responses:
        print(f"{pkt[TCP]} {pkt[TCP].dport}")


def calc_gcd(diff1):
    return reduce(gcd, diff1)


def calc_isr(seq_rates):
    avg = sum(seq_rates) / len(seq_rates) if seq_rates else 0
    return 0 if avg < 1 else round(8 * math.log2(avg))


def calc_sp(seq_rates, gcd):
    loc_seq_rates = [e / gcd for e in seq_rates] if gcd > 0 else seq_rates
    stdev = statistics.stdev(loc_seq_rates)
    return 0 if stdev <= 1 else round(8 * math.log2(stdev))


def main():
    print(scan_os("192.168.50.1", 80))


if __name__ == "__main__":
    main()

import math
import random
import statistics
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

_DEBUG_ENABLED = True

# In order to track tcp probes we relay on source ports
# We choose port between 1024 and 64512 and increment after each loop by 32 up to 64
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
    pck_sent_time = {}

    seq_rates = []
    diff1 = []

    # If we need tcp_probes later want to assert we have clean copy
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
    
    if _DEBUG_ENABLED:
        log_tcp_responses(tcp_responses, pck_sent_time)

    for tcp_res, prev_tcp_res in zip(tcp_responses[1:], tcp_responses):
        dif1_v = (
            calc_min_diff(tcp_res[TCP], prev_tcp_res[TCP])
            if prev_tcp_res[TCP].seq > tcp_res[TCP].seq
            else tcp_res.seq - prev_tcp_res.seq
        )
        sent_diff = calc_time_diff(pck_sent_time, tcp_res, prev_tcp_res)
        seq_rates.append(dif1_v / sent_diff)
        diff1.append(dif1_v)

    if _DEBUG_ENABLED:
        log_final_results(seq_rates, diff1)
    
    gcd = calc_gcd(diff1)
    return gcd, calc_isr(seq_rates),calc_sp(seq_rates, gcd)
    

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
    print(pck_sent_time)
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
    print(scan_os("192.168.55.1"))


if __name__ == "__main__":
    main()

from scapy.all import *
import random
import numpy as np

DST_IP = "192.168.122.2"
DST_PORT = 80

NUM_IPS = 256
PORTS_PER_IP = 1024
PKTS_PER_PORT = 150

MEAN_SIZE = 1500
MIN_SIZE = 300
MAX_SIZE = 1500

pcap_packets = []

def generate_ips(n):
    ips = []
    for i in range(n):
        a = 172
        b = (i >> 16) & 0xff
        c = (i >> 8) & 0xff
        d = i & 0xff
        ips.append(f"{a}.{b}.{c}.{d}")
    return ips

def truncated_normal(mean, min_v, max_v):
    while True:
        v = int(np.random.normal(mean, (max_v - min_v) / 6))
        if min_v <= v <= max_v:
            return v

def build_http(method, size):
    base = f"{method} /index.html HTTP/1.1\r\nHost: {DST_IP}\r\nUser-Agent: DOS-SIM\r\n\r\n"
    padding_len = max(0, size - len(base))
    return base.encode() + b"A" * padding_len

src_ips = generate_ips(NUM_IPS)

for src_ip in src_ips:
    ports = random.sample(range(1024, 65535), PORTS_PER_IP)

    for sport in ports:
        methods = ["GET"] * 50 + ["POST"] * 50 + ["HEAD"] * 50
        random.shuffle(methods)

        for method in methods:
            pkt_size = truncated_normal(MEAN_SIZE, MIN_SIZE, MAX_SIZE)

            payload_size = max(0, pkt_size - 54)

            payload = build_http(method, payload_size)

            pkt = (
                Ether(src="f4:52:14:3e:dd:60", dst="f4:52:14:88:bf:e0") /
                IP(src=src_ip, dst=DST_IP) /
                TCP(sport=sport, dport=DST_PORT, flags="PA", seq=random.randint(0, 2**32)) /
                Raw(load=payload)
            )

            wrpcap("new_dataset.pcap", pkt, append=True)



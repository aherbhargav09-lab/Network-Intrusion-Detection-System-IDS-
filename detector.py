from collections import defaultdict
from logger import log_alert

icmp_count = defaultdict(int)
syn_count = defaultdict(int)

ICMP_THRESHOLD = 20
SYN_THRESHOLD = 20

def detect(packet):

    if packet.haslayer("IP"):

        src_ip = packet["IP"].src

        # ICMP Flood Detection
        if packet.haslayer("ICMP"):
            icmp_count[src_ip] += 1

            if icmp_count[src_ip] > ICMP_THRESHOLD:
                log_alert(
                    f"ICMP Flood Detected from {src_ip}"
                )

        # SYN Flood Detection
        if packet.haslayer("TCP"):

            if packet["TCP"].flags == "S":

                syn_count[src_ip] += 1

                if syn_count[src_ip] > SYN_THRESHOLD:
                    log_alert(
                        f"SYN Flood Detected from {src_ip}"
                    )

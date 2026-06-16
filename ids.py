from scapy.all import sniff
from detector import detect

print("=" * 50)
print(" Network Intrusion Detection System ")
print("=" * 50)

print("Monitoring Started...\n")

sniff(
    prn=detect,
    store=False
)

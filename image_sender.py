from scapy.all import *
import base64
import time

RECEIVER_IP = "106.51.217.12"  # Laptop IP
RECEIVER_ID = 0xABCD
CHUNK_SIZE = 32
ack_received = False

# Step 1: Send handshake
print("[*] Sending handshake ping...")
send(IP(dst=RECEIVER_IP)/ICMP(type=8, id=RECEIVER_ID, seq=9999), verbose=0)

def sniff_ack(pkt):
    global ack_received
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        if icmp.type == 0 and icmp.id == RECEIVER_ID and icmp.seq == 9998:
            print("[*] Handshake ACK received.")
            ack_received = True

print("[*] Waiting for ACK...")
sniff(filter=f"icmp and host {RECEIVER_IP}", prn=sniff_ack, timeout=10)

if not ack_received:
    print("[!] No ACK. Remote's not home.")
    exit()

# Step 2: Load image and split
print("[*] Preparing image...")
with open("image.jpg", "rb") as f:
    image_data = f.read()

b64_data = base64.b64encode(image_data)
chunks = [b64_data[i:i+CHUNK_SIZE] for i in range(0, len(b64_data), CHUNK_SIZE)]
print(f"[+] Split into {len(chunks)} chunks.")

# Step 3: Send chunks
print("[*] Sending image chunks...")
for i, chunk in enumerate(chunks):
    pkt = IP(dst=RECEIVER_IP) / ICMP(type=0, id=0x1234, seq=i) / Raw(load=chunk)
    send(pkt, verbose=0)
    print(f"[>] Sent chunk {i}")
    time.sleep(0.2)  # Give the receiver some breathing room

print("[+] All chunks sent. Cheers, mate.")

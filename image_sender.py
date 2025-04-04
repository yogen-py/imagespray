from scapy.all import *
import base64
import time

# ========================
# SETTINGS
# ========================
RECEIVER_IP = "106.51.217.12"  # <-- Put your laptop's IP here
RECEIVER_ID = 0xABCD
CHUNK_SIZE = 32  # Tune based on MTU, 32 is safe as mum's kitchen

# ========================
# Step 1: HANDSHAKE
# ========================
print("[*] Sending handshake ping...")
send(IP(dst=RECEIVER_IP)/ICMP(type=8, id=RECEIVER_ID, seq=9999), verbose=0)

print("[*] Waiting for handshake ACK...")
ack_received = False

def sniff_ack(pkt):
    global ack_received
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        if icmp.type == 0 and icmp.id == RECEIVER_ID and icmp.seq == 9998:
            print("[*] Handshake ACK received.")
            ack_received = True

sniff(filter=f"icmp and host {RECEIVER_IP}", prn=sniff_ack, timeout=10)

if not ack_received:
    print("[!] No ACK. Remote's ghostin'. Exiting.")
    exit()

print("[+] Receiver's up. Beginning image spray in 3 seconds...")
time.sleep(3)

# ========================
# Step 2: IMAGE LOADING
# ========================
print("[*] Loading image and converting to base64...")

with open("image.jpg", "rb") as f:
    image_data = f.read()

b64_data = base64.b64encode(image_data)

chunks = [b64_data[i:i+CHUNK_SIZE] for i in range(0, len(b64_data), CHUNK_SIZE)]
print(f"[+] Split image into {len(chunks)} chunks of {CHUNK_SIZE} bytes.")

# ========================
# Step 3: SENDING CHUNKS
# ========================
for i, chunk in enumerate(chunks):
    pkt = IP(dst=RECEIVER_IP) / ICMP(type=0, id=0x1234, seq=i) / Raw(load=chunk)
    send(pkt, verbose=0)
    print(f"[>] Sent chunk {i}/{len(chunks)}")
    time.sleep(0.2)  # Optional delay, prevents overwhelming the receiver

print("[+] Image spray complete. Time for a pint.")

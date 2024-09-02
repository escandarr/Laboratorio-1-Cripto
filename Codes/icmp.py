import sys
import time
import struct
import scapy.all as scapy
from cesar import cifrardo_cesar

id_ipv4 = id_icmp = scapy.RandShort()

try:
    with open("identifier.txt", "r") as file:
        id_icmp = int(file.read())
except FileNotFoundError:
    id_icmp = 1

with open("identifier.txt", "w") as file:
    file.write(str(id_icmp + 1))

timestamp = struct.pack("<Q", int(time.time()))

data_icmp = scapy.ICMP(id=0, seq=0).build()

icmp_ping = bytes(range(0x10, 0x38))

if len(sys.argv) != 4:
    print("Uso: python3 icmp_cesar.py <IP_destino> <mensaje> <corrimiento>")
    sys.exit(1)

ip_destino = sys.argv[1]
mensaje = sys.argv[2]
corrimiento = int(sys.argv[3])
mensaje_cifrado = cifrardo_cesar(mensaje, corrimiento)

packets = []
for i, caracter in enumerate(mensaje_cifrado):
    payload = timestamp + data_icmp + icmp_ping + caracter.encode()
    packet = scapy.IP(dst=ip_destino, id=id_ipv4, flags="DF") / scapy.ICMP(id=id_icmp, seq=i + 1) / payload
    packets.append(packet)

scapy.send(packets)

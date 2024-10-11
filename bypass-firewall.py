# https://stackoverflow.com/questions/52433778/using-scapy-to-send-fragment-packets-with-random-offsets
# https://programtalk.com/python-examples/scapy.all.fragment/
# https://nmap.org/book/man-bypass-firewalls-ids.html
# https://scapy.readthedocs.io/en/latest/
# https://www.eit.lth.se/ppplab/IPHeader.htm#Flags
# https://github.com/Gajasurve/CurrentRead/blob/master/Attacking-Network-Protocols-A-Hacker-s-Guide-to-Capture-Analysis-and-Exploitation.pdf
import argparse
import os
import sys

from datetime import datetime

#import pyfiglet
from scapy.config import conf
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import TCP, IP, fragment, UDP
from scapy.packet import Raw
from scapy.sendrecv import sr, sr1
from scapy.themes import BrightTheme
from scapy.volatile import RandShort, RandMAC

conf.verb = 0
conf.color_theme = BrightTheme()

# FLAGS
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

"""
Enviando Pacotes
sr() - Envia pacotest na L3, e fica agauardadndo respostas
sr1() - Envia pacotes na L3, finaliza conexao na primeira resposta
srp() - envia pacotes na L2, e fica aguardandado respostas
srp1() - envia pacotes na L2, finaliza conex~ao na primeira resposta
srloop() - envia e recebe pacotes em loop , L3
srploop() - envia e recebe pacotes em loop,L2
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
"""


class Firewall:
    def __init__(self, ip, sport, ttl, flags, intervalo, payload):
        self.ip = ip
        self.sport = sport
        self.ttl = ttl
        self.flags = flags
        self.intervalo = intervalo
        self.payload = payload

    def __str__(self):
        return f"{type(self.ip)}  {type(self.sport)} ||{self.ttl}|{self.flags}|{self.intervalo}"

    def scan(self):
        pacote, p = sr(IP(dst=self.ip, ttl=self.ttl) / TCP(sport=self.sport,
                                                           dport=[22, 23, 25, 80, 110, 125, 443, 8080, 8000 ],
                                                           flags=self.flags,
                                                           options=[('Timestamp', (0, 0))]),

                       inter=self.intervalo,

                       timeout=5,
                       )  

        for s, r in pacote:
            print(f"{s[TCP].dport}| {r[TCP].flags} | {r[IP].src} | {r[TCP].haslayer(Raw)} | {r[TCP].payload}")

        return pacote


s = Firewall('localhost', 80, 254, 0x02, 2, '%%{{,<sCriPT AlerT() %%/>')
print(s.scan())

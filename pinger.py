#!/usr/bin/env python3

import argparse
import logging
import subprocess
import sys

logging.getLogger("scapy").setLevel(logging.CRITICAL)

import scapy.all as sc

routing_options = [
    "RR",
    "RR-same",
    "RR-trunc",
    "LSRR",
    "LSRR-trunc",
    "SSRR",
    "SSRR-trunc",
]


def parse_args():
    parser = argparse.ArgumentParser(
        prog="pinger.py",
        description="P I N G E R",
        epilog="This utility creates a tun interface, "
        "sends an echo request, and forges the reply.",
    )
    # Required arguments
    # Avoid setting defaults on these arguments,
    # as we want to set them explicitly in the tests
    parser.add_argument(
        "--iface", type=str, required=True, help="Interface to send packet to"
    )
    parser.add_argument(
        "--src", type=str, required=True, help="Source packet IP"
    )
    parser.add_argument(
        "--dst", type=str, required=True, help="Destination packet IP"
    )
    parser.add_argument(
        "--icmp_type", type=int, required=True, help="ICMP type"
    )
    parser.add_argument(
        "--icmp_code", type=int, required=True, help="ICMP code"
    )
    # IP arguments
    parser.add_argument("--ihl", type=int, default=None, help="IHL")
    parser.add_argument(
        "--flags", type=str, default="", choices=["DF", "MF"], help="IP flags"
    )
    parser.add_argument(
        "--opts",
        type=str,
        default="",
        choices=["EOL", "NOP", "NOP-40", "unk", "unk-40"] + routing_options,
        help="Include IP options",
    )
    parser.add_argument(
        "--special",
        type=str,
        default="",
        choices=["no-payload", "tcp", "udp", "wrong", "warp", "every-other"],
        help="Send a special packet",
    )
    parser.add_argument(
        "--oip_ihl",
        type=int,
        default=None,
        help="Inner packet IHL",
    )
    # ICMP arguments
    # Match names with <netinet/ip_icmp.h>
    parser.add_argument(
        "--icmp_pptr", type=int, default=0, help="ICMP pointer"
    )
    parser.add_argument(
        "--icmp_gwaddr",
        type=str,
        default="0.0.0.0",
        help="ICMP gateway IP address",
    )
    parser.add_argument(
        "--icmp_nextmtu", type=int, default=0, help="ICMP next MTU"
    )
    parser.add_argument(
        "--icmp_otime", type=int, default=0, help="ICMP originate timestamp"
    )
    parser.add_argument(
        "--icmp_rtime", type=int, default=0, help="ICMP receive timestamp"
    )
    parser.add_argument(
        "--icmp_ttime", type=int, default=0, help="ICMP transmit timestamp"
    )
    parser.add_argument(
        "--icmp_mask", type=str, default="0.0.0.0", help="ICMP address mask"
    )
    parser.add_argument(
        "--request",
        type=str,
        default="",
        choices=["mask", "timestamp"],
        help="Request type",
    )
    # Miscellaneous arguments
    parser.add_argument(
        "--count", type=int, default=1, help="Number of packets to send"
    )
    parser.add_argument("--dup", action="store_true", help="Duplicate packets")
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")

    return parser.parse_args()


def build_response_packet(echo, ip, icmp, oip_ihl, special):
    icmp_id_seq_types = [0, 8, 13, 14, 15, 16, 17, 18, 37, 38]
    oip = echo[sc.IP]
    oicmp = echo[sc.ICMP]
    load = echo[sc.ICMP].payload
    oip[sc.IP].remove_payload()
    oicmp[sc.ICMP].remove_payload()
    oicmp.type = 8

    # As if the original IP packet had these set
    oip.ihl = None
    oip.len = None
    oip.id = 1
    oip.flags = ip.flags
    oip.chksum = None
    oip.options = ip.options

    # Inner packet (oip) options
    if oip_ihl:
        oip.ihl = oip_ihl

    # Special options
    if special == "every-other" and icmp.seq % 2:
        # Respond badly every other package
        return sc.IP() / sc.ICMP()
    if special == "no-payload":
        load = ""
    if special == "tcp":
        oip.proto = "tcp"
        tcp = sc.TCP(sport=1234, dport=5678)
        return ip / icmp / oip / tcp
    if special == "udp":
        oip.proto = "udp"
        udp = sc.UDP(sport=1234, dport=5678)
        return ip / icmp / oip / udp
    if special == "warp":
        # Build a package with a timestamp of INT_MAX
        # (time-warped package)
        payload_no_timestamp = sc.bytes_hex(load)[16:]
        load = (b"\xff" * 8) + sc.hex_bytes(payload_no_timestamp)
    if special == "wrong":
        # Build a package with a wrong last byte
        payload_no_last_byte = sc.bytes_hex(load)[:-2]
        load = (sc.hex_bytes(payload_no_last_byte)) + b"\x00"

    if icmp.type in icmp_id_seq_types:
        pkt = ip / icmp / load
    else:
        ip.options = ""
        pkt = ip / icmp / oip / oicmp / load
    return pkt


def generate_ip_options(opts):
    if not opts:
        return ""

    routers = [
        "192.0.2.10",
        "192.0.2.20",
        "192.0.2.30",
        "192.0.2.40",
        "192.0.2.50",
        "192.0.2.60",
        "192.0.2.70",
        "192.0.2.80",
        "192.0.2.90",
    ]
    routers_zero = [0, 0, 0, 0, 0, 0, 0, 0, 0]
    if opts == "EOL":
        options = sc.IPOption(b"\x00")
    elif opts == "NOP":
        options = sc.IPOption(b"\x01")
    elif opts == "NOP-40":
        options = sc.IPOption(b"\x01" * 40)
    elif opts == "RR":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption_RR(pointer=40, routers=routers)
    elif opts == "RR-same":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption_RR(pointer=3, routers=routers_zero)
    elif opts == "RR-trunc":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption_RR(length=7, routers=routers_zero)
    elif opts == "LSRR":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption_LSRR(routers=routers)
    elif opts == "LSRR-trunc":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption_LSRR(length=3, routers=routers_zero)
    elif opts == "SSRR":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption_SSRR(routers=routers)
    elif opts == "SSRR-trunc":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption_SSRR(length=3, routers=routers_zero)
    elif opts == "unk":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption(b"\x9f")
    elif opts == "unk-40":
        subprocess.run(["sysctl", "net.inet.ip.process_options=0"], check=True)
        options = sc.IPOption(b"\x9f" * 40)
    else:
        options = ""
    return options


def main():
    """P I N G E R"""
    args = parse_args()
    opts = generate_ip_options(args.opts)
    ip = sc.IP(
        ihl=args.ihl,
        flags=args.flags,
        src=args.dst,
        dst=args.src,
        options=opts,
    )
    tun = sc.TunTapInterface(args.iface)
    subprocess.run(["ifconfig", tun.iface, "up"], check=True)
    subprocess.run(["ifconfig", tun.iface, args.src, args.dst], check=True)
    command = [
        # "/usr/obj/usr/src/amd64.amd64/sbin/ping/ping",
        "/sbin/ping",
        "-c",
        str(args.count),
        "-t",
        str(args.count),
        "-v",
    ]
    if args.request == "mask":
        command += ["-Mm"]
    if args.request == "timestamp":
        command += ["-Mt"]
    if args.special != "":
        command += ["-p1"]
    if args.opts in routing_options:
        command += ["-R"]
    command += [args.dst]
    with subprocess.Popen(args=command, text=True) as ping:
        for dummy in range(args.count):
            echo = tun.recv()
            icmp = sc.ICMP(
                type=args.icmp_type,
                code=args.icmp_code,
                id=echo[sc.ICMP].id,
                seq=echo[sc.ICMP].seq,
                ts_ori=args.icmp_otime,
                ts_rx=args.icmp_rtime,
                ts_tx=args.icmp_ttime,
                gw=args.icmp_gwaddr,
                ptr=args.icmp_pptr,
                addr_mask=args.icmp_mask,
                nexthopmtu=args.icmp_nextmtu,
            )
            pkt = build_response_packet(
                echo, ip, icmp, args.oip_ihl, args.special
            )
            tun.send(pkt)
            if args.dup is True:
                tun.send(pkt)
        ping.communicate()

    sys.exit(ping.returncode)


if __name__ == "__main__":
    main()

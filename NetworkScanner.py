#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/ IP range")
    values = parser.parse_args()
    if not values.target:
        parser.error("[-] Please specify an Target IP address, use --help for more info.")
    return values

def scan(ip):
    arp_req = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast / arp_req
    answered_packages_list = scapy.srp(arp_req_broadcast, timeout = 5, verbose=False)[0]

    client_list = []
    for element in answered_packages_list:
        client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dictionary)
    return client_list

def Result(final_list):
    # This function is for Printing purposes
    print("-----------------------------------------\n     IP\t\t\t   MAC "
          "address\n-----------------------------------------")
    for client in final_list:
        print(client["ip"] + "\t\t" + client["mac"])

values = get_args()
scan_result = scan(values.target)
Result(scan_result)
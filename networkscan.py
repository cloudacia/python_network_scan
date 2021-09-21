
import nmap
import ipaddress
import subnetting
import json
import ipcalc
import socket
import sys
import getopt
import argparse


"""This class is used to discover devices attached to specific network  """
class NetworkScan:

    def __init__(self):
        pass

    def network_discovery(self, network, arguments):
        self.network = network
        self.arguments = arguments

        try:
            self.nm = nmap.PortScanner()
            self.results_dict = self.nm.scan(hosts = self.network, arguments = self.arguments)
            self.results_json = json.dumps(self.results_dict)
            return self.results_json
        except:
            return False


""" This function gets the list of all of device connected to a given network """
def get_list_hosts(subnet):
    network = subnet
    arguments = "-sn"
    try:
        network_hosts = []
        target = NetworkScan()
        report = target.network_discovery(network, arguments)
        report_dict = json.loads(report)
        report_dict = report_dict['scan']
        for key, value in report_dict.items():
            hostname = key
            state = value['status']['state']
            node_up = (hostname, state)
            network_hosts.append(node_up)
        return network_hosts
    except:
        return False

"""This function gets the list of IP address of an specify subnet"""
def get_subnet_ips(subnet):
    network = subnet
    ip_address = []
    for ip in ipcalc.Network(network):
        ip = str(ip)
        ip = ip.replace('IP(', ' ')
        ip = ip.replace(')', ' ')
        ip_address.append(ip)
    return ip_address

"""This functions shows IP address not assigned to any host"""
def get_free_ips(var_list1, var_list2):
    subnet_ips = var_list1
    active_ips = var_list2
    active_ips_cleaned = []
    ips_not_in_used = []

    for host in active_ips:
        host = host[0]
        active_ips_cleaned.append(host)

    for ip in subnet_ips:
        bool_var = ip not in active_ips_cleaned
        if bool_var == True:
            ips_not_in_used.append(ip)
    return ips_not_in_used


"""This function resolve IP address to hostname"""
def get_hostname(ip_var):
    ip_address = ip_var
    hostname = socket.gethostbyaddr(ip_address)
    return hostname


""" This function gets arguments from the CLI"""
def get_cli_args():
    parser = argparse.ArgumentParser(description="Network Discovery Tool")
    parser.add_argument("--network", required=True, type=str, help="show devices connected to the network")
    parser.add_argument('--freeip', action='store_true', help="show IP addresses not in use")
    parser.add_argument('--hostname', action='store_true', help="show device's hostname connected to the network")
    args = parser.parse_args()
    target_net = args.network
    freeips = args.freeip
    hostnames = args.hostname
    return target_net, freeips, hostnames


"""This function shows the IP address of all of the nodes alive in the network """
def show_hosts():
    target_net, freeips, hostnames = get_cli_args()
    dash = '-' * 30
    FIELD1="STATUS"
    FIELD2="IP ADDRESS"
    print(dash)
    print("{:<15}{:^10}".format(FIELD2, FIELD1))
    print(dash)
    for host in get_list_hosts(target_net):
        ip_address = host[0]
        node_status = host[1]
        print("{:<15}{:^10}".format(ip_address, node_status))

""" This functions shows the IP addresses not being used in the network """
def show_free_ip():
    target_net, freeips, hostnames = get_cli_args()
    ip_list = get_subnet_ips(target_net)
    active_ips = get_list_hosts(target_net)
    list_free_ips = get_free_ips(ip_list, active_ips)
    dash = '-' * 25
    FIELD1="IP ADDRESSES AVAILABLE"
    print(dash)
    print("{:^25}".format(FIELD1))
    print(dash)
    for host in list_free_ips:
        print("{:>15}".format(host))

""" This function shows the hostnames of the IP addresses is used in the network"""
def show_hostnames():
    target_net, freeips, hostnames = get_cli_args()
    list_hosts_alive = get_list_hosts(target_net)
    dash = '-' * 60
    FIELD1="HOSTNAME"
    FIELD2="IP ADDRESS"
    print(dash)
    print("{:40}{:>20}".format(FIELD1, FIELD2))
    print(dash)
    for node in list_hosts_alive:
        node = node[0]
        try:
            node = get_hostname(node)
        except:
            MSG="Hostname not unavailable"
            print("{:40}{:>20}".format(MSG.upper(), node))
            continue
        print("{:40}{:>20}".format(node[0], node[2][0]))

if __name__ == "__main__":
    target_net, freeips, hostnames = get_cli_args()
    if freeips == True:
        show_free_ip()
    elif hostnames == True:
        show_hostnames()
    else:
        show_hosts()

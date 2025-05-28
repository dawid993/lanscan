import psutil
from socket import AddressFamily
from ipaddress import IPv4Network
from psutil._common import snicaddr
from typing import List, Tuple, Optional
import ping3

from getmac import get_mac_address

def get_network_addr_range(network_list: List[snicaddr]) -> Optional[Tuple[str, str]]:
    for network in network_list:
        if network.family == AddressFamily.AF_INET:
            return network.address, network.netmask
    return None

    
def scan_net_from_int(interface_name):
    interfaces = psutil.net_if_addrs()    
    int_result = get_network_addr_range(interfaces.get(interface_name))
    hosts_with_mac = []
    
    if int_result:
        addr, netmask = int_result
        hosts = IPv4Network(f"{addr}/{netmask}", strict=False).hosts()
        for host in hosts:
            scan_result = scan_host(host)
            if scan_result:
                hosts_with_mac.append(scan_result)
    
    print(hosts_with_mac)
            
def scan_host(host):
    host_str = str(host)
    ret_val = ping3.ping(host_str, timeout=0.5)
    if ret_val:
        mac_addr = get_mac_address(ip=host_str)
        return (host_str, mac_addr)
    else:
        None

def main():
    scan_net_from_int('wlo1')
    
if __name__ == "__main__": 
    main()

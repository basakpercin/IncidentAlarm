#!/usr/bin/python3

from scapy.all import *
import argparse

from scapy.compat import base64

def ip_proto(p):
  protoField = p.get_field('proto')
  return protoField.i2s[p.proto]

counter = 0
userPassFTP = []

def packetcallback(packet):
  global counter

  try:
    # The following is an example of Scapy detecting HTTP traffic
    # Please remove this case in your actual lab implementation so it doesn't pollute the alerts

    if packet.haslayer("TCP"):
# NULL SCAN
      if packet[TCP].flags == 0:
        incident = "Null scan"
        sourceIP = packet[IP].src
        protocol = ip_proto(packet[IP]).upper()
        counter+=1

        print(f"ALERT #{counter}: {incident} is detected from {sourceIP} ({protocol})!")


# FIN SCAN
      elif packet[TCP].flags == 'F':
        incident = "FIN scan"
        sourceIP = packet[IP].src
        protocol = ip_proto(packet[IP]).upper()
        counter+=1

        print(f"ALERT #{counter}: {incident} is detected from {sourceIP} ({protocol})!")


# XMAS SCAN
      elif packet[TCP].flags == 'FPU':
        incident = "Xmas scan"
        sourceIP = packet[IP].src
        protocol = ip_proto(packet[IP]).upper()
        counter+=1

        print(f"ALERT #{counter}: {incident} is detected from {sourceIP} ({protocol})!")



# NIKTO SCAN
      elif packet.haslayer(Raw) and "HTTP".encode() in packet.getlayer(Raw).load and "Nikto/2.1.6".encode() in packet.getlayer(Raw).load:
        incident = "Nikto scan"
        sourceIP = packet[IP].src
        protocol = ip_proto(packet[IP]).upper()
        counter+=1
        
        print(f"ALERT #{counter}: {incident} is detected from {sourceIP} ({protocol})!")


# HTTP - USERNAME AND PASSWORD SENT IN THE CLEAR   
      elif packet.haslayer(Raw) and "Authorization: Basic".encode() in packet.getlayer(Raw).load:
        incident = "Usernames and passwords sent in-the-clear (HTTP)"

        payload = packet[TCP].load.decode("ascii")
        
        encodedCredentials = payload.split("Authorization: Basic ")[1].split("\r\n")[0]

        decodedCredentials = base64.b64decode(encodedCredentials).decode("ascii")

        username = (decodedCredentials.split(":"))[0]
        password = (decodedCredentials.split(":"))[1]

        counter+=1

        print(f"ALERT #{counter}: {incident} username:{username} and password:{password}")

# FTP USERNAME AND PASSWORD
      
      elif packet[TCP].dport == 21:
        incident = "Usernames and passwords sent in-the-clear (FTP)"
        if "USER".encode() in packet[TCP].load:
          username = packet[TCP].load.decode("ascii").split("USER ")[1].split("\r\n")[0]
          if username not in userPassFTP:
            userPassFTP.append(username)
        elif "PASS".encode() in packet[TCP].load:
          password = packet[TCP].load.decode("ascii").split("PASS ")[1].split("\r\n")[0]
          if password not in userPassFTP:
            userPassFTP.append(password)
            counter+=1

          print(f"ALERT #{counter}: {incident} username:{userPassFTP[0]} and password:{userPassFTP[1]}")

#IMAP USERNAME AND PASSWORD
      elif packet[TCP].dport == 143:
        if "LOGIN".encode() in packet.getlayer(Raw).load:
          incident = "Usernames and passwords sent in-the-clear (IMAP)"
          payload = packet[TCP].load.decode("ascii").split("LOGIN ")[1].split("\r\n")[0]
          username = payload.split(" ")[0]
          password = payload.split("\"")[1]

          counter+=1
          print(f"ALERT #{counter}: {incident} username:{username} and password:{password}")


# SOMEONE SCANNING FOR SERVER MESSAGE BLOCK (SMB)            
      elif packet[TCP].dport == 445 or packet[TCP].dport == 139:
        incident = "Someone Scanning for Server Message Block (SMB)"
        sourceIP = packet[IP].src
        protocol = ip_proto(packet[IP]).upper()
        counter+=1

        print(f"ALERT #{counter}: {incident} is detected from {sourceIP} ({protocol}) and Port Number: {packet[TCP].dport}!")

# SOMEONE SCANNING FOR REMOTE DESKTOP PROTOCOL (RDP)
      elif packet[TCP].dport == 3389:
        incident = "Someone Scanning for Remote Desktop Protocol (RDP)"
        sourceIP = packet[IP].src
        protocol = ip_proto(packet[IP]).upper()
        counter+=1

        print(f"ALERT #{counter}: {incident} is detected from {sourceIP} ({protocol}) and Port Number: {packet[TCP].dport}!")

# SOMEONE SCANNING FOR VIRTUAL NETWORK COMPUTING (VNC)
      elif packet[TCP].dport == 5900:
        incident = "Someone Scanning for Virtual Network Computing (VNC)"
        sourceIP = packet[IP].src
        protocol = ip_proto(packet[IP]).upper()
        counter+=1

        print(f"ALERT #{counter}: {incident} is detected from {sourceIP} ({protocol}) and Port Number: {packet[TCP].dport}!")


  
    
  except Exception as e:
    # Uncomment the below and comment out `pass` for debugging, find error(s)
    #print(e)
    pass

# DO NOT MODIFY THE CODE BELOW
parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
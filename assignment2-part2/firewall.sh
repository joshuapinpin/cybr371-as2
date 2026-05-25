#!/bin/bash

# ------------------------------------------------------------
# AI Declaration:
# State clearly whether you used AI tools in this assignment.
#
# Examples:
# AI Declaration: No AI tools were used in the development of this submission.
#
# AI Declaration: Used ChatGPT to clarify how iptables handles
# ESTABLISHED,RELATED connection tracking states and DNAT behaviour.
# ------------------------------------------------------------

# Exit on error
set -e

# Enable IPv4 forwarding
sysctl -w net.ipv4.ip_forward=1

# Flush rules
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -t raw -F

iptables -X
iptables -t nat -X
iptables -t mangle -X
iptables -t raw -X

# Default-deny policy
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# ------------------------------------------------------------
# Add your rules below
# ------------------------------------------------------------

# G: Block all ICMP Redirect messages
iptables -A INPUT -p icmp --icmp-type redirect -j DROP
iptables -A OUTPUT -p icmp --icmp-type redirect -j DROP
iptables -A FORWARD -p icmp --icmp-type redirect -j DROP

# Core stateful handling and local traffic
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# H: Drop spoofed packets arriving on WAN with private/reserved source ranges
iptables -A INPUT -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 100.64.0.0/10 -j DROP
iptables -A INPUT -i eth0 -s 127.0.0.0/8 -j DROP
iptables -A INPUT -i eth0 -s 169.254.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A INPUT -i eth0 -s 198.18.0.0/15 -j DROP
iptables -A INPUT -i eth0 -s 224.0.0.0/4 -j DROP
iptables -A INPUT -i eth0 -s 240.0.0.0/4 -j DROP
iptables -A FORWARD -i eth0 -s 10.0.0.0/8 -j DROP
iptables -A FORWARD -i eth0 -s 100.64.0.0/10 -j DROP
iptables -A FORWARD -i eth0 -s 127.0.0.0/8 -j DROP
iptables -A FORWARD -i eth0 -s 169.254.0.0/16 -j DROP
iptables -A FORWARD -i eth0 -s 172.16.0.0/12 -j DROP
iptables -A FORWARD -i eth0 -s 192.168.0.0/16 -j DROP
iptables -A FORWARD -i eth0 -s 198.18.0.0/15 -j DROP
iptables -A FORWARD -i eth0 -s 224.0.0.0/4 -j DROP
iptables -A FORWARD -i eth0 -s 240.0.0.0/4 -j DROP

# P: Allow SSH access to the firewall from LAN2 only, with rate limiting and logging
iptables -A INPUT -i eth3 -p tcp --dport 22 -m conntrack --ctstate NEW -m hashlimit \
	--hashlimit-upto 3/minute --hashlimit-burst 3 --hashlimit-mode srcip --hashlimit-srcmask 32 \
	--hashlimit-name fw_ssh_allow -j ACCEPT
iptables -A INPUT -i eth3 -p tcp --dport 22 -m conntrack --ctstate NEW -m limit \
	--limit 6/minute --limit-burst 6 -j LOG --log-prefix "P: firewall SSH rate-limit "

# O: Allow the firewall itself to initiate outbound connections to the WAN
iptables -A OUTPUT -o eth0 -m conntrack --ctstate NEW -j ACCEPT

# Q: Block unsolicited ICMP to the firewall while allowing replies via ESTABLISHED,RELATED
iptables -A INPUT -p icmp -j DROP

# A/F: WAN and LAN access to the web server on HTTP/HTTPS with SYN-flood mitigation
iptables -A FORWARD -i eth0 -o eth1 -p tcp -d 10.0.0.2 -m multiport --dports 80,443 \
	-m conntrack --ctstate NEW -m tcp --syn -m hashlimit --hashlimit-upto 20/second \
	--hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-name web_syn -j ACCEPT
iptables -A FORWARD -i eth2 -o eth1 -p tcp -d 10.0.0.2 -m multiport --dports 80,443 \
	-m conntrack --ctstate NEW -m tcp --syn -m hashlimit --hashlimit-upto 20/second \
	--hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-name lan1_web_syn -j ACCEPT
iptables -A FORWARD -i eth3 -o eth1 -p tcp -d 10.0.0.2 -m multiport --dports 80,443 \
	-m conntrack --ctstate NEW -m tcp --syn -m hashlimit --hashlimit-upto 20/second \
	--hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-name lan2_web_syn -j ACCEPT

# C: SSH access to the web server only from LAN2, rate-limited per source IP, with logging of violations
iptables -A FORWARD -i eth3 -o eth1 -p tcp -d 10.0.0.2 --dport 22 -m conntrack --ctstate NEW \
	-m hashlimit --hashlimit-upto 3/minute --hashlimit-burst 3 --hashlimit-mode srcip \
	--hashlimit-srcmask 32 --hashlimit-name web_ssh_allow -j ACCEPT
iptables -A FORWARD -i eth3 -o eth1 -p tcp -d 10.0.0.2 --dport 22 -m conntrack --ctstate NEW \
	-m limit --limit 6/minute --limit-burst 6 -j LOG --log-prefix "C: web SSH rate-limit "

# E: Allow ICMP Echo Requests from LAN to the web server, with rate limiting
iptables -A FORWARD -i eth2 -o eth1 -p icmp --icmp-type echo-request -d 10.0.0.2 \
	-m limit --limit 5/second --limit-burst 10 -j ACCEPT
iptables -A FORWARD -i eth3 -o eth1 -p icmp --icmp-type echo-request -d 10.0.0.2 \
	-m limit --limit 5/second --limit-burst 10 -j ACCEPT

# D: Allow ICMP Destination Unreachable from DMZ to WAN; other DMZ ICMP stays blocked by default deny
iptables -A FORWARD -i eth1 -o eth0 -p icmp --icmp-type destination-unreachable -j ACCEPT

# I/K: Allow the web server to contact the update and certificate servers over HTTPS
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.0.2 -d 198.51.100.10 -p tcp --dport 443 \
	-m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.0.2 -d 198.51.100.20 -p tcp --dport 443 \
	-m conntrack --ctstate NEW -j ACCEPT

# J: Transparently redirect the web server's DNS requests to 8.8.8.8
iptables -t nat -A PREROUTING -s 10.0.0.2 -p udp --dport 53 -j DNAT --to-destination 8.8.8.8

# B3: LAN clients must use the internal DNS server at 192.168.80.53
iptables -A FORWARD -i eth2 -o eth2 -p udp -d 192.168.80.53 --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth3 -o eth2 -p udp -d 192.168.80.53 --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth2 -p udp --dport 53 -j DROP
iptables -A FORWARD -i eth3 -p udp --dport 53 -j DROP

# B1/B2/B4: LAN egress restrictions before the general LAN-to-WAN allow rule
iptables -A FORWARD -i eth2 -o eth0 -d 203.0.113.128/25 -j DROP
iptables -A FORWARD -i eth3 -o eth0 -d 203.0.113.128/25 -j DROP
iptables -A FORWARD -i eth2 -o eth0 -p tcp -m multiport --dports 23,445,6667 -j DROP
iptables -A FORWARD -i eth3 -o eth0 -p tcp -m multiport --dports 23,445,6667 -j DROP
iptables -A FORWARD -i eth2 -o eth0 -p tcp --dport 8080 -m string --algo bm --string "Shai-Hulud" -j DROP
iptables -A FORWARD -i eth3 -o eth0 -p tcp --dport 8080 -m string --algo bm --string "Shai-Hulud" -j DROP
iptables -A FORWARD -i eth2 -o eth0 -p udp --dport 4040 -m string --algo bm --string "Shai-Hulud" -j DROP
iptables -A FORWARD -i eth3 -o eth0 -p udp --dport 4040 -m string --algo bm --string "Shai-Hulud" -j DROP

# B: LAN hosts have general Internet access after the specific blocks above
iptables -A FORWARD -i eth2 -o eth0 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth3 -o eth0 -m conntrack --ctstate NEW -j ACCEPT

# L: Apply MASQUERADE for LAN-to-WAN traffic
iptables -t nat -A POSTROUTING -s 192.168.80.0/24 -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -s 192.168.90.0/24 -o eth0 -j MASQUERADE

# M: SNAT for DMZ-to-WAN traffic to the firewall's WAN IP
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j SNAT --to-source 203.0.113.1

# N: DNAT incoming WAN HTTP/HTTPS traffic to the DMZ web server
iptables -t nat -A PREROUTING -i eth0 -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 10.0.0.2

echo "Firewall rules applied."
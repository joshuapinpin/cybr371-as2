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
# Requirements A--Q should be implemented here.
# Ensure correct use of INPUT, OUTPUT, FORWARD, and nat chains.
# Rules are order-sensitive.

echo "Firewall rules applied."
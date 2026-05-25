CYBR371: SYSTEM AND NETWORK SECURITY
2026–T1: Arman Khouzani, Ian Welch
Assignment 2 (10%) – PART 2: Network Security
• Academic Integrity:
– You are encouraged to seek help from tutors or the lecturer during scheduled
lab sessions.
– All submitted work must be your own. Do not share your solutions, in
whole or in part, with others.
– We maintain a zero-tolerance policy toward plagiarism and unauthorised
collaboration. If you are unsure about what constitutes acceptable conduct,
please ask.
– You must acknowledge any external assistance at the point of use. This includes textbooks, official documentation, tutorials, forums (e.g., Stack Overflow), and any form of AI-assisted tools, such as:
* ChatGPT (including OpenAI models), GitHub Copilot, Google Gemini,
Microsoft Copilot, Claude (Anthropic), Perplexity, Phind, and similar
systems
– In addition, your submission must include an AI Declaration as a comment
block at the top of your code, prefaced with AI Declaration:. This declaration must clearly state whether AI tools were used. Even if no AI tools
were used, you must include this statement explicitly (e.g., “AI Declaration: No AI tools were used in the development of this submission.”).
– A detailed transcript of your interaction is not required. A brief acknowledgement is sufficient (e.g., “Used ChatGPT to clarify how iptables handles ESTABLISHED,RELATED connection tracking states”).
– Important: You are responsible for ensuring that any assistance you use does
not replace your own understanding. Submissions that demonstrate a lack
of understanding may be subject to further review.
– Failure to appropriately acknowledge sources or assistance may be treated
as academic misconduct.
CYBR371 Assignment 2 – part 2 2026
Q.1 Walls of Fire: A DMZ Edition.
In this exercise, you will design firewall rules for the trivial case of a web server deployed
in a four-legged DMZ topology. This is a hands-on exercise in stateful filtering, NAT, and
policy-driven firewall design.
You are tasked with creating a firewall ruleset for a Linux-based gateway in a screenedsubnet firewall topology with separate LAN1 and LAN2 interfaces, as depicted below.
192.168.80.0/24
LAN1
192.168.90.0/24
LAN2
DMZ
Gateway
Web Server
10.0.0.2
Internet
Update Server
198.51.100.10
Certificate Server
198.51.100.20
eth0
eth2
eth3
eth1
Network Configuration and Assumptions:
• The firewall has four interfaces:
– eth0 (WAN): 203.0.113.1/24
– eth1 (DMZ): 10.0.0.1/24
– eth2 (LAN1): 192.168.80.1/24
– eth3 (LAN2): 192.168.90.1/24
• The web server is located in the DMZ at 10.0.0.2.
• LAN1 uses subnet 192.168.80.0/24.
• LAN2 uses subnet 192.168.90.0/24.
• The internal DNS server is located at 192.168.80.53.
• The firewall acts as the default gateway for all internal hosts.
• IP forwarding is enabled on the firewall.
• A correct routing table is already configured; you do not need to modify routing.
2
CYBR371 Assignment 2 – part 2 2026
Note: In real deployments, LAN1 and LAN2 would typically be implemented as separate VLANs
on a shared interface. In this exercise, they are provided as separate interfaces for clarity.
Here are the list of requirements:
A. Hosts on the WAN should be able to access the web server via the firewalls WAN IP
on TCP ports 80 and 443. Hosts on LAN1 and LAN2 should be able to access the
web server directly at 10.0.0.2 on the same ports.
B. Hosts on the LAN should have full access to the Internet, with the following exceptions:
B1. Block outbound connections to the IP range 203.0.113.128/25 (representing
a known command-and-control network).
B2. Disallow outbound connections to TCP ports 6667 (IRC), 23 (Telnet), and 445
(SMB).
B3. LAN clients must use the internal DNS server at 192.168.80.53. Block all
other DNS (UDP/53) traffic from LAN.
B4. Block a known worm that propagates over TCP port 8080 and UDP port 4040
where the payload contains the ASCII string “Shai-Hulud”. You do not need
to consider TCP stream reassembly.
C. SSH access to the web server (port 22) should be allowed only from the LAN2 subnet. Apply a rate limit of at most 3 new connections per minute per source IP. Log
violations (rate-limited) as potential SSH dictionary attacks.
D. Allow ICMP Destination Unreachable (Type 3) messages from DMZ to WAN. Drop
all other ICMP originating from the DMZ.
E. Allow ICMP Echo Requests (ping) from LAN to the web server, with rate limiting.
F. Mitigate SYN flood attacks against the web server by rate-limiting new TCP connection attempts to ports 80 and 443.
G. Block all ICMP Redirect messages.
H. Drop spoofed packets arriving on the WAN interface (eth0) with source IPs from
private or reserved ranges (e.g., 10.0.0.0/8, 192.168.0.0/16, 127.0.0.0/8,
etc.).
I. The web server should be able to contact an update server at 198.51.100.10 over
HTTPS.
J. The web server should be able to send DNS requests (UDP/53). Transparently redirect these DNS requests to 8.8.8.8, regardless of the original destination.
K. Allow the web server to initiate HTTPS connections to a certificate server at
198.51.100.20.
NAT Requirements:
L. Apply MASQUERADE for LAN-to-WAN traffic.
M. For DMZ-to-WAN traffic, perform SNAT to the firewalls WAN IP (203.0.113.1).
N. DNAT all incoming WAN traffic on ports 80 and 443 to the web server at 10.0.0.2.
Firewall Host Requirements:
3
CYBR371 Assignment 2 – part 2 2026
O. The firewall itself should be able to initiate outbound connections to the WAN.
P. Allow SSH access to the firewall from LAN2 only, with rate limiting and logging.
Q. Block all unsolicited ICMP traffic to the firewall. Allow ICMP replies to traffic initiated by the firewall.
Note: You should rely on default-deny policies to block all other traffic. Do not add
explicit DROP rules for unspecified traffic.
iptables Implementation
Translate your policy into a working iptables ruleset.
• Use IPv4 only.
• Your rules must be stateful, using connection tracking (e.g., ESTABLISHED,RELATED).
• Clearly distinguish between INPUT, OUTPUT, and FORWARD chains. Your rules must
be placed in the correct chains and tables. Incorrect placement (e.g., using INPUT
instead of FORWARD, or filter instead of nat) will result in loss of marks even if
the intent is correct.
• Use the nat table where appropriate (PREROUTING, POSTROUTING, OUTPUT).
• Rules are order-sensitive; ensure correct ordering.
• Structure your rules using modular chains where appropriate.
• Use logging where required, and ensure all logging is rate-limited.
• Include comments mapping each rule to the corresponding requirement (A–Q).
Submission Requirements:
• Submit a single executable shell script (firewall.sh).
• The script must flush existing rules before applying new ones.
• The script must be idempotent (safe to run multiple times).
• Ensure IP forwarding is enabled.
Suggested Skeleton
You may use the following skeleton as a starting point. You are not required to follow
this exact structure, but your final script should be clear, ordered, and commented.
Minimal Skeleton (Optional)
firewall.sh skeleton (minimal with AI Declaration)
#!/bin/bash
# ------------------------------------------------------------
# AI Declaration:
# State clearly whether you used AI tools in this assignment.
#
4
CYBR371 Assignment 2 – part 2 2026
# Examples:
# AI Declaration: No AI tools were used in the development of
this submission.
#
# AI Declaration: Used ChatGPT to clarify how iptables handles
# ESTABLISHED,RELATED connection tracking states and DNAT
behaviour.
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
5
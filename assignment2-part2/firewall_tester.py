#!/usr/bin/env python3

import os
import subprocess
import sys
import time
from pathlib import Path

STUDENT_SCRIPT = sys.argv[1] if len(sys.argv) > 1 else "./firewall.sh"

NS = ["fw", "wan", "dmz", "lan1", "lan2"]


def run(cmd, check=True, capture=False, ns=None):
    if ns:
        cmd = ["ip", "netns", "exec", ns] + cmd
    print("+", " ".join(cmd))
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def sh(cmd, check=True, capture=False, ns=None):
    return run(["bash", "-lc", cmd], check=check, capture=capture, ns=ns)


def cleanup():
    for ns in NS:
        subprocess.run(["ip", "netns", "del", ns], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup():
    cleanup()

    for ns in NS:
        run(["ip", "netns", "add", ns])

    # WAN link
    run(["ip", "link", "add", "fw-wan", "type", "veth", "peer", "name", "wan-fw"])
    run(["ip", "link", "set", "fw-wan", "netns", "fw"])
    run(["ip", "link", "set", "wan-fw", "netns", "wan"])

    # DMZ link
    run(["ip", "link", "add", "fw-dmz", "type", "veth", "peer", "name", "dmz-fw"])
    run(["ip", "link", "set", "fw-dmz", "netns", "fw"])
    run(["ip", "link", "set", "dmz-fw", "netns", "dmz"])

    # LAN1 link
    run(["ip", "link", "add", "fw-lan1", "type", "veth", "peer", "name", "lan1-fw"])
    run(["ip", "link", "set", "fw-lan1", "netns", "fw"])
    run(["ip", "link", "set", "lan1-fw", "netns", "lan1"])

    # LAN2 link
    run(["ip", "link", "add", "fw-lan2", "type", "veth", "peer", "name", "lan2-fw"])
    run(["ip", "link", "set", "fw-lan2", "netns", "fw"])
    run(["ip", "link", "set", "lan2-fw", "netns", "lan2"])

    # Rename firewall-side interfaces to match assignment
    sh("ip link set fw-wan name eth0", ns="fw")
    sh("ip link set fw-dmz name eth1", ns="fw")
    sh("ip link set fw-lan1 name eth2", ns="fw")
    sh("ip link set fw-lan2 name eth3", ns="fw")

    # Assign addresses
    sh("ip addr add 203.0.113.1/24 dev eth0", ns="fw")
    sh("ip addr add 10.0.0.1/24 dev eth1", ns="fw")
    sh("ip addr add 192.168.80.1/24 dev eth2", ns="fw")
    sh("ip addr add 192.168.90.1/24 dev eth3", ns="fw")

    sh("ip addr add 203.0.113.50/24 dev wan-fw", ns="wan")
    sh("ip addr add 10.0.0.2/24 dev dmz-fw", ns="dmz")
    sh("ip addr add 192.168.80.10/24 dev lan1-fw", ns="lan1")
    sh("ip addr add 192.168.90.10/24 dev lan2-fw", ns="lan2")

    # Add extra public IPs to WAN namespace to represent external servers
    sh("ip addr add 198.51.100.10/24 dev wan-fw", ns="wan")
    sh("ip addr add 198.51.100.20/24 dev wan-fw", ns="wan")
    sh("ip addr add 8.8.8.8/24 dev wan-fw", ns="wan")

    # Bring up loopback and interfaces
    for ns in NS:
        sh("ip link set lo up", ns=ns)

    for ns, iface in [
        ("fw", "eth0"), ("fw", "eth1"), ("fw", "eth2"), ("fw", "eth3"),
        ("wan", "wan-fw"), ("dmz", "dmz-fw"),
        ("lan1", "lan1-fw"), ("lan2", "lan2-fw"),
    ]:
        sh(f"ip link set {iface} up", ns=ns)

    
    # Routes
    sh("ip route add default via 203.0.113.1", ns="wan")
    sh("ip route add default via 10.0.0.1", ns="dmz")
    sh("ip route add default via 192.168.80.1", ns="lan1")
    sh("ip route add default via 192.168.90.1", ns="lan2")

    # Firewall routes to fake Internet-side service networks
    sh("ip route replace 198.51.100.0/24 dev eth0", ns="fw")
    sh("ip route replace 8.8.8.0/24 dev eth0", ns="fw")


def copy_and_run_student_script():
    dst = "/tmp/firewall.sh"
    run(["ip", "netns", "exec", "fw", "mkdir", "-p", "/tmp"])
    subprocess.run(["cp", STUDENT_SCRIPT, dst], check=True)
    os.chmod(dst, 0o755)
    sh(dst, ns="fw")


def start_servers():
    # Web server in DMZ on 80 and 443
    sh("nohup nc -lk -p 80 >/tmp/http.log 2>&1 &", ns="dmz")
    sh("nohup nc -lk -p 443 >/tmp/https.log 2>&1 &", ns="dmz")
    sh("nohup nc -lk -p 22 >/tmp/ssh.log 2>&1 &", ns="dmz")

    # External HTTPS update/cert servers
    sh("nohup nc -lk -p 443 >/tmp/wan443.log 2>&1 &", ns="wan")

    # Fake DNS listener on 8.8.8.8 UDP/53
    sh("nohup nc -luk -p 53 >/tmp/dns.log 2>&1 &", ns="wan")

    time.sleep(1)


def tcp_test(name, ns, host, port, should_pass=True, timeout=2):
    cmd = f"timeout {timeout} bash -c '</dev/tcp/{host}/{port}'"
    ok = sh(cmd, check=False, ns=ns).returncode == 0
    result(name, ok == should_pass)


def ping_test(name, ns, host, should_pass=True):
    ok = sh(f"ping -c 1 -W 1 {host}", check=False, ns=ns).returncode == 0
    result(name, ok == should_pass)


def udp_send(name, ns, host, port, payload, should_pass=True):
    # UDP is awkward to test with nc because success is not connection-oriented.
    # Here we mainly test that the command is allowed to leave without local failure.
    rc = sh(f"printf '{payload}' | timeout 1 nc -u -w1 {host} {port}", check=False, ns=ns).returncode
    ok = rc in (0, 124)
    result(name, ok == should_pass)


RESULTS = []


def result(name, passed):
    RESULTS.append((name, passed))
    mark = "PASS" if passed else "FAIL"
    print(f"[{mark}] {name}")


def tests():
    # A/O: WAN reaches public IP, DNAT to webserver
    tcp_test("WAN can reach webserver via firewall WAN IP on HTTP", "wan", "203.0.113.1", 80, True)
    tcp_test("WAN can reach webserver via firewall WAN IP on HTTPS", "wan", "203.0.113.1", 443, True)

    # A: LAN reaches webserver directly
    tcp_test("LAN1 can reach DMZ webserver HTTP directly", "lan1", "10.0.0.2", 80, True)
    tcp_test("LAN2 can reach DMZ webserver HTTPS directly", "lan2", "10.0.0.2", 443, True)

    # C: SSH to webserver only from LAN2
    tcp_test("LAN2 can SSH to webserver", "lan2", "10.0.0.2", 22, True)
    tcp_test("LAN1 cannot SSH to webserver", "lan1", "10.0.0.2", 22, False)

    # E: LAN ping to webserver
    ping_test("LAN1 can ping webserver", "lan1", "10.0.0.2", True)

    # I/K: DMZ HTTPS to update/cert servers
    tcp_test("Webserver can reach update server HTTPS", "dmz", "198.51.100.10", 443, True)
    tcp_test("Webserver can reach certificate server HTTPS", "dmz", "198.51.100.20", 443, True)

    # Negative cases
    tcp_test("WAN cannot SSH to webserver", "wan", "203.0.113.1", 22, False)
    tcp_test("DMZ cannot initiate SSH to LAN1", "dmz", "192.168.80.10", 22, False)

    # B2: blocked LAN outbound ports
    tcp_test("LAN1 outbound Telnet TCP/23 blocked", "lan1", "198.51.100.10", 23, False)
    tcp_test("LAN1 outbound SMB TCP/445 blocked", "lan1", "198.51.100.10", 445, False)
    tcp_test("LAN1 outbound IRC TCP/6667 blocked", "lan1", "198.51.100.10", 6667, False)

    # B: allowed general Internet HTTPS
    tcp_test("LAN1 general Internet HTTPS allowed", "lan1", "198.51.100.10", 443, True)

    # Q: unsolicited ICMP to firewall blocked
    ping_test("WAN cannot ping firewall", "wan", "203.0.113.1", False)


def summary():
    passed = sum(1 for _, ok in RESULTS if ok)
    total = len(RESULTS)
    print()
    print(f"Summary: {passed}/{total} tests passed")
    for name, ok in RESULTS:
        if not ok:
            print(f"  FAIL: {name}")

    return 0 if passed == total else 1


def main():
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)

    if not Path(STUDENT_SCRIPT).exists():
        print(f"Cannot find student script: {STUDENT_SCRIPT}")
        sys.exit(1)

    try:
        setup()
        copy_and_run_student_script()
        start_servers()
        tests()
        sys.exit(summary())
    finally:
        cleanup()


if __name__ == "__main__":
    main()
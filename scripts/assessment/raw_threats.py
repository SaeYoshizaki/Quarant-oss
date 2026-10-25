#!/usr/bin/env python3
"""An independent measure of path threats for the countermeasure evaluation:
reads the raw packets of a capture with its own parser (rawscan.py, stdlib
only, no reassembly) and relies on neither Quarant nor Zeek.

Threats counted, each as (device, kind, position):
  tls_old       a ServerHello selecting TLS 1.1 or older (the
                supported_versions extension decides when present)
  tls_broken    a ServerHello selecting an RC4, DES, 3DES, NULL, EXPORT,
                anonymous or MD5 suite
  cred_auth     an Authorization header with a reusable scheme (Basic,
                Bearer, ...; per-request signatures such as Digest and
                AWS4-HMAC-SHA256 are left out) in cleartext
  cred_mqtt     an MQTT CONNECT with the password flag
  cred_ftp      an FTP PASS command
  cred_named    a URL, header or body field named like a password, token,
                secret, API key or session id (the name only; a candidate)
  cookie        a Cookie header in cleartext
  media         an image, video or audio signature or Content-Type sent by
                the device to a public address over cleartext TCP
The device is the end inside the home network. Position: internet_path when
the other end is a public address, home when both are inside. Credentials
sent to a device by a host listed in --scanners are not counted (guesses).

Only metadata is kept; values never leave memory.

usage: raw_threats.py CAPTURE|- OUT_JSON [--scanners FILE] [--exclude FILE]
"""
import argparse
import ipaddress
import json
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "accuracy"))
import rawscan  # noqa: E402

import re  # noqa: E402

# Field names that name a secret on their own (not "auth" or "sid", which
# are often identifiers or flags).
STRICT_NAME = re.compile(r"passw(or)?d|passwd|pwd|passcode|token|secret|api[_-]?key|apikey|session[_-]?id|sessionid")
SIG_SCHEMES = {"digest", "aws4-hmac-sha256", "aws", "oss", "wsse", "hmac-sha256"}
OLD = {0x0300: "SSL3.0", 0x0301: "TLS1.0", 0x0302: "TLS1.1"}
# Suites with known breaks (IANA TLS Cipher Suites registry): RC4, DES,
# 3DES, NULL encryption, EXPORT, anonymous key exchange, MD5 MAC.
BROKEN = {
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E,
    0x000F, 0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018, 0x0019, 0x001A, 0x001B,
    0x002C, 0x002D, 0x002E, 0x0034, 0x003A, 0x003B, 0x006C, 0x006D, 0x008A, 0x008B, 0x008E, 0x008F, 0x0092,
    0x0093, 0x00B0, 0x00B1, 0x00B4, 0x00B5, 0x00B8, 0x00B9, 0xC001, 0xC002, 0xC003, 0xC006, 0xC007, 0xC008,
    0xC00B, 0xC00C, 0xC00D, 0xC010, 0xC011, 0xC012, 0xC015, 0xC016, 0xC017, 0xC018, 0xC019, 0xC01A, 0xC01B,
    0xC01C, 0xC033, 0xC034, 0xC039, 0xC03A, 0xC03B,
}


def local(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local
    except ValueError:
        return False


def public(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def server_hello(pl):
    """(selected version, cipher) of a ServerHello at the start of a TLS
    record, or None."""
    if len(pl) < 11 or pl[0] != 0x16 or pl[1] != 3 or pl[5] != 0x02:
        return None
    try:
        body = pl[9:]
        ver = struct.unpack("!H", body[0:2])[0]
        sid_len = body[34]
        i = 35 + sid_len
        cipher = struct.unpack("!H", body[i:i + 2])[0]
        i += 3  # cipher, compression
        if len(body) >= i + 2:
            ext_len = struct.unpack("!H", body[i:i + 2])[0]
            j, end = i + 2, min(len(body), i + 2 + ext_len)
            while j + 4 <= end:
                et, el = struct.unpack("!HH", body[j:j + 4])
                if et == 0x002B and el == 2:
                    ver = struct.unpack("!H", body[j + 4:j + 6])[0]
                j += 4 + el
        return ver, cipher
    except (IndexError, struct.error):
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("out")
    ap.add_argument("--scanners")
    ap.add_argument("--exclude", help="MACs of home hosts that are not IoT devices; they are not counted as devices")
    a = ap.parse_args()
    read = lambda p: {l.strip().lower() for l in open(p) if l.strip() and not l.startswith("#")} if p else set()
    scanners, exclude = read(a.scanners), read(a.exclude)
    ipmac = {}
    threats = {}
    path = "/dev/stdin" if a.capture == "-" else a.capture
    for _, lt, fr in rawscan.packets(path):
        p = rawscan.parse(lt, fr)
        if not p:
            continue
        smac, dmac, src, dst, proto, sp, dpt, pl = p
        if lt == 113 and len(fr) >= 12:
            smac = rawscan.mac(fr[6:12])  # Linux cooked capture: sender's address only
        if smac and local(src):
            ipmac[src] = smac
        if not dmac:
            dmac = ipmac.get(dst, "")
        if not pl:
            continue

        def add(dev_ip, dev_mac, peer, kind):
            m = dev_mac or dev_ip
            if m in exclude:
                return
            pos = "home" if local(peer) else "internet_path"
            k = (m, kind, pos)
            threats[k] = threats.get(k, 0) + 1

        # TLS: what the server selected
        if proto == "tcp" and pl[0] == 0x16:
            sh = server_hello(pl)
            if sh:
                ver, cipher = sh
                # the device is the home end: as client it accepted, as
                # server it chose
                if local(dst) and not local(src):
                    dev = (dst, dmac, src)
                elif local(src):
                    dev = (src, smac, dst)
                else:
                    dev = None
                if dev:
                    if ver in OLD:
                        add(*dev, "tls_old")
                    if cipher in BROKEN:
                        add(*dev, "tls_broken")
            continue
        if len(pl) > 5 and 0x14 <= pl[0] <= 0x17 and pl[1] == 3:
            continue
        if not rawscan.PRE.search(pl):
            continue
        for cls, name in rawscan.classify(pl):
            kind = None
            if cls == "authorization" and name not in SIG_SCHEMES:
                kind = "cred_auth"
            elif cls == "mqtt_connect" and "pass=True" in name:
                kind = "cred_mqtt"
            elif cls == "ftp_pass":
                kind = "cred_ftp"
            elif cls == "secret_key" and STRICT_NAME.search(name):
                kind = "cred_named"
            elif cls == "cookie":
                kind = "cookie"
            elif cls in ("media_signature", "media_content_type") and proto == "tcp" and local(src) and public(dst):
                add(src, smac, dst, "media")
                continue
            if not kind:
                continue
            # credentials travel client -> server: the account is the
            # server's when the server is in the home, else the client's
            if local(dst):
                if smac in scanners:
                    continue
                add(dst, dmac, src, kind)
            elif local(src):
                add(src, smac, dst, kind)
    out = [{"device": k[0], "kind": k[1], "position": k[2], "packets": n} for k, n in sorted(threats.items())]
    json.dump({"threats": out}, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()

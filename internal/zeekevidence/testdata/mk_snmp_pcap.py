# Synthetic SNMP v2c exchange: a manager (192.168.1.10) asks an agent
# (192.168.1.20) for sysDescr with community "public" and the agent answers.
import struct, sys

def tlv(t, v): 
    n = len(v)
    return bytes([t]) + (bytes([n]) if n < 128 else bytes([0x81, n])) + v

def snmp(pdu_type, community, req_id, value):
    oid = tlv(0x06, bytes([0x2b, 6, 1, 2, 1, 1, 1, 0]))
    varbind = tlv(0x30, oid + value)
    pdu = tlv(pdu_type, tlv(0x02, bytes([req_id])) + tlv(0x02, b"\x00") + tlv(0x02, b"\x00") + tlv(0x30, varbind))
    return tlv(0x30, tlv(0x02, b"\x01") + tlv(0x04, community) + pdu)

def frame(src_mac, dst_mac, src, dst, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    s = sum(struct.unpack("!10H", ip)); s = (s & 0xffff) + (s >> 16); s = (s & 0xffff) + (s >> 16)
    ip = ip[:10] + struct.pack("!H", ~s & 0xffff) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + udp

m1, m2 = bytes.fromhex("020000000010"), bytes.fromhex("020000000020")
req = frame(m1, m2, "192.168.1.10", "192.168.1.20", 40000, 161, snmp(0xa0, b"public", 7, b"\x05\x00"))
resp = frame(m2, m1, "192.168.1.20", "192.168.1.10", 161, 40000, snmp(0xa2, b"public", 7, tlv(0x04, b"Linux camera")))
with open(sys.argv[1], "wb") as f:
    f.write(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for i, p in enumerate((req, resp)):
        f.write(struct.pack("<IIII", 1700000000 + i, 0, len(p), len(p)) + p)

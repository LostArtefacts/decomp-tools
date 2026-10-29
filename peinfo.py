import struct, sys, time

data = open(sys.argv[1], "rb").read()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]

# Rich header: XOR-masked, between DOS stub and PE header
rich = data.find(b"Rich", 0, e_lfanew)
if rich >= 0:
    key = struct.unpack_from("<I", data, rich + 4)[0]
    i = rich - 4
    while struct.unpack_from("<I", data, i)[0] ^ key != 0x536E6144:  # "DanS"
        i -= 4
    print(f"Rich key {key:08x}")
    for off in range(i + 16, rich, 8):
        compid, count = (v ^ key for v in struct.unpack_from("<II", data, off))
        print(f"  prodid {compid >> 16:3d}  build {compid & 0xFFFF:5d}  count {count}")
else:
    print("no Rich header")

machine, nsec, ts, _, _, optsz, chars = struct.unpack_from("<HHIIIHH", data, e_lfanew + 4)
opt = e_lfanew + 24
magic, lmaj, lmin = struct.unpack_from("<HBB", data, opt)
entry, = struct.unpack_from("<I", data, opt + 16)
base, = struct.unpack_from("<I", data, opt + 28)
subsys, = struct.unpack_from("<H", data, opt + 68)
print(f"machine {machine:#x} linker {lmaj}.{lmin:02d} timestamp {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))} UTC")
print(f"imagebase {base:#x} entry {base + entry:#x} subsystem {subsys}")

sec = opt + optsz
sections = []
for n in range(nsec):
    name, vsz, va, rsz, rptr = struct.unpack_from("<8sIIII", data, sec + 40 * n)
    sections.append((va, vsz, rptr))
    print(f"  {name.rstrip(b'\0').decode():8s} va {base + va:#010x} vsize {vsz:#08x} raw {rsz:#08x}")

def rva2off(rva):
    for va, vsz, rptr in sections:
        if va <= rva < va + max(vsz, 1):
            return rva - va + rptr

imp_rva, = struct.unpack_from("<I", data, opt + 96 + 8)
o = rva2off(imp_rva)
print("imports:")
while True:
    oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", data, o)
    if not name_rva:
        break
    nm = data[rva2off(name_rva):].split(b"\0")[0].decode()
    t = rva2off(oft or ft)
    funcs = []
    while (v := struct.unpack_from("<I", data, t)[0]):
        funcs.append(f"#{v & 0xFFFF}" if v & 0x80000000 else data[rva2off(v) + 2:].split(b"\0")[0].decode())
        t += 4
    print(f"  {nm} ({len(funcs)}): {', '.join(funcs[:12])}{' ...' if len(funcs) > 12 else ''}")
    o += 20

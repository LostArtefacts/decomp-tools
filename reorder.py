"""Sorts the function definitions in a .c or .cpp into the original's address
order, keeping every other top-level item (includes, globals, class
definitions) where it is. A function keeps the comment lines right above
it.

    reorder.py src/FILE.c [OBJ]      rewrite FILE.c in place
    reorder.py -n src/FILE.c         only print the planned order

The functions placed are those build/<name>_exe.map puts in the object
(default: FILE.obj) whose name (symbols.csv `name`) matches a definition
in the file, so build the exe first. Slots are refilled in original
address order. Definitions the map doesn't place in that object (inline
helpers that are always expanded), forward declarations and #define or
#undef lines travel with the next placed function. Check the result with
order.py: inline functions land after their first caller (see there).
"""
import os, re, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import order


def items(text):
    """Top-level items: (kind, text). kind is 'fn' for a function
    definition, else 'other'."""
    lines = text.splitlines(keepends=True)
    out = []; cur = []; depth = 0; pending = []
    in_block_comment = False
    def strip(l):
        nonlocal in_block_comment
        s = ""; i = 0
        while i < len(l):
            if in_block_comment:
                j = l.find("*/", i)
                if j < 0: return s
                in_block_comment = False; i = j + 2; continue
            c = l[i]
            if l.startswith("//", i): break
            if l.startswith("/*", i): in_block_comment = True; i += 2; continue
            if c in "\"'":
                q = c; i += 1
                while i < len(l) and l[i] != q:
                    i += 2 if l[i] == "\\" else 1
                i += 1; s += q + q; continue
            s += c; i += 1
        return s
    macro = None  # a preprocessor line continued with backslashes
    for l in lines:
        if macro is not None:
            macro += l
            if not l.rstrip("\r\n").endswith("\\"):
                out.append(("other", macro))
                macro = None
            continue
        code = strip(l)
        if depth == 0 and not cur:
            st = l.strip()
            if st == "" or st.startswith("//"):
                pending.append(l); continue
            if st.startswith("#"):
                if l.rstrip("\r\n").endswith("\\"):
                    macro = "".join(pending) + l
                else:
                    out.append(("other", "".join(pending) + l))
                pending = []
                continue
        cur.append(l)
        depth += code.count("{") - code.count("}")
        if depth == 0:
            body = "".join(cur)
            cs = code.rstrip()
            if cs.endswith("}") or cs.endswith(";"):
                kind = "fn" if cs.endswith("}") and re.search(r"\)\s*(const\s*)?(:[^{]*)?\{", strip_all(body), re.S) and not re.match(r"\s*(struct|class|union|enum|namespace|extern \"C\")\b", strip_all(body)) and "=" not in strip_all(body).split("{")[0].split("(")[0] else "other"
                out.append((kind, "".join(pending) + body)); pending = []; cur = []
    if cur or pending:
        out.append(("other", "".join(pending) + "".join(cur)))
    return out

def strip_all(t):
    t = re.sub(r"//[^\n]*", "", t)
    return re.sub(r"/\*.*?\*/", "", t, flags=re.S)

def fn_name(body):
    code = strip_all(body)
    head = code.split("{")[0]
    m = re.search(r"([A-Za-z_~][\w]*(?:::[~\w]+)*(?:::operator\s*[^\s(]+)?)\s*\(", head)
    return m.group(1) if m else None

def main():
    args = sys.argv[1:]
    dry = "-n" in args
    args = [a for a in args if a != "-n"]
    path = args[0]
    obj = args[1] if len(args) > 1 else os.path.splitext(os.path.basename(path))[0] + ".obj"
    syms = order.read_syms()
    # name -> original addresses of this object's functions
    byname = {}
    for addr, sym, inl, o in order.read_map():
        if o == obj and sym in syms:
            byname.setdefault(syms[sym][1], []).append(syms[sym][0])
    text = open(path, encoding="utf-8").read()
    its = items(text)
    assert "".join(t for _, t in its) == text
    slots = []
    fns = []
    used = {}
    glue = []  # items that travel with the next placed function
    for i, (k, t) in enumerate(its):
        if k == "fn":
            n = fn_name(t)
            if n in byname:
                idx = used.get(n, 0)
                used[n] = idx + 1
                addrs = sorted(byname[n])
                if idx < len(addrs):
                    slots.append(glue + [i])
                    fns.append((addrs[idx], n, "".join(its[j][1] for j in glue + [i])))
                    glue = []
                    continue
            print(f"travels with the next function: {n}", file=sys.stderr)
            glue.append(i)
            continue
        lines = [l.strip() for l in t.splitlines() if l.strip() and not l.strip().startswith("//")]
        st = lines[0] if lines else ""
        decl = re.search(r"\)\s*;\s*$", strip_all(t)) is not None and "=" not in strip_all(t)
        if slots and (decl or st.startswith("#define") or st.startswith("#undef")):
            glue.append(i)
    ordered = sorted(fns, key=lambda f: f[0])
    for a, n, _ in ordered:
        print(f"{a:#x} {n}")
    if dry:
        return
    new = list(its)
    for s, f in zip(slots, ordered):
        for j in s:
            new[j] = ("fn", "")
        new[s[-1]] = ("fn", f[2])
    open(path, "w", encoding="utf-8").write("".join(t for _, t in new))


if __name__ == "__main__":
    main()

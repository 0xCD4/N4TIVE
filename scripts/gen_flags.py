#!/usr/bin/env python3
"""Write every flag-dependent table of N4TIVE from one secret file.

The encrypted blobs in the challenge sources and the HMAC digests in
flag_core.c and verify_flag.sh all depend on the flags. This script is the
only thing that writes them, so a blob and its digest cannot drift apart.

    python scripts/gen_flags.py new      create FLAGS_SECRET.txt with random flags
    python scripts/gen_flags.py apply    rewrite the generated blocks in the sources
    python scripts/gen_flags.py check    exit 1 if the sources differ from the secrets

FLAGS_SECRET.txt is listed in .gitignore and must never be committed.
Keys, tables and opcodes are read from the C sources, so the C files stay
the single source of truth for everything except the flags.
"""

import argparse
import hashlib
import hmac
import re
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JNI = ROOT / "app" / "src" / "main" / "jni"
SECRET_FILE = ROOT / "FLAGS_SECRET.txt"
VERIFY_SH = ROOT / "scripts" / "verify_flag.sh"

CHALLENGES = ["ch01", "ch02", "ch03", "ch04", "ch05", "ch06"]
# Length of the part between FLAG{ and }, fixed by each challenge's C code.
INNER_LEN = {"ch01": 40, "ch02": 42, "ch03": 40, "ch04": 42, "ch05": 42, "ch06": 40}
CH06_INPUT_LEN = 16
MASK32 = 0xFFFFFFFF


# --------------------------------------------------------------------------
# Small helpers: file access, C parsing, block replacement, formatting
# --------------------------------------------------------------------------

def read_text(path):
    """Return (text with LF line ends, original line end)."""
    raw = path.read_bytes().decode("utf-8")
    eol = "\r\n" if "\r\n" in raw else "\n"
    return raw.replace("\r\n", "\n"), eol


def write_text(path, text, eol):
    path.write_bytes(text.replace("\n", eol).encode("utf-8"))


def strip_comments(src):
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)


def c_array(src, name):
    """All integer literals of the C array `name`, flattened."""
    clean = strip_comments(src)
    m = re.search(r"\b%s\s*(?:\[[^\]]*\]\s*)+=\s*\{" % re.escape(name), clean)
    if not m:
        raise SystemExit("array %s not found" % name)
    depth, i = 1, m.end()
    while depth:
        depth += {"{": 1, "}": -1}.get(clean[i], 0)
        i += 1
    return [int(t, 0) for t in re.findall(r"0[xX][0-9a-fA-F]+|\d+", clean[m.end():i - 1])]


def c_scalar(src, name):
    m = re.search(r"\b%s\s*=\s*(0[xX][0-9a-fA-F]+|\d+)" % re.escape(name), strip_comments(src))
    if not m:
        raise SystemExit("constant %s not found" % name)
    return int(m.group(1), 0)


def c_define(src, name):
    m = re.search(r"^[ \t]*#define[ \t]+%s[ \t]+(0[xX][0-9a-fA-F]+|\d+)" % re.escape(name), src, re.M)
    if not m:
        raise SystemExit("#define %s not found" % name)
    return int(m.group(1), 0)


def replace_block(text, name, body, style="c"):
    """Replace the lines between the `gen_flags begin/end NAME` markers."""
    if style == "c":
        begin, end = "/* gen_flags begin %s */" % name, "/* gen_flags end %s */" % name
    else:
        begin, end = "# gen_flags begin %s" % name, "# gen_flags end %s" % name
    pattern = re.compile(
        r"(^[ \t]*%s[ \t]*\n).*?(^[ \t]*%s[ \t]*$)" % (re.escape(begin), re.escape(end)),
        re.S | re.M,
    )
    if not pattern.search(text):
        raise SystemExit("marker block %s not found" % name)
    return pattern.sub(lambda m: m.group(1) + body + m.group(2), text, count=1)


def fmt_bytes(values, indent="    ", per_line=8):
    lines = []
    for i in range(0, len(values), per_line):
        lines.append(indent + ", ".join("0x%02x" % v for v in values[i:i + per_line]))
    return ",\n".join(lines) + "\n"


def lcg_states(seed, count):
    """The LCG used by ch01 and ch04: state = state * 1103515245 + 12345."""
    state = seed & MASK32
    for _ in range(count):
        yield state
        state = (state * 1103515245 + 12345) & MASK32


# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

def ch06_flag(vm_input):
    return "FLAG{%s}" % hashlib.sha256(vm_input).digest()[:20].hex()


def new_secrets():
    lines = [
        "# N4TIVE flags. Never commit this file.",
        "# Written by scripts/gen_flags.py new. Run `apply` after any change.",
    ]
    for ch in CHALLENGES[:5]:
        lines.append("%s=FLAG{%s}" % (ch, secrets.token_hex(INNER_LEN[ch] // 2)))
    vm_input = secrets.token_bytes(CH06_INPUT_LEN)
    lines.append("# ch06 has no free flag. It is derived from the 16-byte VM input.")
    lines.append("ch06_input=%s" % vm_input.hex())
    return "\n".join(lines) + "\n"


def load_secrets():
    if not SECRET_FILE.exists():
        raise SystemExit("%s is missing. Run: python scripts/gen_flags.py new" % SECRET_FILE.name)
    values = {}
    for line in SECRET_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip()

    flags = {}
    for ch in CHALLENGES[:5]:
        flag = values.get(ch, "")
        m = re.fullmatch(r"FLAG\{([0-9a-f]+)\}", flag)
        if not m or len(m.group(1)) != INNER_LEN[ch]:
            raise SystemExit("%s must be FLAG{<%d lowercase hex characters>}" % (ch, INNER_LEN[ch]))
        flags[ch] = flag
    try:
        vm_input = bytes.fromhex(values.get("ch06_input", ""))
    except ValueError:
        vm_input = b""
    if len(vm_input) != CH06_INPUT_LEN:
        raise SystemExit("ch06_input must be %d hex characters" % (CH06_INPUT_LEN * 2))
    flags["ch06"] = ch06_flag(vm_input)
    return flags, vm_input


def inner(flag):
    return list(flag[5:-1].encode("ascii"))


# --------------------------------------------------------------------------
# One builder per challenge. Each returns the body of its generated block.
# --------------------------------------------------------------------------

def build_ch01(src, flag):
    """Layer1(Layer2(Layer3(plaintext))), the inverse of decrypt_flag()."""
    plain = inner(flag)
    key3 = sum((c_array(src, "rodata_frag_" + s) for s in "abcde"), [])
    perm = c_array(src, "perm_table")
    stream = [s & 0xFF for s in lcg_states(c_scalar(src, "xor_seed"), 40)]
    if sorted(perm) != list(range(40)) or len(key3) != 40:
        raise SystemExit("ch01 tables have the wrong shape")

    layer3 = [p ^ k for p, k in zip(plain, key3)]
    layer2 = [layer3[perm[i]] for i in range(40)]
    enc = [b ^ k for b, k in zip(layer2, stream)]

    # Run the C decryption order on the result as a self-check.
    buf = [b ^ k for b, k in zip(enc, stream)]
    tmp = [0] * 40
    for i in range(40):
        tmp[perm[i]] = buf[i]
    assert [t ^ k for t, k in zip(tmp, key3)] == plain

    return "static const uint8_t encrypted_flag[40] = {\n" + fmt_bytes(enc) + "};\n"


def build_ch02(_src, flag):
    """The 42-character seed as big-endian words, last word half used."""
    seed = bytes(inner(flag))
    words = [int.from_bytes(seed[i:i + 4], "big") for i in range(0, 40, 4)]
    words.append((seed[40] << 24) | (seed[41] << 16))
    rows = []
    for i in range(0, len(words), 4):
        rows.append("        " + ", ".join("0x%08x" % w for w in words[i:i + 4]))
    return "    static const uint32_t magic[] = {\n" + ",\n".join(rows) + "\n    };\n"


def build_ch03(src, flag):
    """combine() XORs the four fragments with master_key."""
    fragments = sum((c_array(src, "fragment_" + s) for s in "abcd"), [])
    if len(fragments) != 40:
        raise SystemExit("ch03 fragments have the wrong shape")
    key = [f ^ p for f, p in zip(fragments, inner(flag))]
    return "static const uint8_t master_key[40] = {\n" + fmt_bytes(key) + "};\n"


def build_ch04(src, flag):
    """derive_flag() expands the seven key bytes with an LCG."""
    key_bytes = c_array(src, "expected_bytes")
    state = 0
    for i, k in enumerate(key_bytes):
        state ^= (k << ((i % 4) * 8)) & MASK32
    states = list(lcg_states(state, 43))[1:]          # the C code steps first
    full_key = [(s >> 16) & 0xFF for s in states]
    enc = [p ^ k for p, k in zip(inner(flag), full_key)]
    return "static const uint8_t enc_flag[42] = {\n" + fmt_bytes(enc) + "};\n"


def build_ch05(src, flag):
    """flag_generator() unmasks the whole flag with a rolling byte key."""
    key = c_define(src, "FLAG_MASK_SEED")
    mul, add = c_define(src, "FLAG_MASK_MUL"), c_define(src, "FLAG_MASK_ADD")
    masked = []
    for b in flag.encode("ascii"):
        masked.append(b ^ key)
        key = (key * mul + add) & 0xFF
    return "static const uint8_t masked_flag[%d] = {\n" % len(masked) + fmt_bytes(masked) + "};\n"


# --------------------------------------------------------------------------
# ch06: a tiny assembler for the VM in ch06_vm.c
# --------------------------------------------------------------------------

WITH_REG = {"POP", "LOAD", "STORE"}
WITH_IMM = {"PUSH", "JMP", "JEQ", "JNE", "JGT", "JLT", "CALL"}
# Sixteen fixed round keys. Public constants, nothing secret about them.
ROUND_KEYS = [
    int.from_bytes(hashlib.sha512(b"N4TIVE ch06 round keys").digest()[i:i + 4], "big")
    for i in range(0, 64, 4)
]


def rol32(value, count):
    count &= 31
    return ((value << count) | (value >> (32 - count))) & MASK32 if count else value


def ch06_expected(vm_input):
    """What the registers hold after the transformation, computed directly."""
    reg = list(vm_input)
    for k in range(0, 16, 2):
        reg[k] ^= reg[k + 1]
    for i in range(16):
        reg[i] = (rol32(reg[i], i + 1) + ROUND_KEYS[i]) & MASK32
    for i in range(16):
        reg[i] = (reg[i] + reg[(i + 7) % 16]) & MASK32
    return reg


def ch06_program(expected):
    """The program as rows of (label or None, [(mnemonic, operand), ...])."""
    rows = []

    def row(*ins, label=None):
        rows.append((label, list(ins)))

    for i in range(16):
        row(("INPUT", None), ("STORE", i))

    # Opaque predicate: two equal constants never compare unequal.
    row(("PUSH", 0x7A3C91E5), ("PUSH", 0x7A3C91E5), ("CMP", None), ("JNE", "dead_a"))
    row(label="back_a")

    for k in range(0, 16, 2):
        row(("LOAD", k), ("LOAD", k + 1), ("XOR", None), ("STORE", k))

    for i in range(16):
        row(("LOAD", i), ("PUSH", i + 1), ("ROL", None),
            ("PUSH", ROUND_KEYS[i]), ("ADD", None), ("STORE", i))

    # Opaque predicate: (x | 1) is never 0.
    row(("LOAD", 3), ("PUSH", 1), ("OR", None), ("PUSH", 0), ("CMP", None), ("JEQ", "dead_b"))
    row(label="back_b")

    for i in range(16):
        row(("LOAD", i), ("LOAD", (i + 7) % 16), ("ADD", None), ("STORE", i))

    for i in range(16):
        row(("LOAD", i), ("PUSH", expected[i]), ("CMP", None), ("JNE", "fail"))

    row(("PUSH", 1), ("OUTPUT", None), ("HALT", None))
    row(("PUSH", 0), ("OUTPUT", None), ("HALT", None), label="fail")

    # Dead blocks. Never reached, they only look like they alter state.
    row(("LOAD", 0), ("NOT", None), ("STORE", 0), ("JMP", "back_a"), label="dead_a")
    row(("PUSH", 0xDEADC0DE), ("STORE", 5), ("JMP", "back_b"), label="dead_b")
    return rows


def ins_size(mnemonic):
    return 5 if mnemonic in WITH_IMM else 2 if mnemonic in WITH_REG else 1


def ch06_assemble(rows, opcodes):
    """Return [(offset, bytes, text)] with labels resolved."""
    labels, offset = {}, 0
    for label, ins in rows:
        if label:
            labels[label] = offset
        offset += sum(ins_size(m) for m, _ in ins)

    out, offset = [], 0
    for label, ins in rows:
        code, text = [], []
        for mnemonic, operand in ins:
            code.append(opcodes[mnemonic])
            if mnemonic in WITH_REG:
                code.append(operand)
                text.append("%s R%d" % (mnemonic, operand))
            elif mnemonic in WITH_IMM:
                value = labels[operand] if isinstance(operand, str) else operand
                code += list(value.to_bytes(4, "little"))
                text.append("%s 0x%X" % (mnemonic, value) if mnemonic == "PUSH"
                            else "%s %04X" % (mnemonic, value))
            else:
                text.append(mnemonic)
        if code:
            out.append((offset, code, "; ".join(text)))
            offset += len(code)
    return out


def ch06_run(code, opcodes, vm_input):
    """Interpreter for the instructions the program uses. Returns the output bytes."""
    name = {v: k for k, v in opcodes.items()}
    reg, stack, out, pc, flag, pos, steps = [0] * 16, [], [], 0, 0, 0, 0
    binary = {
        "ADD": lambda a, b: a + b, "SUB": lambda a, b: a - b, "MUL": lambda a, b: a * b,
        "XOR": lambda a, b: a ^ b, "AND": lambda a, b: a & b, "OR": lambda a, b: a | b,
        "ROL": rol32,
    }
    while pc < len(code) and steps < 100000:
        steps += 1
        op = name.get(code[pc])
        pc += 1
        if op in WITH_IMM:
            imm = int.from_bytes(bytes(code[pc:pc + 4]), "little")
            pc += 4
        if op in WITH_REG:
            r = code[pc]
            pc += 1
        if op == "PUSH":
            stack.append(imm)
        elif op == "LOAD":
            stack.append(reg[r])
        elif op in ("STORE", "POP"):
            reg[r] = stack.pop()
        elif op in binary:
            b, a = stack.pop(), stack.pop()
            stack.append(binary[op](a, b) & MASK32)
        elif op == "NOT":
            stack.append(~stack.pop() & MASK32)
        elif op == "CMP":
            b, a = stack.pop(), stack.pop()
            flag = (a > b) - (a < b)
        elif op == "JMP":
            pc = imm
        elif op == "JEQ":
            pc = imm if flag == 0 else pc
        elif op == "JNE":
            pc = imm if flag != 0 else pc
        elif op == "INPUT":
            stack.append(vm_input[pos] if pos < len(vm_input) else 0)
            pos += 1
        elif op == "OUTPUT":
            out.append(stack.pop() & 0xFF)
        elif op == "HALT":
            break
        else:
            raise SystemExit("ch06 self-check hit an unexpected opcode at %d" % (pc - 1))
    return out


def build_ch06(src, vm_input):
    opcodes = {m: int(v, 16) for m, v in re.findall(r"\bOP_(\w+)\s*=\s*(0x[0-9A-Fa-f]+)", src)}
    xor_key = c_define(src, "BYTECODE_XOR_KEY")
    listing = ch06_assemble(ch06_program(ch06_expected(vm_input)), opcodes)
    code = [b for _, row_code, _ in listing for b in row_code]

    # Self-check: the right input passes, any single flipped bit fails.
    assert ch06_run(code, opcodes, vm_input) == [1]
    for i in range(CH06_INPUT_LEN * 8):
        wrong = bytearray(vm_input)
        wrong[i // 8] ^= 1 << (i % 8)
        assert ch06_run(code, opcodes, bytes(wrong)) == [0]

    lines = ["static const uint8_t encoded_bytecode[] = {"]
    for offset, row_code, text in listing:
        lines.append("    /* %04X  %s */" % (offset, text))
        encoded = ["0x%02X" % (b ^ xor_key) for b in row_code]
        for i in range(0, len(encoded), 12):
            lines.append("    " + ", ".join(encoded[i:i + 12]) + ",")
    lines.append("};")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Digest tables
# --------------------------------------------------------------------------

def digests(core_src, flags):
    salts = c_array(core_src, "challenge_salts")
    if len(salts) != 6 * 32:
        raise SystemExit("challenge_salts has the wrong shape")
    table = []
    for i, ch in enumerate(CHALLENGES):
        salt = bytes(salts[i * 32:(i + 1) * 32])
        table.append((ch, salt, hmac.new(salt, flags[ch].encode("ascii"), hashlib.sha256).digest()))
    return table


def build_digests_c(table):
    lines = ["static const uint8_t stored_digests[6][SHA256_DIGEST_SIZE] = {"]
    for n, (ch, _salt, digest) in enumerate(table):
        rows = [",".join("0x%02x" % b for b in digest[i:i + 8]) for i in range(0, 32, 8)]
        lines.append("    /* %s */ {%s," % (ch, rows[0]))
        lines += ["                %s," % r for r in rows[1:3]]
        lines.append("                %s}%s" % (rows[3], "," if n < 5 else ""))
    lines.append("};")
    return "\n".join(lines) + "\n"


def build_tables_sh(table):
    lines = ['SALTS[%s]="%s"' % (ch, salt.hex()) for ch, salt, _ in table]
    lines += ['DIGESTS[%s]="%s"' % (ch, digest.hex()) for ch, _, digest in table]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def render():
    """Return {path: (new_text, eol, old_text)} for every generated file."""
    flags, vm_input = load_secrets()
    jobs = [
        ("ch01_stringmaze.c", "encrypted_flag", lambda s: build_ch01(s, flags["ch01"])),
        ("ch02_stacksmasher.c", "magic", lambda s: build_ch02(s, flags["ch02"])),
        ("ch03_typeconfusion.c", "master_key", lambda s: build_ch03(s, flags["ch03"])),
        ("ch04_gauntlet.c", "enc_flag", lambda s: build_ch04(s, flags["ch04"])),
        ("ch05_heapcraft.c", "masked_flag", lambda s: build_ch05(s, flags["ch05"])),
        ("ch06_vm.c", "encoded_bytecode", lambda s: build_ch06(s, vm_input)),
    ]
    result = {}
    for filename, block, build in jobs:
        old, eol = read_text(JNI / filename)
        result[JNI / filename] = (replace_block(old, block, build(old)), eol, old)

    core_old, core_eol = read_text(JNI / "flag_core.c")
    table = digests(core_old, flags)
    result[JNI / "flag_core.c"] = (
        replace_block(core_old, "stored_digests", build_digests_c(table)), core_eol, core_old)

    sh_old, sh_eol = read_text(VERIFY_SH)
    result[VERIFY_SH] = (
        replace_block(sh_old, "tables", build_tables_sh(table), style="sh"), sh_eol, sh_old)
    return result


def cmd_new(args):
    if SECRET_FILE.exists() and not args.force:
        raise SystemExit("%s already exists. Use --force to replace every flag." % SECRET_FILE.name)
    with open(SECRET_FILE, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(new_secrets())
    print("wrote %s. Now run: python scripts/gen_flags.py apply" % SECRET_FILE.name)


def cmd_apply(_args):
    for path, (new, eol, old) in render().items():
        if new != old:
            write_text(path, new, eol)
        print("%-9s %s" % ("updated" if new != old else "unchanged", path.relative_to(ROOT).as_posix()))


def cmd_check(_args):
    stale = [path for path, (new, _eol, old) in render().items() if new != old]
    for path in stale:
        print("STALE     %s" % path.relative_to(ROOT).as_posix())
    if stale:
        raise SystemExit("sources differ from FLAGS_SECRET.txt. Run: python scripts/gen_flags.py apply")
    print("ok, every generated block matches FLAGS_SECRET.txt")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    new = sub.add_parser("new", help="create FLAGS_SECRET.txt with random flags")
    new.add_argument("--force", action="store_true", help="replace an existing secret file")
    new.set_defaults(func=cmd_new)
    sub.add_parser("apply", help="rewrite the generated blocks").set_defaults(func=cmd_apply)
    sub.add_parser("check", help="verify the sources against the secrets").set_defaults(func=cmd_check)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())

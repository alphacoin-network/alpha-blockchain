"""Bitcoin Script: opcodes, the stack interpreter, and standard templates.

Implements the same execution semantics as Bitcoin Core's EvalScript /
VerifyScript, including P2SH wrapping, segwit v0 witness programs
(BIP141), OP_CODESEPARATOR, CLTV (BIP65) and CSV (BIP112).
"""

import struct
from dataclasses import dataclass

from . import crypto
from .transaction import (
    SIGHASH_ALL, SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE,
    SIGHASH_SINGLE,
)
from .utils import (
    BytesReader, decode_script_num, encode_script_num, hash160,
    ripemd160, ser_compact_size, sha256, sha256d,
)


class ScriptError(Exception):
    pass


# ---------------------------------------------------------------------------
# Opcodes (identical numeric assignments to Bitcoin)
# ---------------------------------------------------------------------------
OP_0 = OP_FALSE = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1NEGATE = 0x4F
OP_RESERVED = 0x50
OP_1 = OP_TRUE = 0x51
OP_2, OP_3, OP_4, OP_5 = 0x52, 0x53, 0x54, 0x55
OP_6, OP_7, OP_8, OP_9 = 0x56, 0x57, 0x58, 0x59
OP_10, OP_11, OP_12, OP_13 = 0x5A, 0x5B, 0x5C, 0x5D
OP_14, OP_15, OP_16 = 0x5E, 0x5F, 0x60

OP_NOP = 0x61
OP_VER = 0x62
OP_IF = 0x63
OP_NOTIF = 0x64
OP_VERIF = 0x65
OP_VERNOTIF = 0x66
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_VERIFY = 0x69
OP_RETURN = 0x6A

OP_TOALTSTACK = 0x6B
OP_FROMALTSTACK = 0x6C
OP_2DROP = 0x6D
OP_2DUP = 0x6E
OP_3DUP = 0x6F
OP_2OVER = 0x70
OP_2ROT = 0x71
OP_2SWAP = 0x72
OP_IFDUP = 0x73
OP_DEPTH = 0x74
OP_DROP = 0x75
OP_DUP = 0x76
OP_NIP = 0x77
OP_OVER = 0x78
OP_PICK = 0x79
OP_ROLL = 0x7A
OP_ROT = 0x7B
OP_SWAP = 0x7C
OP_TUCK = 0x7D

# disabled
OP_CAT = 0x7E
OP_SUBSTR = 0x7F
OP_LEFT = 0x80
OP_RIGHT = 0x81

OP_SIZE = 0x82

# disabled
OP_INVERT = 0x83
OP_AND = 0x84
OP_OR = 0x85
OP_XOR = 0x86

OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_RESERVED1 = 0x89
OP_RESERVED2 = 0x8A

OP_1ADD = 0x8B
OP_1SUB = 0x8C
OP_2MUL = 0x8D          # disabled
OP_2DIV = 0x8E          # disabled
OP_NEGATE = 0x8F
OP_ABS = 0x90
OP_NOT = 0x91
OP_0NOTEQUAL = 0x92
OP_ADD = 0x93
OP_SUB = 0x94
OP_MUL = 0x95           # disabled
OP_DIV = 0x96           # disabled
OP_MOD = 0x97           # disabled
OP_LSHIFT = 0x98        # disabled
OP_RSHIFT = 0x99        # disabled
OP_BOOLAND = 0x9A
OP_BOOLOR = 0x9B
OP_NUMEQUAL = 0x9C
OP_NUMEQUALVERIFY = 0x9D
OP_NUMNOTEQUAL = 0x9E
OP_LESSTHAN = 0x9F
OP_GREATERTHAN = 0xA0
OP_LESSTHANOREQUAL = 0xA1
OP_GREATERTHANOREQUAL = 0xA2
OP_MIN = 0xA3
OP_MAX = 0xA4
OP_WITHIN = 0xA5

OP_RIPEMD160 = 0xA6
OP_SHA1 = 0xA7
OP_SHA256 = 0xA8
OP_HASH160 = 0xA9
OP_HASH256 = 0xAA
OP_CODESEPARATOR = 0xAB
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF

OP_NOP1 = 0xB0
OP_CHECKLOCKTIMEVERIFY = OP_NOP2 = 0xB1
OP_CHECKSEQUENCEVERIFY = OP_NOP3 = 0xB2
OP_NOP4 = 0xB3
OP_NOP5 = 0xB4
OP_NOP6 = 0xB5
OP_NOP7 = 0xB6
OP_NOP8 = 0xB7
OP_NOP9 = 0xB8
OP_NOP10 = 0xB9

OP_INVALIDOPCODE = 0xFF

DISABLED_OPS = {
    OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT, OP_INVERT, OP_AND, OP_OR, OP_XOR,
    OP_2MUL, OP_2DIV, OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT,
}

# ---------------------------------------------------------------------------
# Script verification flags (same bit meanings as Bitcoin)
# ---------------------------------------------------------------------------
SCRIPT_VERIFY_NONE = 0
SCRIPT_VERIFY_P2SH = 1 << 0
SCRIPT_VERIFY_STRICTENC = 1 << 1
SCRIPT_VERIFY_DERSIG = 1 << 2
SCRIPT_VERIFY_LOW_S = 1 << 3
SCRIPT_VERIFY_NULLDUMMY = 1 << 4
SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5
SCRIPT_VERIFY_MINIMALDATA = 1 << 6
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7
SCRIPT_VERIFY_CLEANSTACK = 1 << 8
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = 1 << 10
SCRIPT_VERIFY_WITNESS = 1 << 11
SCRIPT_VERIFY_MINIMALIF = 1 << 13
SCRIPT_VERIFY_NULLFAIL = 1 << 14
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE = 1 << 15

MANDATORY_SCRIPT_FLAGS = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS

STANDARD_SCRIPT_FLAGS = (
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG
    | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLDUMMY | SCRIPT_VERIFY_MINIMALDATA
    | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_CLEANSTACK
    | SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
    | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_MINIMALIF | SCRIPT_VERIFY_NULLFAIL
    | SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
)

MAX_SCRIPT_ELEMENT_SIZE = 520
MAX_OPS_PER_SCRIPT = 201
MAX_STACK_SIZE = 1000
MAX_PUBKEYS_PER_MULTISIG = 20
LOCKTIME_THRESHOLD = 500_000_000

SIGVERSION_BASE = 0
SIGVERSION_WITNESS_V0 = 1
SIGVERSION_TAPROOT = 2
SIGVERSION_TAPSCRIPT = 3

OP_CHECKSIGADD = 0xBA   # BIP342 tapscript multisig opcode


# ---------------------------------------------------------------------------
# Script parsing / building
# ---------------------------------------------------------------------------
@dataclass
class ScriptOp:
    opcode: int
    data: bytes | None          # pushed data, or None for plain opcodes
    start: int                  # byte offset of the opcode
    end: int                    # byte offset just past this op


def parse_script(script: bytes):
    """Yield ScriptOp for each instruction. Raises ScriptError on truncation."""
    i = 0
    n = len(script)
    while i < n:
        start = i
        opcode = script[i]
        i += 1
        data = None
        if opcode <= 75:
            size = opcode
        elif opcode == OP_PUSHDATA1:
            if i + 1 > n:
                raise ScriptError("truncated PUSHDATA1")
            size = script[i]
            i += 1
        elif opcode == OP_PUSHDATA2:
            if i + 2 > n:
                raise ScriptError("truncated PUSHDATA2")
            size = struct.unpack_from("<H", script, i)[0]
            i += 2
        elif opcode == OP_PUSHDATA4:
            if i + 4 > n:
                raise ScriptError("truncated PUSHDATA4")
            size = struct.unpack_from("<I", script, i)[0]
            i += 4
        else:
            yield ScriptOp(opcode, None, start, i)
            continue
        if i + size > n:
            raise ScriptError("truncated push data")
        data = script[i:i + size]
        i += size
        yield ScriptOp(opcode, data, start, i)


def script_ops(script: bytes):
    return list(parse_script(script))


def push_data(data: bytes) -> bytes:
    """Minimally encode a data push."""
    n = len(data)
    if n < OP_1:
        if n == 0:
            return bytes([OP_0])
        if n == 1 and 1 <= data[0] <= 16:
            return bytes([OP_1 - 1 + data[0]])
        if n == 1 and data[0] == 0x81:
            return bytes([OP_1NEGATE])
        return bytes([n]) + data
    if n <= 75:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([OP_PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([OP_PUSHDATA2]) + struct.pack("<H", n) + data
    return bytes([OP_PUSHDATA4]) + struct.pack("<I", n) + data


def push_int(v: int) -> bytes:
    return push_data(encode_script_num(v))


def is_push_only(script: bytes) -> bool:
    try:
        return all(op.opcode <= OP_16 for op in parse_script(script))
    except ScriptError:
        return False


def is_minimal_push(op: ScriptOp) -> bool:
    data = op.data
    if data is None:
        return True
    if len(data) == 0:
        return op.opcode == OP_0
    if len(data) == 1 and 1 <= data[0] <= 16:
        return op.opcode == OP_1 - 1 + data[0]
    if len(data) == 1 and data[0] == 0x81:
        return op.opcode == OP_1NEGATE
    if len(data) <= 75:
        return op.opcode == len(data)
    if len(data) <= 255:
        return op.opcode == OP_PUSHDATA1
    if len(data) <= 65535:
        return op.opcode == OP_PUSHDATA2
    return True


def cast_to_bool(b: bytes) -> bool:
    for i, ch in enumerate(b):
        if ch != 0:
            if i == len(b) - 1 and ch == 0x80:  # negative zero
                return False
            return True
    return False


# ---------------------------------------------------------------------------
# Standard script templates
# ---------------------------------------------------------------------------
def script_p2pk(pubkey: bytes) -> bytes:
    return push_data(pubkey) + bytes([OP_CHECKSIG])


def script_p2pkh(pubkey_hash: bytes) -> bytes:
    return (bytes([OP_DUP, OP_HASH160]) + push_data(pubkey_hash)
            + bytes([OP_EQUALVERIFY, OP_CHECKSIG]))


def script_p2sh(script_hash: bytes) -> bytes:
    return bytes([OP_HASH160]) + push_data(script_hash) + bytes([OP_EQUAL])


def script_p2wpkh(pubkey_hash: bytes) -> bytes:
    return bytes([OP_0]) + push_data(pubkey_hash)


def script_p2wsh(script_hash: bytes) -> bytes:
    return bytes([OP_0]) + push_data(script_hash)


def script_multisig(m: int, pubkeys) -> bytes:
    out = bytes([OP_1 - 1 + m])
    for pk in pubkeys:
        out += push_data(pk)
    out += bytes([OP_1 - 1 + len(pubkeys), OP_CHECKMULTISIG])
    return out


def script_op_return(data: bytes) -> bytes:
    return bytes([OP_RETURN]) + push_data(data)


TX_NONSTANDARD = "nonstandard"
TX_PUBKEY = "pubkey"           # P2PK
TX_PUBKEYHASH = "pubkeyhash"   # P2PKH
TX_SCRIPTHASH = "scripthash"   # P2SH
TX_MULTISIG = "multisig"
TX_NULL_DATA = "nulldata"
TX_WITNESS_V0_KEYHASH = "witness_v0_keyhash"    # P2WPKH
TX_WITNESS_V0_SCRIPTHASH = "witness_v0_scripthash"  # P2WSH
TX_WITNESS_V1_TAPROOT = "witness_v1_taproot"    # P2TR
TX_WITNESS_UNKNOWN = "witness_unknown"


def witness_program(script: bytes):
    """If script is a segwit program, return (version, program bytes)."""
    if 4 <= len(script) <= 42 and script[0] in (OP_0, *range(OP_1, OP_16 + 1)):
        ver = 0 if script[0] == OP_0 else script[0] - OP_1 + 1
        size = script[1]
        if size == len(script) - 2 and 2 <= size <= 40:
            if ver == 0 and size not in (20, 32):
                return None
            return ver, script[2:]
    return None


def solver(script: bytes):
    """Classify a scriptPubKey. Returns (type, payload)."""
    wp = witness_program(script)
    if wp is not None:
        ver, prog = wp
        if ver == 0 and len(prog) == 20:
            return TX_WITNESS_V0_KEYHASH, prog
        if ver == 0 and len(prog) == 32:
            return TX_WITNESS_V0_SCRIPTHASH, prog
        if ver == 1 and len(prog) == 32:
            return TX_WITNESS_V1_TAPROOT, prog
        return TX_WITNESS_UNKNOWN, (ver, prog)

    if (len(script) == 25 and script[0] == OP_DUP and script[1] == OP_HASH160
            and script[2] == 20 and script[23] == OP_EQUALVERIFY
            and script[24] == OP_CHECKSIG):
        return TX_PUBKEYHASH, script[3:23]

    if (len(script) == 23 and script[0] == OP_HASH160 and script[1] == 20
            and script[22] == OP_EQUAL):
        return TX_SCRIPTHASH, script[2:22]

    # P2PK: <33|65 pubkey> OP_CHECKSIG
    if ((len(script) == 35 and script[0] == 33 and script[34] == OP_CHECKSIG)
            or (len(script) == 67 and script[0] == 65
                and script[66] == OP_CHECKSIG)):
        pk = script[1:-1]
        if crypto.is_valid_pubkey(pk):
            return TX_PUBKEY, pk

    # multisig: OP_m <pubkeys...> OP_n OP_CHECKMULTISIG
    try:
        ops = script_ops(script)
        if (len(ops) >= 4 and ops[-1].opcode == OP_CHECKMULTISIG
                and OP_1 <= ops[0].opcode <= OP_16
                and OP_1 <= ops[-2].opcode <= OP_16
                and all(o.data is not None for o in ops[1:-2])):
            m = ops[0].opcode - OP_1 + 1
            n = ops[-2].opcode - OP_1 + 1
            keys = [o.data for o in ops[1:-2]]
            if len(keys) == n and 1 <= m <= n <= MAX_PUBKEYS_PER_MULTISIG:
                return TX_MULTISIG, (m, keys)
    except ScriptError:
        pass

    if script and script[0] == OP_RETURN and is_push_only(script[1:]):
        return TX_NULL_DATA, None

    return TX_NONSTANDARD, None


def extract_destination(script: bytes, params):
    """Return an address string for standard scriptPubKeys, else None."""
    from .base58 import b58encode_check
    from .bech32 import encode_segwit_address

    typ, data = solver(script)
    if typ == TX_PUBKEYHASH:
        return b58encode_check(bytes([params.base58_pubkey_address]) + data)
    if typ == TX_SCRIPTHASH:
        return b58encode_check(bytes([params.base58_script_address]) + data)
    if typ == TX_PUBKEY:
        return b58encode_check(
            bytes([params.base58_pubkey_address]) + hash160(data))
    if typ in (TX_WITNESS_V0_KEYHASH, TX_WITNESS_V0_SCRIPTHASH):
        return encode_segwit_address(params.bech32_hrp, 0, data)
    if typ == TX_WITNESS_UNKNOWN:
        ver, prog = data
        return encode_segwit_address(params.bech32_hrp, ver, prog)
    return None


def script_for_address(addr: str, params):
    """Decode an address into the corresponding scriptPubKey."""
    from .base58 import b58decode_check
    from .bech32 import decode_segwit_address

    try:
        payload = b58decode_check(addr)
        if len(payload) == 21:
            ver, h = payload[0], payload[1:]
            if ver == params.base58_pubkey_address:
                return script_p2pkh(h)
            if ver == params.base58_script_address:
                return script_p2sh(h)
    except ValueError:
        pass
    try:
        witver, witprog = decode_segwit_address(params.bech32_hrp, addr)
        if witver == 0:
            return bytes([OP_0]) + push_data(witprog)
        return bytes([OP_1 - 1 + witver]) + push_data(witprog)
    except ValueError:
        pass
    raise ValueError(f"invalid address: {addr}")


# ---------------------------------------------------------------------------
# Signature-operation counting (identical logic to Bitcoin GetSigOpCount)
# ---------------------------------------------------------------------------
def get_sig_op_count(script: bytes, accurate: bool = True) -> int:
    count = 0
    last_opcode = OP_INVALIDOPCODE
    try:
        for op in parse_script(script):
            if op.opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
                count += 1
            elif op.opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
                if accurate and OP_1 <= last_opcode <= OP_16:
                    count += last_opcode - OP_1 + 1
                else:
                    count += MAX_PUBKEYS_PER_MULTISIG
            last_opcode = op.opcode
    except ScriptError:
        return count
    return count


def count_p2sh_sigops(script_sig: bytes, script_pubkey: bytes) -> int:
    """Sigops in a P2SH redeem script (block accounting)."""
    typ, _ = solver(script_pubkey)
    if typ != TX_SCRIPTHASH or not is_push_only(script_sig):
        return get_sig_op_count(script_pubkey, True)
    ops = script_ops(script_sig)
    if not ops:
        return 0
    subscript = ops[-1].data or b""
    return get_sig_op_count(subscript, True)


def count_witness_sigops(script_pubkey: bytes, script_sig: bytes, witness) -> int:
    """Witness sigops (BIP141): these count at 1/4 weight in the sigop limit."""
    wp = witness_program(script_pubkey)
    if wp is None:
        typ, _ = solver(script_pubkey)
        if typ == TX_SCRIPTHASH and is_push_only(script_sig) and script_sig:
            redeem = script_ops(script_sig)[-1].data or b""
            wp = witness_program(redeem)
            if wp:
                script_pubkey = redeem
            else:
                return 0
        else:
            return 0
    ver, prog = wp
    if ver != 0:
        return 0
    if len(prog) == 20:  # P2WPKH: one sigop
        return 1
    if len(prog) == 32 and witness:  # P2WSH: count in witness script
        return get_sig_op_count(witness[-1], True)
    return 0


# ---------------------------------------------------------------------------
# The interpreter
# ---------------------------------------------------------------------------
@dataclass
class ScriptContext:
    tx: object                  # Transaction being validated
    n_in: int                   # input index
    amount: int                 # value of the spent output (segwit sighash)
    flags: int
    sigversion: int = SIGVERSION_BASE
    block_height: int = 0       # for CLTV/CSV context
    block_time: int = 0
    all_prevouts: dict | None = None  # {"amounts":[...], "spks":[...]} for BIP341
    tapleaf_hash: bytes = b""         # for tapscript script-path sighash
    tapleaf_codesep_pos: int = 0xFFFFFFFF  # last executed OP_CODESEPARATOR


def _check_sig_encoding(sig: bytes, flags: int) -> None:
    """Verify signature encoding (hashtype byte + DER + low-S)."""
    if not sig:
        return  # empty sig is not a real sig; it just evaluates false
    if flags & SCRIPT_VERIFY_STRICTENC:
        hash_type = sig[-1]
        if (hash_type & SIGHASH_MASK) not in (SIGHASH_ALL, SIGHASH_NONE,
                                            SIGHASH_SINGLE):
            raise ScriptError("bad sighash type")
    if flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S):
        if not crypto.is_valid_der(sig[:-1]):
            raise ScriptError("non-DER signature")
    if flags & SCRIPT_VERIFY_LOW_S:
        try:
            _, s = crypto.der_decode_sig(sig[:-1], strict=True)
        except ValueError:
            raise ScriptError("cannot parse signature")
        if s > crypto.ORDER_N // 2:
            raise ScriptError("high-S signature")


def _check_pubkey_encoding(pubkey: bytes, flags: int, sigversion: int) -> None:
    if (sigversion == SIGVERSION_WITNESS_V0
            and flags & SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
            and not crypto.is_compressed_pubkey(pubkey)):
        raise ScriptError("uncompressed pubkey in witness")
    if flags & SCRIPT_VERIFY_STRICTENC and not crypto.is_valid_pubkey(pubkey):
        raise ScriptError("bad pubkey encoding")


def eval_script(stack: list, script: bytes, ctx: ScriptContext) -> None:
    """Execute `script` against `stack` (mutated in place).

    Raises ScriptError on failure. Faithful to Bitcoin's EvalScript.
    """
    if len(script) > 10000:
        raise ScriptError("script too large")

    altstack: list = []
    vf_exec: list = []   # conditional execution stack
    last_codesep_end = 0  # byte position after the last executed CODESEPARATOR
    op_count = 0

    try:
        ops = script_ops(script)
    except ScriptError:
        raise ScriptError("script parse error")

    for op in ops:
        f_exec = all(vf_exec)

        # --- data pushes ----------------------------------------------------
        if op.data is not None or op.opcode <= OP_PUSHDATA4:
            if op.data is not None and len(op.data) > MAX_SCRIPT_ELEMENT_SIZE:
                raise ScriptError("pushed item too large")
            if f_exec:
                if ctx.flags & SCRIPT_VERIFY_MINIMALDATA and not is_minimal_push(op):
                    raise ScriptError("non-minimal push")
                stack.append(op.data if op.data is not None else b"")
            continue

        opcode = op.opcode
        if opcode > OP_16:
            op_count += 1
            if op_count > MAX_OPS_PER_SCRIPT:
                raise ScriptError("too many opcodes")

        # --- conditional flow ------------------------------------------------
        if opcode in (OP_IF, OP_NOTIF):
            value = False
            if f_exec:
                if not stack:
                    raise ScriptError("unbalanced conditional")
                vch = stack.pop()
                if ctx.flags & SCRIPT_VERIFY_MINIMALIF and len(vch) > 1:
                    raise ScriptError("MINIMALIF violation")
                if len(vch) == 1 and vch[0] not in (1,):
                    raise ScriptError("MINIMALIF violation")
                value = cast_to_bool(vch)
                if opcode == OP_NOTIF:
                    value = not value
            vf_exec.append(value)
            continue
        if opcode == OP_ELSE:
            if not vf_exec:
                raise ScriptError("unbalanced ELSE")
            vf_exec[-1] = not vf_exec[-1]
            continue
        if opcode == OP_ENDIF:
            if not vf_exec:
                raise ScriptError("unbalanced ENDIF")
            vf_exec.pop()
            continue

        if not f_exec:
            continue

        # --- small integer pushes ---------------------------------------------
        if opcode == OP_1NEGATE:
            stack.append(encode_script_num(-1))
            continue
        if OP_1 <= opcode <= OP_16:
            stack.append(encode_script_num(opcode - OP_1 + 1))
            continue

        # --- plain opcodes ----------------------------------------------------
        if opcode == OP_NOP:
            pass
        elif opcode in (OP_VER,):
            raise ScriptError("OP_VER is forbidden")
        elif opcode in (OP_VERIF, OP_VERNOTIF):
            raise ScriptError("OP_VERIF/VERNOTIF are forbidden")
        elif opcode == OP_VERIFY:
            if not stack:
                raise ScriptError("VERIFY on empty stack")
            if not cast_to_bool(stack.pop()):
                raise ScriptError("VERIFY failed")
        elif opcode == OP_RETURN:
            raise ScriptError("OP_RETURN encountered")

        elif opcode == OP_TOALTSTACK:
            if not stack:
                raise ScriptError("stack underflow")
            altstack.append(stack.pop())
        elif opcode == OP_FROMALTSTACK:
            if not altstack:
                raise ScriptError("altstack underflow")
            stack.append(altstack.pop())
        elif opcode in (OP_DROP, OP_2DROP, OP_3DUP, OP_2DUP, OP_2OVER,
                        OP_2ROT, OP_2SWAP, OP_IFDUP, OP_DEPTH, OP_DUP,
                        OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP,
                        OP_TUCK):
            _stack_op(opcode, stack)
        elif opcode in DISABLED_OPS:
            raise ScriptError("disabled opcode executed")
        elif opcode == OP_SIZE:
            if not stack:
                raise ScriptError("stack underflow")
            stack.append(encode_script_num(len(stack[-1])))
        elif opcode == OP_EQUAL or opcode == OP_EQUALVERIFY:
            if len(stack) < 2:
                raise ScriptError("stack underflow")
            a, b = stack.pop(), stack.pop()
            stack.append(b"\x01" if a == b else b"")
            if opcode == OP_EQUALVERIFY:
                if not cast_to_bool(stack.pop()):
                    raise ScriptError("EQUALVERIFY failed")
        elif opcode in (OP_RESERVED1, OP_RESERVED2, OP_RESERVED):
            raise ScriptError("reserved opcode executed")

        elif opcode in (OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT,
                        OP_0NOTEQUAL, OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR,
                        OP_NUMEQUAL, OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL,
                        OP_LESSTHAN, OP_GREATERTHAN, OP_LESSTHANOREQUAL,
                        OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX, OP_WITHIN,
                        OP_1NEGATE):
            _arith_op(opcode, stack, ctx)

        elif opcode in (OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160,
                        OP_HASH256):
            if not stack:
                raise ScriptError("stack underflow")
            v = stack.pop()
            if opcode == OP_RIPEMD160:
                stack.append(ripemd160(v))
            elif opcode == OP_SHA1:
                import hashlib as _hl
                stack.append(_hl.sha1(v).digest())
            elif opcode == OP_SHA256:
                stack.append(sha256(v))
            elif opcode == OP_HASH160:
                stack.append(hash160(v))
            else:
                stack.append(sha256d(v))
        elif opcode == OP_CODESEPARATOR:
            last_codesep_end = op.end
            ctx.tapleaf_codesep_pos = op.start   # BIP342 codesep position
        elif opcode in (OP_CHECKSIG, OP_CHECKSIGVERIFY):
            if len(stack) < 2:
                raise ScriptError("stack underflow")
            pubkey = stack.pop()
            sig = stack.pop()
            ok = False
            if ctx.sigversion == SIGVERSION_TAPSCRIPT:
                # BIP342: x-only pubkey + schnorr sig (empty sig = just false)
                if sig:
                    if len(pubkey) != 32:
                        raise ScriptError("tapscript needs 32B x-only pubkey")
                    ok = _check_signature(sig, pubkey, b"", ctx)
            elif sig:
                if ctx.flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S
                                | SCRIPT_VERIFY_STRICTENC):
                    _check_sig_encoding(sig, ctx.flags)
                if ctx.flags & SCRIPT_VERIFY_STRICTENC:
                    _check_pubkey_encoding(pubkey, ctx.flags, ctx.sigversion)
                subscript = script[last_codesep_end:]
                # remove the signature itself from the hashed subscript
                subscript = subscript.replace(push_data(sig), b"")
                ok = _check_signature(sig, pubkey, subscript, ctx)
            elif ctx.flags & SCRIPT_VERIFY_NULLFAIL:
                pass
            if not ok and sig and ctx.flags & SCRIPT_VERIFY_NULLFAIL:
                raise ScriptError("NULLFAIL: signature must be empty on failure")
            if opcode == OP_CHECKSIGVERIFY:
                if not ok:
                    raise ScriptError("CHECKSIGVERIFY failed")
            else:
                stack.append(b"\x01" if ok else b"")
        elif opcode == OP_CHECKSIGADD:
            # BIP342: <sig> <n> <pubkey> -> <n + (sig valid ? 1 : 0)>
            if ctx.sigversion != SIGVERSION_TAPSCRIPT:
                raise ScriptError("OP_CHECKSIGADD is tapscript-only")
            if len(stack) < 3:
                raise ScriptError("stack underflow")
            pubkey = stack.pop()
            n = decode_script_num(stack.pop())
            sig = stack.pop()
            if len(pubkey) != 32:
                raise ScriptError("tapscript needs 32B x-only pubkey")
            incr = 1 if (sig and _check_signature(sig, pubkey, b"", ctx)) else 0
            stack.append(encode_script_num(n + incr))
        elif opcode in (OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY):
            if not stack:
                raise ScriptError("stack underflow")
            n_keys = decode_script_num(stack.pop())
            if not 0 <= n_keys <= MAX_PUBKEYS_PER_MULTISIG:
                raise ScriptError("bad pubkey count")
            op_count += n_keys
            if op_count > MAX_OPS_PER_SCRIPT:
                raise ScriptError("too many opcodes")
            if len(stack) < n_keys:
                raise ScriptError("stack underflow")
            pubkeys = stack[len(stack) - n_keys:]
            del stack[len(stack) - n_keys:]
            if not stack:
                raise ScriptError("stack underflow")
            n_sigs = decode_script_num(stack.pop())
            if not 0 <= n_sigs <= n_keys:
                raise ScriptError("bad signature count")
            if len(stack) < n_sigs + 1:
                raise ScriptError("stack underflow")
            sigs = stack[len(stack) - n_sigs:]
            del stack[len(stack) - n_sigs:]
            dummy = stack.pop()
            if ctx.flags & SCRIPT_VERIFY_NULLDUMMY and dummy != b"":
                raise ScriptError("NULLDUMMY violation")

            subscript = script[last_codesep_end:]
            for sig in sigs:
                subscript = subscript.replace(push_data(sig), b"")

            ok = True
            sig_idx = 0
            key_idx = 0
            while sig_idx < n_sigs:
                sig = sigs[sig_idx]
                pubkey = pubkeys[key_idx]
                if sig:
                    try:
                        if ctx.flags & (SCRIPT_VERIFY_DERSIG
                                        | SCRIPT_VERIFY_LOW_S
                                        | SCRIPT_VERIFY_STRICTENC):
                            _check_sig_encoding(sig, ctx.flags)
                        if ctx.flags & SCRIPT_VERIFY_STRICTENC:
                            _check_pubkey_encoding(pubkey, ctx.flags,
                                                   ctx.sigversion)
                        valid = _check_signature(sig, pubkey, subscript, ctx)
                    except ScriptError:
                        raise
                else:
                    valid = False
                if valid:
                    sig_idx += 1
                key_idx += 1
                if n_sigs - sig_idx > n_keys - key_idx:
                    ok = False
                    break
            # any remaining non-empty sigs violating NULLFAIL
            if not ok and ctx.flags & SCRIPT_VERIFY_NULLFAIL:
                for sig in sigs:
                    if sig:
                        raise ScriptError("NULLFAIL in multisig")
            if opcode == OP_CHECKMULTISIGVERIFY:
                if not ok:
                    raise ScriptError("CHECKMULTISIGVERIFY failed")
            else:
                stack.append(b"\x01" if ok else b"")
        elif opcode in (OP_NOP1, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8,
                        OP_NOP9, OP_NOP10):
            if ctx.flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS:
                raise ScriptError("NOPx discouraged")
        elif opcode == OP_CHECKLOCKTIMEVERIFY:
            if ctx.flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY:
                _check_cltv(stack, ctx)
            elif ctx.flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS:
                raise ScriptError("NOP2 discouraged")
        elif opcode == OP_CHECKSEQUENCEVERIFY:
            if ctx.flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY:
                _check_csv(stack, ctx)
            elif ctx.flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS:
                raise ScriptError("NOP3 discouraged")
        else:
            raise ScriptError(f"bad opcode 0x{opcode:02x}")

        if len(stack) + len(altstack) > MAX_STACK_SIZE:
            raise ScriptError("stack size limit exceeded")

    if vf_exec:
        raise ScriptError("unbalanced IF/ENDIF")


def _check_signature(sig: bytes, pubkey: bytes, script_code: bytes,
                     ctx: ScriptContext) -> bool:
    if ctx.sigversion == SIGVERSION_TAPSCRIPT:
        # BIP342: schnorr sig, 64B (default) or 65B (with hash_type byte)
        from . import schnorr as _schnorr
        from .transaction import hashlib_tagged
        if len(sig) not in (64, 65):
            return False
        hash_type = sig[64] if len(sig) == 65 else 0x00
        if hash_type not in (0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83):
            return False
        ext = (ctx.tapleaf_hash + b"\x00"
               + struct.pack("<I", ctx.tapleaf_codesep_pos))
        sighash = ctx.tx.signature_hash_v1(
            ctx.n_in, ctx.all_prevouts["amounts"],
            ctx.all_prevouts["spks"], hash_type, ext=ext)
        return _schnorr.schnorr_verify(sighash, pubkey, sig[:64])
    hash_type = sig[-1]
    try:
        if ctx.sigversion == SIGVERSION_WITNESS_V0:
            sighash = ctx.tx.signature_hash_v0(
                script_code, ctx.n_in, ctx.amount, hash_type)
        else:
            sighash = ctx.tx.signature_hash(script_code, ctx.n_in, hash_type)
    except (IndexError, ValueError):
        return False
    return crypto.ecdsa_verify(sighash, sig[:-1], pubkey)


def _stack_op(opcode: int, stack: list) -> None:
    def need(n):
        if len(stack) < n:
            raise ScriptError("stack underflow")

    if opcode == OP_DROP:
        need(1)
        stack.pop()
    elif opcode == OP_2DROP:
        need(2)
        stack.pop()
        stack.pop()
    elif opcode == OP_2DUP:
        need(2)
        stack.extend(stack[-2:])
    elif opcode == OP_3DUP:
        need(3)
        stack.extend(stack[-3:])
    elif opcode == OP_2OVER:
        need(4)
        stack.extend(stack[-4:-2])
    elif opcode == OP_2ROT:
        need(6)
        stack.append(stack.pop(-6))
        stack.append(stack.pop(-6))
    elif opcode == OP_2SWAP:
        need(4)
        stack[-4:-2], stack[-2:] = stack[-2:], stack[-4:-2]
    elif opcode == OP_IFDUP:
        need(1)
        if cast_to_bool(stack[-1]):
            stack.append(stack[-1])
    elif opcode == OP_DEPTH:
        stack.append(encode_script_num(len(stack)))
    elif opcode == OP_DUP:
        need(1)
        stack.append(stack[-1])
    elif opcode == OP_NIP:
        need(2)
        del stack[-2]
    elif opcode == OP_OVER:
        need(2)
        stack.append(stack[-2])
    elif opcode in (OP_PICK, OP_ROLL):
        need(2)
        n = decode_script_num(stack.pop())
        if n < 0 or n >= len(stack):
            raise ScriptError("PICK/ROLL out of range")
        idx = len(stack) - n - 1
        if opcode == OP_PICK:
            stack.append(stack[idx])
        else:
            stack.append(stack.pop(idx))
    elif opcode == OP_ROT:
        need(3)
        stack.append(stack.pop(-3))
    elif opcode == OP_SWAP:
        need(2)
        stack[-1], stack[-2] = stack[-2], stack[-1]
    elif opcode == OP_TUCK:
        need(2)
        stack.insert(-2, stack[-1])


def _num(stack: list, minimal: bool = False) -> int:
    if not stack:
        raise ScriptError("stack underflow")
    try:
        return decode_script_num(stack.pop(), max_size=4,
                                 require_minimal=minimal)
    except ValueError as e:
        raise ScriptError(str(e))


def _arith_op(opcode: int, stack: list, ctx: ScriptContext) -> None:
    minimal = bool(ctx.flags & SCRIPT_VERIFY_MINIMALDATA)
    if opcode == OP_1NEGATE:
        stack.append(encode_script_num(-1))
        return
    binary = opcode in (OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
                        OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN,
                        OP_GREATERTHAN, OP_LESSTHANOREQUAL,
                        OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX)
    ternary = opcode == OP_WITHIN
    if ternary:
        if len(stack) < 3:
            raise ScriptError("stack underflow")
        c = _num(stack, minimal)
        b = _num(stack, minimal)
        a = _num(stack, minimal)
        stack.append(b"\x01" if b <= a < c else b"")
        return
    if binary:
        if len(stack) < 2:
            raise ScriptError("stack underflow")
        b = _num(stack, minimal)
        a = _num(stack, minimal)
    else:
        if len(stack) < 1:
            raise ScriptError("stack underflow")
        a = _num(stack, minimal)
        b = 0

    if opcode == OP_1ADD:
        r = a + 1
    elif opcode == OP_1SUB:
        r = a - 1
    elif opcode == OP_NEGATE:
        r = -a
    elif opcode == OP_ABS:
        r = abs(a)
    elif opcode == OP_NOT:
        r = 1 if a == 0 else 0
    elif opcode == OP_0NOTEQUAL:
        r = 1 if a != 0 else 0
    elif opcode == OP_ADD:
        r = a + b
    elif opcode == OP_SUB:
        r = a - b
    elif opcode == OP_BOOLAND:
        r = 1 if (a != 0 and b != 0) else 0
    elif opcode == OP_BOOLOR:
        r = 1 if (a != 0 or b != 0) else 0
    elif opcode == OP_NUMEQUAL or opcode == OP_NUMEQUALVERIFY:
        r = 1 if a == b else 0
    elif opcode == OP_NUMNOTEQUAL:
        r = 1 if a != b else 0
    elif opcode == OP_LESSTHAN:
        r = 1 if a < b else 0
    elif opcode == OP_GREATERTHAN:
        r = 1 if a > b else 0
    elif opcode == OP_LESSTHANOREQUAL:
        r = 1 if a <= b else 0
    elif opcode == OP_GREATERTHANOREQUAL:
        r = 1 if a >= b else 0
    elif opcode == OP_MIN:
        r = min(a, b)
    elif opcode == OP_MAX:
        r = max(a, b)
    else:
        raise ScriptError("bad arithmetic op")

    if opcode == OP_NUMEQUALVERIFY:
        if not r:
            raise ScriptError("NUMEQUALVERIFY failed")
    else:
        stack.append(encode_script_num(r))


def _check_cltv(stack: list, ctx: ScriptContext) -> None:
    """OP_CHECKLOCKTIMEVERIFY (BIP65)."""
    if not stack:
        raise ScriptError("CLTV on empty stack")
    n_locktime = decode_script_num(stack[-1], max_size=5)
    if n_locktime < 0:
        raise ScriptError("negative locktime")
    tx = ctx.tx
    txin = tx.vin[ctx.n_in]
    if ((tx.locktime < LOCKTIME_THRESHOLD) != (n_locktime < LOCKTIME_THRESHOLD)
            or n_locktime > tx.locktime):
        raise ScriptError("locktime requirement not satisfied")
    if txin.sequence == 0xFFFFFFFF:
        raise ScriptError("input is final; CLTV ineffective")


def _check_csv(stack: list, ctx: ScriptContext) -> None:
    """OP_CHECKSEQUENCEVERIFY (BIP112)."""
    if not stack:
        raise ScriptError("CSV on empty stack")
    n_seq = decode_script_num(stack[-1], max_size=5)
    if n_seq < 0:
        raise ScriptError("negative sequence")
    tx = ctx.tx
    txin = tx.vin[ctx.n_in]
    if tx.version < 2:
        raise ScriptError("tx version too low for CSV")
    if txin.sequence & (1 << 31):
        raise ScriptError("sequence disable flag set")
    TYPE_FLAG = 0x00400000
    MASK = 0x0000FFFF
    # the type flags must match (time-locked vs height-locked) -- BIP112
    if (n_seq & TYPE_FLAG) != (txin.sequence & TYPE_FLAG):
        raise ScriptError("sequence lock type mismatch")
    if (n_seq & MASK) > (txin.sequence & MASK):
        raise ScriptError("sequence requirement not satisfied")


# ---------------------------------------------------------------------------
# Top-level script verification (Bitcoin VerifyScript equivalent)
# ---------------------------------------------------------------------------
def eval_witness_program(witver: int, witprog: bytes, witness: list,
                         ctx: ScriptContext) -> None:
    """Execute a witness program against its witness stack."""
    if witver == 0:
        if len(witprog) == 20:
            # P2WPKH: run a P2PKH script with the witness items as stack
            if len(witness) != 2:
                raise ScriptError("P2WPKH witness must have 2 items")
            stack = list(witness)
            eval_script(stack, script_p2pkh(witprog),
                        ScriptContext(ctx.tx, ctx.n_in, ctx.amount, ctx.flags,
                                      SIGVERSION_WITNESS_V0,
                                      ctx.block_height, ctx.block_time))
            if len(stack) != 1 or not cast_to_bool(stack[0]):
                raise ScriptError("P2WPKH script failed")
            return
        if len(witprog) == 32:
            # P2WSH: last witness item is the script itself
            if not witness:
                raise ScriptError("empty witness")
            witness_script = witness[-1]
            if sha256(witness_script) != witprog:
                raise ScriptError("witness script hash mismatch")
            stack = list(witness[:-1])
            eval_script(stack, witness_script,
                        ScriptContext(ctx.tx, ctx.n_in, ctx.amount, ctx.flags,
                                      SIGVERSION_WITNESS_V0,
                                      ctx.block_height, ctx.block_time))
            if len(stack) != 1 or not cast_to_bool(stack[0]):
                raise ScriptError("P2WSH script failed")
            if any(len(i) > MAX_SCRIPT_ELEMENT_SIZE for i in stack):
                raise ScriptError("witness item too large")
            return
        raise ScriptError("bad v0 program length")
    if witver == 1 and len(witprog) == 32:
        prevouts = getattr(ctx, "all_prevouts", None)
        if prevouts is None:
            raise ScriptError("taproot eval needs all_prevouts")
        from . import schnorr as _schnorr
        if len(witness) == 1 and len(witness[0]) in (64, 65):
            # key-path: single schnorr signature
            sig = witness[0]
            hash_type = sig[64] if len(sig) == 65 else 0x00
            if hash_type not in (0x00, 0x01, 0x02, 0x03,
                                 0x81, 0x82, 0x83):
                raise ScriptError("bad taproot sighash")
            sighash = ctx.tx.signature_hash_v1(
                ctx.n_in, prevouts["amounts"], prevouts["spks"],
                hash_type)
            if not _schnorr.schnorr_verify(sighash, witprog, sig[:64]):
                raise ScriptError("taproot signature failed")
            return
        if len(witness) >= 2:
            # script-path: [...args, script, control_block]
            args, tapscript, control = \
                witness[:-2], witness[-2], witness[-1]
            try:
                _schnorr.verify_script_path(control, witprog, tapscript)
            except ValueError as e:
                raise ScriptError(f"bad control block: {e}")
            # run the tapscript with the args as initial stack
            ctx.sigversion = SIGVERSION_TAPSCRIPT
            ctx.tapleaf_hash = _schnorr.tapleaf_hash(tapscript)
            ctx.tapleaf_codesep_pos = 0xFFFFFFFF
            eval_script(list(args), tapscript, ctx)
            return
        raise ScriptError("bad taproot witness")
    # Unknown witness version: succeeds (anyone-can-spend) per BIP141.
    return


def verify_script(script_sig: bytes, script_pubkey: bytes, tx, n_in: int,
                  amount: int, flags: int,
                  block_height: int = 0, block_time: int = 0,
                  all_prevouts: dict | None = None) -> bool:
    """Full input-script verification, mirroring Bitcoin's VerifyScript.

    `amount` is the value of the output being spent (required for segwit).
    `all_prevouts` = {"amounts":[...], "spks":[...]} for every input (BIP341).
    Raises ScriptError on failure, returns True on success.
    """
    if flags & SCRIPT_VERIFY_SIGPUSHONLY and not is_push_only(script_sig):
        raise ScriptError("scriptSig not push-only")

    stack: list = []
    stack_copy: list | None = None
    ctx = ScriptContext(tx, n_in, amount, flags, SIGVERSION_BASE,
                        block_height, block_time, all_prevouts)
    eval_script(stack, script_sig, ctx)
    if flags & SCRIPT_VERIFY_P2SH:
        stack_copy = list(stack)
    eval_script(stack, script_pubkey, ctx)
    if not stack or not cast_to_bool(stack[-1]):
        raise ScriptError("script evaluated false")

    had_witness = False
    wp = witness_program(script_pubkey)
    if wp is not None:
        if not (flags & SCRIPT_VERIFY_WITNESS):
            raise ScriptError("unexpected witness program")
        if script_sig:
            raise ScriptError("scriptSig must be empty for native segwit")
        txin = tx.vin[n_in]
        eval_witness_program(wp[0], wp[1], txin.witness, ctx)
        stack = [b"\x01"]
        had_witness = True

    # P2SH: run the redeem script
    if (flags & SCRIPT_VERIFY_P2SH) and solver(script_pubkey)[0] == TX_SCRIPTHASH:
        if not is_push_only(script_sig):
            raise ScriptError("P2SH scriptSig must be push-only")
        if not stack_copy:
            raise ScriptError("P2SH: empty stack after scriptSig")
        redeem = stack_copy[-1]
        stack = stack_copy[:-1]
        eval_script(stack, redeem, ctx)
        if not stack or not cast_to_bool(stack[-1]):
            raise ScriptError("P2SH redeem script failed")
        wp = witness_program(redeem)
        if wp is not None:
            if not (flags & SCRIPT_VERIFY_WITNESS):
                raise ScriptError("unexpected witness program")
            if script_sig != push_data(redeem):
                raise ScriptError("P2SH-segwit scriptSig must be redeem push")
            eval_witness_program(wp[0], wp[1], tx.vin[n_in].witness, ctx)
            stack = [b"\x01"]
            had_witness = True

    if flags & SCRIPT_VERIFY_CLEANSTACK:
        if not (flags & SCRIPT_VERIFY_P2SH):
            raise ScriptError("CLEANSTACK requires P2SH")
        if len(stack) != 1:
            raise ScriptError("stack not clean")
    if had_witness and not cast_to_bool(stack[-1]):
        raise ScriptError("witness evaluation failed")

    return True


def has_valid_witness(txin) -> bool:
    return bool(txin.witness)

"""Tests for ThreadContext blocks (0x0011, spec Section 5.7)."""
import io
import struct

from memslicer.acquirer.bridge import (
    RegisterValue, ThreadInfo, register_role, register_width_bytes,
)
from memslicer.acquirer.engine import _build_thread_contexts
from memslicer.msl.constants import (
    ArchType, BlockType, CapBit, CompAlgo, REG_FLAG_PC, REG_FLAG_SP,
    THREAD_FLAG_CURRENT, ThreadState,
)
from memslicer.msl.iterator import iterate_blocks
from memslicer.msl.types import FileHeader, ThreadContext, ThreadRegister
from memslicer.msl.writer import MSLWriter
from memslicer.utils.padding import pad8

_HDR = "<QQHBBIH6s"
_HDR_SIZE = struct.calcsize(_HDR)
_REG = "<BBHI"


def _decode_thread_context(payload: bytes) -> dict:
    tid, start, flags, state, _r, regc, nlen, _r2 = struct.unpack(
        _HDR, payload[:_HDR_SIZE]
    )
    off = _HDR_SIZE
    name = ""
    if nlen:
        name = payload[off:off + nlen - 1].decode("utf-8")
        off += pad8(nlen)
    regs = []
    for _ in range(regc):
        rn, width, rflags, _ = struct.unpack(_REG, payload[off:off + 8])
        off += 8
        rname = payload[off:off + rn - 1].decode("utf-8")
        off += pad8(rn)
        value = int.from_bytes(payload[off:off + width], "little")
        off += pad8(width)
        regs.append((rname, width, rflags, value))
    return dict(
        tid=tid, start=start, flags=flags, state=state, name=name, regs=regs,
    )


def _write_one(tc: ThreadContext) -> bytes:
    buf = io.BytesIO()
    header = FileHeader(cap_bitmap=(1 << CapBit.ThreadContexts))
    writer = MSLWriter(buf, header, CompAlgo.NONE)
    writer.write_thread_context(tc)
    writer.finalize()
    buf.seek(0)
    blocks = [b for b in iterate_blocks(buf) if b.block_type == BlockType.ThreadContext]
    assert len(blocks) == 1
    return blocks[0].payload


def test_thread_context_roundtrip():
    tc = ThreadContext(
        thread_id=4242, start_time_ns=999, flags=THREAD_FLAG_CURRENT,
        state=ThreadState.Stopped, name="worker",
        registers=[
            ThreadRegister("rip", (0xdeadbeef).to_bytes(8, "little"), REG_FLAG_PC),
            ThreadRegister("rsp", (0x7fff1234).to_bytes(8, "little"), REG_FLAG_SP),
            ThreadRegister("rax", (1).to_bytes(8, "little"), 0),
        ],
    )
    got = _decode_thread_context(_write_one(tc))
    assert got["tid"] == 4242
    assert got["start"] == 999
    assert got["flags"] == THREAD_FLAG_CURRENT
    assert got["state"] == ThreadState.Stopped
    assert got["name"] == "worker"
    assert got["regs"] == [
        ("rip", 8, REG_FLAG_PC, 0xdeadbeef),
        ("rsp", 8, REG_FLAG_SP, 0x7fff1234),
        ("rax", 8, 0, 1),
    ]


def test_thread_context_no_name():
    tc = ThreadContext(thread_id=1, registers=[
        ThreadRegister("pc", (0x1000).to_bytes(8, "little"), REG_FLAG_PC),
    ])
    got = _decode_thread_context(_write_one(tc))
    assert got["name"] == ""
    assert got["regs"][0][0] == "pc"


def test_block_type_present_and_aligned():
    tc = ThreadContext(thread_id=7, name="x", registers=[
        ThreadRegister("sp", (0x20).to_bytes(8, "little"), REG_FLAG_SP),
    ])
    payload = _write_one(tc)
    # Payload is padded to 8 bytes by the writer.
    assert len(payload) % 8 == 0


def test_register_role():
    assert register_role("RIP") == "pc"
    assert register_role("rsp") == "sp"
    assert register_role("rbp") == "fp"
    assert register_role("rflags") == "flags"
    assert register_role("pc") == "pc"      # AArch64 canonical
    assert register_role("sp") == "sp"
    assert register_role("rax") == ""


def test_register_width_bytes():
    assert register_width_bytes(ArchType.x86_64) == 8
    assert register_width_bytes(ArchType.ARM64) == 8
    assert register_width_bytes(ArchType.x86) == 4
    assert register_width_bytes(ArchType.ARM32) == 4


def test_build_thread_contexts_current_fallback():
    # No thread marked current -> first one becomes current.
    threads = [
        ThreadInfo(tid=10, registers=[
            RegisterValue("rip", 0xabc, 8, "pc"),
        ], is_current=False),
        ThreadInfo(tid=11, registers=[
            RegisterValue("rip", 0xdef, 8, "pc"),
        ], is_current=False),
    ]
    ctxs = _build_thread_contexts(threads)
    assert len(ctxs) == 2
    assert ctxs[0].flags & THREAD_FLAG_CURRENT
    assert not (ctxs[1].flags & THREAD_FLAG_CURRENT)
    # Register integer encoded little-endian to declared width.
    assert ctxs[0].registers[0].value == (0xabc).to_bytes(8, "little")
    assert ctxs[0].registers[0].flags == REG_FLAG_PC


def test_build_thread_contexts_explicit_current():
    threads = [
        ThreadInfo(tid=1, registers=[], is_current=False),
        ThreadInfo(tid=2, registers=[RegisterValue("pc", 5, 8, "pc")],
                   is_current=True),
    ]
    ctxs = _build_thread_contexts(threads)
    assert not (ctxs[0].flags & THREAD_FLAG_CURRENT)
    assert ctxs[1].flags & THREAD_FLAG_CURRENT

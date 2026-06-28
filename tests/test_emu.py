"""Tests for the MSL emulator (memslicer.emu)."""
import pytest

from memslicer.emu.loader import load_slice
from memslicer.msl.writer import MSLWriter
from memslicer.msl.types import (
    FileHeader, ModuleEntry, ProcessIdentity, MemoryRegion, ThreadContext,
    ThreadRegister,
)
from memslicer.msl.constants import (
    ArchType, CapBit, CompAlgo, OSType, PageState, RegionType,
    REG_FLAG_PC, REG_FLAG_SP, THREAD_FLAG_CURRENT, ThreadState,
)

PS = 4096
CODE_VA = 0x401000
STACK_VA = 0x7ffff000
# mov rax,1 ; mov rbx,2 ; add rax,rbx ; inc rax ; mov rcx,rax
CODE = bytes.fromhex("48c7c001000000" "48c7c302000000" "4801d8" "48ffc0" "4889c1")


def _write_slice(path, *, with_regs=True):
    page = CODE + b"\x90" * (PS - len(CODE))
    cap = (1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
    if with_regs:
        cap |= (1 << CapBit.ThreadContexts)
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64,
                     pid=4321, cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/demo"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x00" * PS]))
        if with_regs:
            w.write_thread_context(ThreadContext(
                thread_id=4321, flags=THREAD_FLAG_CURRENT,
                state=ThreadState.Stopped, name="main", registers=[
                    ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
                    ThreadRegister("rsp", (STACK_VA + 0xf00).to_bytes(8, "little"), REG_FLAG_SP),
                    ThreadRegister("rax", (0xcafe).to_bytes(8, "little"), 0),
                ]))
        w.finalize()


# ---- loader (no unicorn/capstone needed) ----

def test_loader_parses_regions_and_thread(tmp_path):
    p = tmp_path / "x.msl"
    _write_slice(p)
    img = load_slice(str(p))
    assert img.arch == ArchType.x86_64
    assert img.os == OSType.Linux
    assert len(img.regions) == 2
    code = next(r for r in img.regions if r.base == CODE_VA)
    assert code.pages[CODE_VA].startswith(CODE)
    assert img.entry == CODE_VA
    t = img.current_thread
    assert t is not None and t.tid == 4321
    assert t.as_dict()["rax"] == 0xcafe


def test_loader_rejects_non_msl(tmp_path):
    p = tmp_path / "bad.bin"
    p.write_bytes(b"NOTMSL__" + b"\x00" * 64)
    with pytest.raises(ValueError):
        load_slice(str(p))


# ---- engine (requires the emu extra) ----

def test_emulator_steps_real_code(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "code.msl"
    _write_slice(p)
    emu = MSLEmulator(load_slice(str(p)))

    assert emu.pc == CODE_VA
    assert emu.read_reg("rax") == 0xcafe          # seeded
    assert emu.read_reg("rbx") == 0               # not captured -> 0

    r1 = emu.step()                                # mov rax, 1
    assert r1.ok and r1.mnemonic == "mov"
    assert emu.read_reg("rax") == 1
    emu.step()                                     # mov rbx, 2
    assert emu.read_reg("rbx") == 2
    emu.step()                                     # add rax, rbx
    assert emu.read_reg("rax") == 3
    emu.step()                                     # inc rax
    assert emu.read_reg("rax") == 4
    emu.step()                                     # mov rcx, rax
    assert emu.read_reg("rcx") == 4
    assert emu.pc == CODE_VA + len(CODE)


def test_emulator_step_until(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "code.msl"
    _write_slice(p)
    emu = MSLEmulator(load_slice(str(p)))
    results = list(emu.step_until(CODE_VA + 0x11))  # stop at 'inc rax'
    assert all(r.ok for r in results)
    assert emu.pc == CODE_VA + 0x11
    assert emu.read_reg("rax") == 3                 # after add, before inc


def test_emulator_read_write_mem_and_reg(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "code.msl"
    _write_slice(p)
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.read_mem(CODE_VA, len(CODE)) == CODE
    emu.write_reg("rax", 0x1234)
    assert emu.read_reg("rax") == 0x1234


# ---- reverse execution (requires the emu extra) ----

def _write_code(path, code, regs):
    """Write a minimal slice: one r-x code page + one rw- stack page + a
    Thread Context with the given registers."""
    page = code + b"\x90" * (PS - len(code))
    cap = (1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity) | (1 << CapBit.ThreadContexts)
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64, pid=1, cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/demo"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x00" * PS]))
        w.write_thread_context(ThreadContext(
            thread_id=1, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=regs))
        w.finalize()


def test_emulator_step_back_registers(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "code.msl"
    _write_slice(p)                                  # seeds rax=0xcafe
    emu = MSLEmulator(load_slice(str(p)))
    for _ in range(3):                               # mov rax,1; mov rbx,2; add
        emu.step()
    assert emu.read_reg("rax") == 3
    assert emu.pc == CODE_VA + 0x11

    assert emu.step_back()                            # undo add
    assert emu.read_reg("rax") == 1
    assert emu.step_back()                            # undo mov rbx,2
    assert emu.read_reg("rbx") == 0
    assert emu.step_back()                            # undo mov rax,1
    assert emu.read_reg("rax") == 0xcafe              # back to the seeded value
    assert emu.pc == CODE_VA
    assert not emu.step_back()                        # no more history


SECOND_VA = CODE_VA + 7   # 'mov rbx, 2' (second instruction)


def _write_multithread_slice(path):
    """A slice with two captured threads: tid 100 (Current) parked at CODE_VA
    with rax=0xaaaa, and tid 200 parked at the second instruction with
    rax=0xbbbb."""
    page = CODE + b"\x90" * (PS - len(CODE))
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
           | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Linux, arch_type=ArchType.x86_64,
                     pid=100, cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="/bin/demo"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x00" * PS]))
        w.write_thread_context(ThreadContext(
            thread_id=100, flags=THREAD_FLAG_CURRENT,
            state=ThreadState.Running, name="main", registers=[
                ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("rsp", (STACK_VA + 0xf00).to_bytes(8, "little"), REG_FLAG_SP),
                ThreadRegister("rax", (0xaaaa).to_bytes(8, "little"), 0),
            ]))
        w.write_thread_context(ThreadContext(
            thread_id=200, flags=0,
            state=ThreadState.Stopped, name="worker", registers=[
                ThreadRegister("rip", SECOND_VA.to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("rsp", (STACK_VA + 0xe00).to_bytes(8, "little"), REG_FLAG_SP),
                ThreadRegister("rax", (0xbbbb).to_bytes(8, "little"), 0),
            ]))
        w.finalize()


def test_loader_select_thread(tmp_path):
    p = tmp_path / "mt.msl"
    _write_multithread_slice(p)
    img = load_slice(str(p))
    assert [t.tid for t in img.threads] == [100, 200]
    assert img.current_thread.tid == 100          # flagged Current
    assert img.select_thread(None).tid == 100     # default -> Current
    assert img.select_thread(200).tid == 200      # by tid
    assert img.thread_by_tid(200).pc == SECOND_VA
    assert img.thread_by_tid(999) is None
    with pytest.raises(KeyError):
        img.select_thread(999)


def test_emulator_seeds_selected_thread(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator, EmuError

    p = tmp_path / "mt.msl"
    _write_multithread_slice(p)
    img = load_slice(str(p))

    # Default: Current thread (tid 100).
    emu = MSLEmulator(img)
    assert emu.thread.tid == 100
    assert emu.pc == CODE_VA and emu.read_reg("rax") == 0xaaaa

    # Pick the non-Current thread by tid.
    emu2 = MSLEmulator(img, thread=200)
    assert emu2.thread.tid == 200
    assert emu2.pc == SECOND_VA and emu2.read_reg("rax") == 0xbbbb

    # Unknown tid is a clean error.
    with pytest.raises(EmuError):
        MSLEmulator(img, thread=999)


def test_emulator_switch_thread(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "mt.msl"
    _write_multithread_slice(p)
    emu = MSLEmulator(load_slice(str(p)))         # starts on tid 100
    emu.step()                                    # mov rax, 1
    assert emu.read_reg("rax") == 1

    t = emu.switch_thread(200)                    # re-seed from the worker thread
    assert t.tid == 200
    assert emu.thread.tid == 200
    assert emu.pc == SECOND_VA                     # reset to its captured PC
    assert emu.read_reg("rax") == 0xbbbb           # reset to its captured regs
    assert not emu.can_step_back()                 # history dropped on switch

    emu.step()                                     # mov rbx, 2
    assert emu.read_reg("rbx") == 2


def test_cli_list_threads(tmp_path):
    from click.testing import CliRunner
    from memslicer.cli_emu import main

    p = tmp_path / "mt.msl"
    _write_multithread_slice(p)
    res = CliRunner().invoke(main, [str(p), "--list-threads"])
    assert res.exit_code == 0
    assert "tid=100" in res.output and "tid=200" in res.output
    assert "*" in res.output                       # Current thread marked


def test_emulator_step_back_memory(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    rsp = STACK_VA + 0x100
    # mov rax, 0x4142 ; mov [rsp], rax
    code = bytes.fromhex("48c7c042410000" "48890424")
    p = tmp_path / "mem.msl"
    _write_code(p, code, [
        ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
        ThreadRegister("rsp", rsp.to_bytes(8, "little"), REG_FLAG_SP),
    ])
    emu = MSLEmulator(load_slice(str(p)))
    emu.step()                                        # mov rax, 0x4142
    before = emu.read_mem(rsp, 8)
    emu.step()                                        # mov [rsp], rax
    assert emu.read_mem(rsp, 8) != before
    assert emu.read_reg("rax") == 0x4142

    assert emu.step_back()                            # undo the store
    assert emu.read_mem(rsp, 8) == before             # memory reverted
    assert emu.step_back()                            # undo mov rax
    assert emu.read_reg("rax") != 0x4142


# ---- self-modifying code / unpacking (requires the emu extra) ----

def test_emulator_detects_self_modifying_code(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    target = CODE_VA + 0x20
    # movabs rbx, target ; mov byte [rbx], 0x90 ; jmp rbx ; (executes the NOP
    # written at +0x20 -> write-then-execute)
    code = bytes.fromhex("48bb" + target.to_bytes(8, "little").hex()
                         + "c60390" + "ffe3")
    p = tmp_path / "smc.msl"
    _write_code(p, code, [
        ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
        ThreadRegister("rsp", (STACK_VA + 0x100).to_bytes(8, "little"), REG_FLAG_SP),
    ])
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.self_modified_exec() == []              # nothing executed yet
    for _ in range(4):                                 # movabs ; mov ; jmp ; nop
        emu.step()

    assert emu.self_modified_exec() == [target]        # W->X at the written byte
    assert any(lo <= target < hi for lo, hi in emu.written_ranges())

    dumped = emu.dump_written(str(tmp_path / "out"))
    assert dumped
    assert any(executed for _path, _lo, _hi, executed in dumped)
    # the dumped range covering the written byte exists on disk
    hit = next(d for d in dumped if d[1] <= target < d[2])
    import os
    assert os.path.getsize(hit[0]) == hit[2] - hit[1]


def test_cli_dump_written(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from click.testing import CliRunner
    from memslicer.cli_emu import main

    target = CODE_VA + 0x20
    code = bytes.fromhex("48bb" + target.to_bytes(8, "little").hex()
                         + "c60390" + "ffe3")
    p = tmp_path / "smc.msl"
    _write_code(p, code, [
        ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
        ThreadRegister("rsp", (STACK_VA + 0x100).to_bytes(8, "little"), REG_FLAG_SP),
    ])
    outdir = tmp_path / "written"
    res = CliRunner().invoke(
        main, [str(p), "-s", "4", "--dump-written", str(outdir)])
    assert res.exit_code == 0, res.output
    assert "self-modifying code" in res.output
    assert "(executed)" in res.output
    assert list(outdir.glob("*.bin"))

# ---- vector / FP registers ----

XMM_VAL = 0x0123456789abcdef_fedcba9876543210  # 128-bit


def test_loader_parses_vector_register(tmp_path):
    p = tmp_path / "v.msl"
    _write_code(p, b"\x90", [
        ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
        ThreadRegister("xmm0", XMM_VAL.to_bytes(16, "little"), 0),
    ])
    img = load_slice(str(p))
    xmm = next(r for r in img.current_thread.registers if r.name == "xmm0")
    assert xmm.width == 16
    assert xmm.value == XMM_VAL                      # full 128-bit round-trip


def test_emulator_seeds_vector_register(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "v.msl"
    _write_code(p, b"\x90", [
        ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
        ThreadRegister("rsp", (STACK_VA + 0x100).to_bytes(8, "little"), REG_FLAG_SP),
        ThreadRegister("xmm0", XMM_VAL.to_bytes(16, "little"), 0),
    ])
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.read_reg("xmm0") == XMM_VAL           # 128-bit reg seeded
    assert emu.read_reg("rip") == CODE_VA            # GPRs unaffected



# ---- segment base / TEB / PEB ----

def test_emulator_honors_gs_base(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    # movabs rbx, 0xCAFEBABE ; mov gs:[0x60], rbx ; mov rax, gs:[0x60]
    code = bytes.fromhex("48bbbebafeca00000000"
                         "6548891c2560000000"
                         "65488b042560000000")
    p = tmp_path / "gs.msl"
    _write_code(p, code, [
        ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
        ThreadRegister("rsp", (STACK_VA + 0x200).to_bytes(8, "little"), REG_FLAG_SP),
        ThreadRegister("gs_base", STACK_VA.to_bytes(8, "little"), 0),
    ])
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.segment_base("gs") == STACK_VA          # fs/gs base seeded
    for _ in range(3):
        emu.step()
    assert emu.read_reg("rax") == 0xCAFEBABE           # gs:[0x60] resolved


def test_emulator_peb_address(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    peb = 0x7ff50000
    teb = bytearray(b"\x00" * PS)
    teb[0x60:0x68] = peb.to_bytes(8, "little")         # PEB pointer at gs:[0x60]
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
           | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Windows, arch_type=ArchType.x86_64,
                     pid=1, cap_bitmap=cap)
    p = tmp_path / "peb.msl"
    with open(p, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="C:\\a.exe"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x90" * PS]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[bytes(teb)]))
        w.write_thread_context(ThreadContext(
            thread_id=1, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=[
                ThreadRegister("rip", CODE_VA.to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("gs_base", STACK_VA.to_bytes(8, "little"), 0),
            ]))
        w.finalize()
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.peb_address() == peb                    # resolved gs:[0x60]


# ---- x86 (32-bit) segment base via synthetic GDT ----

def _write_x86_slice(path, code, regs, *, extra_regions=()):
    """Write a minimal 32-bit Windows slice: code + stack + thread context,
    plus any *extra_regions* as (base, page_bytes) pairs (e.g. a TEB page)."""
    page = code + b"\x90" * (PS - len(code))
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
           | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Windows, arch_type=ArchType.x86,
                     pid=1, cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="C:\\a.exe"))
        w.write_memory_region(MemoryRegion(
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[page]))
        w.write_memory_region(MemoryRegion(
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x00" * PS]))
        for base, data in extra_regions:
            w.write_memory_region(MemoryRegion(
                base_addr=base, region_size=PS, protection=0b011,
                region_type=RegionType.Stack, page_size=PS,
                page_states=[PageState.CAPTURED], page_data_chunks=[data]))
        w.write_thread_context(ThreadContext(
            thread_id=1, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=regs))
        w.finalize()


def test_emulator_seeds_x86_fs_base_via_gdt(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    TEB = 0x60000000
    peb = 0x001a0000
    teb = bytearray(b"\x00" * PS)
    teb[0x30:0x34] = peb.to_bytes(4, "little")          # PEB pointer at fs:[0x30]
    code = bytes.fromhex("64a130000000")                # mov eax, fs:[0x30]
    p = tmp_path / "x86fs.msl"
    _write_x86_slice(p, code, [
        ThreadRegister("eip", CODE_VA.to_bytes(4, "little"), REG_FLAG_PC),
        ThreadRegister("esp", (STACK_VA + 0xf00).to_bytes(4, "little"), REG_FLAG_SP),
        ThreadRegister("fs_base", TEB.to_bytes(4, "little"), 0),
    ], extra_regions=[(TEB, bytes(teb))])
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.segment_base("fs") == TEB               # GDT-seeded base
    assert emu.peb_address() == peb                    # fs:[0x30] resolved
    emu.step()                                         # mov eax, fs:[0x30]
    assert emu.read_reg("eax") == peb                  # segment-relative read worked


def test_emulator_x86_without_fs_base_still_runs(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "x86plain.msl"
    _write_x86_slice(p, b"\x90", [                      # nop
        ThreadRegister("eip", CODE_VA.to_bytes(4, "little"), REG_FLAG_PC),
        ThreadRegister("esp", (STACK_VA + 0xf00).to_bytes(4, "little"), REG_FLAG_SP),
    ])
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.segment_base("fs") is None              # no GDT installed
    assert emu.peb_address() is None
    assert emu.step().ok                               # no regression


# ---- resume from a library/syscall the slice is parked in --------------------

SYS_VA = 0x70000000   # stand-in for ntdll.dll (where the parked PC sits)


def _write_parked_slice(path, *, rsp=STACK_VA + 0x100, stack_layout=None):
    """A slice captured 'parked in a system call': the Current thread's PC is
    inside a system module (SYS_VA, ~ntdll), and the stack carries a system
    return address, some junk, then a real return address into the program
    image (``demo.exe`` at CODE_VA). *stack_layout* maps a stack offset (from
    STACK_VA) to an 8-byte value; defaults to that 3-slot layout."""
    if stack_layout is None:
        stack_layout = {
            0x100: SYS_VA + 4,      # nested system frame -> skipped (not image)
            0x108: 0x12345,         # junk, not executable -> skipped
            0x110: CODE_VA,         # return into the image -> the caller
        }
    stack = bytearray(b"\x00" * PS)
    for off, val in stack_layout.items():
        stack[off:off + 8] = val.to_bytes(8, "little")
    code_page = CODE + b"\x90" * (PS - len(CODE))
    cap = ((1 << CapBit.MemoryRegions) | (1 << CapBit.ProcessIdentity)
           | (1 << CapBit.ThreadContexts))
    hdr = FileHeader(os_type=OSType.Windows, arch_type=ArchType.x86_64,
                     pid=964, cap_bitmap=cap)
    with open(path, "wb") as f:
        w = MSLWriter(f, hdr, CompAlgo.NONE)
        w.write_process_identity(ProcessIdentity(exe_path="C:\\demo.exe"))  # block 0
        w.write_module_list([                            # block 1 (per spec)
            ModuleEntry(base_addr=CODE_VA, module_size=PS, path="C:\\demo.exe"),
            ModuleEntry(base_addr=SYS_VA, module_size=PS,
                        path="C:\\Windows\\System32\\ntdll.dll"),
        ])
        w.write_memory_region(MemoryRegion(                # program image (r-x)
            base_addr=CODE_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[code_page]))
        w.write_memory_region(MemoryRegion(                # ntdll (r-x), parked PC
            base_addr=SYS_VA, region_size=PS, protection=0b101,
            region_type=RegionType.Image, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[b"\x90" * PS]))
        w.write_memory_region(MemoryRegion(                # stack (rw-)
            base_addr=STACK_VA, region_size=PS, protection=0b011,
            region_type=RegionType.Stack, page_size=PS,
            page_states=[PageState.CAPTURED], page_data_chunks=[bytes(stack)]))
        w.write_thread_context(ThreadContext(
            thread_id=964, flags=THREAD_FLAG_CURRENT, state=ThreadState.Stopped,
            name="main", registers=[
                ThreadRegister("rip", SYS_VA.to_bytes(8, "little"), REG_FLAG_PC),
                ThreadRegister("rsp", rsp.to_bytes(8, "little"), REG_FLAG_SP),
            ]))
        w.finalize()


def test_emulator_identifies_image_and_system_call(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "parked.msl"
    _write_parked_slice(p)
    emu = MSLEmulator(load_slice(str(p)))

    assert emu.main_image().name == "demo.exe"         # the .exe, not ntdll
    assert emu.module_at(SYS_VA).name == "ntdll.dll"
    assert emu.pc == SYS_VA
    assert emu.in_system_call() is True                # parked outside the image


def test_emulator_find_caller_frame_skips_system_and_junk(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "parked.msl"
    _write_parked_slice(p)
    emu = MSLEmulator(load_slice(str(p)))

    frame = emu.find_caller_frame()
    assert frame is not None
    assert frame.return_addr == CODE_VA                # skipped ntdll + junk
    assert frame.sp_slot == STACK_VA + 0x110
    assert frame.depth == 2
    assert frame.module == "demo.exe"


def test_emulator_resume_from_syscall(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "parked.msl"
    _write_parked_slice(p)
    emu = MSLEmulator(load_slice(str(p)))

    frame = emu.resume_from_syscall()
    assert frame is not None
    assert emu.pc == CODE_VA                            # back in the image
    assert emu.in_system_call() is False
    # plain 'ret': SP moved just past the return-address slot
    assert emu.read_reg("rsp") == STACK_VA + 0x110 + 8
    assert not emu.can_step_back()                      # unwind dropped history

    emu.step()                                          # mov rax, 1 (really runs)
    assert emu.read_reg("rax") == 1


def test_emulator_resume_from_syscall_pops_stdcall_args(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    p = tmp_path / "parked.msl"
    _write_parked_slice(p)
    emu = MSLEmulator(load_slice(str(p)))

    emu.resume_from_syscall(pop_bytes=4)                # e.g. Sleep's 'ret 4'
    assert emu.pc == CODE_VA
    assert emu.read_reg("rsp") == STACK_VA + 0x110 + 8 + 4


def test_emulator_resume_from_syscall_no_caller(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from memslicer.emu.engine import MSLEmulator

    # A stack with no return address into the image -> nothing to resume to.
    p = tmp_path / "noframe.msl"
    _write_parked_slice(p, stack_layout={0x100: SYS_VA + 4, 0x108: 0x12345})
    emu = MSLEmulator(load_slice(str(p)))
    assert emu.find_caller_frame() is None
    assert emu.resume_from_syscall() is None


def test_cli_resume_from_syscall(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from click.testing import CliRunner
    from memslicer.cli_emu import main

    p = tmp_path / "parked.msl"
    _write_parked_slice(p)
    res = CliRunner().invoke(main, [str(p), "-R", "-s", "1", "-r"])
    assert res.exit_code == 0, res.output
    assert "resume-from-syscall" in res.output
    assert "ntdll.dll" in res.output                   # reports where it was parked
    assert f"caller return @ {CODE_VA:#x}" in res.output
    assert "demo.exe" in res.output
    assert "rsp" in res.output


def test_cli_resume_from_syscall_image_range(tmp_path):
    pytest.importorskip("unicorn")
    pytest.importorskip("capstone")
    from click.testing import CliRunner
    from memslicer.cli_emu import main

    p = tmp_path / "parked.msl"
    _write_parked_slice(p)
    # Explicit image range instead of auto-detection.
    res = CliRunner().invoke(
        main, [str(p), "-R", "--image-range", f"{CODE_VA:#x}:{CODE_VA + PS:#x}"])
    assert res.exit_code == 0, res.output
    assert f"caller return @ {CODE_VA:#x}" in res.output

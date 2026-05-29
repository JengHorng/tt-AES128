# =============================================================================
# test.py  —  cocotb testbench for tt_um_aes_project
#             Sequential SubBytes version (181 cycles per encryption)
# =============================================================================

import cocotb
from cocotb.clock    import Clock
from cocotb.triggers import RisingEdge, ClockCycles, Timer


# ─── helpers ──────────────────────────────────────────────────────────────────

async def reset(dut):
    dut.rst_n.value  = 0
    dut.ena.value    = 1
    dut.ui_in.value  = 0
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value  = 1
    await ClockCycles(dut.clk, 2)


async def write_byte(dut, byte_index, value, is_plaintext):
    sel = 1 if is_plaintext else 0
    dut.ui_in.value  = value
    dut.uio_in.value = (1 << 5) | (sel << 4) | (byte_index & 0xF)
    await RisingEdge(dut.clk)
    dut.uio_in.value = 0
    await RisingEdge(dut.clk)


async def load_key_bytes(dut, key_hex):
    key_bytes = bytes.fromhex(key_hex)
    assert len(key_bytes) == 16
    for i, b in enumerate(key_bytes):
        await write_byte(dut, i, b, is_plaintext=False)
    dut.uio_in.value = (1 << 6)   # pulse load_key_cmd
    await RisingEdge(dut.clk)
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 3)  # wait for key_ready


async def encrypt(dut, pt_hex):
    """
    Write 16 plaintext bytes, pulse start_cmd, wait for encryption.

    Sequential SubBytes timing:
      Cycle  0       : initial ARK            (S_READY)
      Cycles 1..18   : round 1  (1+16+1)      (S_SUBBYTES × 17 + S_ROUND_OP × 1)
      Cycles 19..36  : round 2
      ...
      Cycles 163..180: round 10
      Cycle  181     : valid_out fires
      + wrapper latency (~3 cycles)
    Wait 200 cycles to be safe.
    """
    pt_bytes = bytes.fromhex(pt_hex)
    assert len(pt_bytes) == 16
    for i, b in enumerate(pt_bytes):
        await write_byte(dut, i, b, is_plaintext=True)

    # Pulse start_cmd (uio_in[7])
    dut.uio_in.value = (1 << 7)
    await RisingEdge(dut.clk)
    dut.uio_in.value = 0

    # Wait: 181 cycles encryption + TT wrapper latency + margin = 200 cycles
    await ClockCycles(dut.clk, 250)


async def read_ciphertext(dut):
    result = []
    for i in range(16):
        dut.uio_in.value = i & 0xF
        await Timer(2, unit="ns")
        result.append(int(dut.uo_out.value) & 0xFF)
    dut.uio_in.value = 0
    return bytes(result)


# ─── tests ────────────────────────────────────────────────────────────────────

@cocotb.test()
async def test_nist_fips197_c1(dut):
    """
    NIST FIPS 197 Appendix C.1
      Key  : 000102030405060708090a0b0c0d0e0f
      PT   : 00112233445566778899aabbccddeeff
      CT   : 69c4e0d86a7b0430d8cdb78070b4c55a
    """
    cocotb.start_soon(Clock(dut.clk, 20, unit="ns").start())
    await reset(dut)

    key_hex = "000102030405060708090a0b0c0d0e0f"
    pt_hex  = "00112233445566778899aabbccddeeff"
    exp_hex = "69c4e0d86a7b0430d8cdb78070b4c55a"

    dut._log.info(f"Key      : {key_hex}")
    await load_key_bytes(dut, key_hex)

    dut._log.info(f"Plaintext: {pt_hex}")
    await encrypt(dut, pt_hex)

    ct = await read_ciphertext(dut)
    dut._log.info(f"Got      : {ct.hex()}")
    dut._log.info(f"Expected : {exp_hex}")
    assert ct.hex() == exp_hex, f"MISMATCH: got {ct.hex()}"
    dut._log.info("PASS — NIST FIPS 197 Appendix C.1")


@cocotb.test()
async def test_nist_fips197_appb(dut):
    """
    NIST FIPS 197 Appendix B
      Key  : 2b7e151628aed2a6abf7158809cf4f3c
      PT   : 3243f6a8885a308d313198a2e0370734
      CT   : 3925841d02dc09fbdc118597196a0b32
    """
    cocotb.start_soon(Clock(dut.clk, 20, unit="ns").start())
    await reset(dut)

    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    pt_hex  = "3243f6a8885a308d313198a2e0370734"
    exp_hex = "3925841d02dc09fbdc118597196a0b32"

    await load_key_bytes(dut, key_hex)
    await encrypt(dut, pt_hex)
    ct = await read_ciphertext(dut)
    assert ct.hex() == exp_hex, f"MISMATCH: {ct.hex()}"
    dut._log.info("PASS — NIST FIPS 197 Appendix B")


@cocotb.test()
async def test_second_encrypt_same_key(dut):
    """
    Two consecutive encryptions — verifies key resets correctly.
      Key    : 2b7e151628aed2a6abf7158809cf4f3c
      Block1 : 6bc1bee22e409f96e93d7e117393172a → 3ad77bb40d7a3660a89ecaf32466ef97
      Block2 : ae2d8a571e03ac9c9eb76fac45af8e51 → f5d3d58503b9699de785895a96fdbaaf
    """
    cocotb.start_soon(Clock(dut.clk, 20, unit="ns").start())
    await reset(dut)

    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    await load_key_bytes(dut, key_hex)

    await encrypt(dut, "6bc1bee22e409f96e93d7e117393172a")
    ct1 = await read_ciphertext(dut)
    assert ct1.hex() == "3ad77bb40d7a3660a89ecaf32466ef97", f"Block1 FAIL: {ct1.hex()}"
    dut._log.info(f"Block 1 PASS: {ct1.hex()}")

    await encrypt(dut, "ae2d8a571e03ac9c9eb76fac45af8e51")
    ct2 = await read_ciphertext(dut)
    assert ct2.hex() == "f5d3d58503b9699de785895a96fdbaaf", f"Block2 FAIL: {ct2.hex()}"
    dut._log.info(f"Block 2 PASS: {ct2.hex()}")

    dut._log.info("PASS — two consecutive encryptions")

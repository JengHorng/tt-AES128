# =============================================================================
# test.py  —  cocotb testbench for tt_um_aes_project (iterative AES-128)
# =============================================================================

import cocotb
from cocotb.clock    import Clock
from cocotb.triggers import RisingEdge, ClockCycles, Timer


# ─── helpers ──────────────────────────────────────────────────────────────────

async def reset(dut):
    """Apply active-low reset for 5 cycles."""
    dut.rst_n.value  = 0
    dut.ena.value    = 1
    dut.ui_in.value  = 0
    dut.uio_in.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value  = 1
    await ClockCycles(dut.clk, 2)


async def write_byte(dut, byte_index, value, is_plaintext):
    """Write one byte into the key or plaintext register."""
    sel = 1 if is_plaintext else 0
    # uio_in: [7]=0 [6]=0 [5]=write_en [4]=sel [3:0]=index
    dut.ui_in.value  = value
    dut.uio_in.value = (1 << 5) | (sel << 4) | (byte_index & 0xF)
    await RisingEdge(dut.clk)
    dut.uio_in.value = 0    # de-assert write_en
    await RisingEdge(dut.clk)


async def load_key_bytes(dut, key_hex):
    """Write 16 key bytes then pulse load_key_cmd."""
    key_bytes = bytes.fromhex(key_hex)
    assert len(key_bytes) == 16

    # Write 16 bytes (byte 0 = MSB)
    for i, b in enumerate(key_bytes):
        await write_byte(dut, i, b, is_plaintext=False)

    # Pulse load_key_cmd (uio_in[6])
    dut.uio_in.value = (1 << 6)
    await RisingEdge(dut.clk)
    dut.uio_in.value = 0

    # Wait for FSM to transition to S_READY (2 cycles is enough)
    await ClockCycles(dut.clk, 3)


async def encrypt(dut, pt_hex):
    """
    Write 16 plaintext bytes, pulse start_cmd, then wait fixed cycles.

    Why fixed wait instead of polling done_latch:
      uio_out is hardwired to 0 in tt_um_aes_project.v so done_latch
      is not externally visible. We know the iterative design takes
      exactly 11 cycles after valid_in fires, and valid_in fires 1
      cycle after start_cmd. Total = 13 cycles. We wait 18 to be safe.
    """
    pt_bytes = bytes.fromhex(pt_hex)
    assert len(pt_bytes) == 16

    # Write 16 plaintext bytes
    for i, b in enumerate(pt_bytes):
        await write_byte(dut, i, b, is_plaintext=True)

    # Pulse start_cmd (uio_in[7]) for 1 cycle
    dut.uio_in.value = (1 << 7)
    await RisingEdge(dut.clk)
    dut.uio_in.value = 0

    # Fixed wait:
    #   Cycle +1 : valid_in=1 latched by wrapper NBA, aes_top reads it
    #   Cycle +2 : aes_top initial ARK (S_READY → S_ENCRYPT)
    #   Cycles +3 to +11 : standard rounds 1–9
    #   Cycle +12 : final round, valid_out=1, ciphertext_out updated
    #   Cycle +13 : wrapper latches ciphertext_latch
    #   Cycles +14–18 : margin
    await ClockCycles(dut.clk, 18)


async def read_ciphertext(dut):
    """Read all 16 ciphertext bytes by setting byte_index on uio_in[3:0]."""
    result = []
    for i in range(16):
        dut.uio_in.value = i & 0xF     # set byte_index, no write_en
        await Timer(2, unit="ns")       # short combinational settle
        result.append(int(dut.uo_out.value) & 0xFF)
    dut.uio_in.value = 0
    return bytes(result)


# ─── tests ────────────────────────────────────────────────────────────────────

@cocotb.test()
async def test_nist_fips197_c1(dut):
    """
    NIST FIPS 197 Appendix C.1
      Key       : 000102030405060708090a0b0c0d0e0f
      Plaintext : 00112233445566778899aabbccddeeff
      Expected  : 69c4e0d86a7b0430d8cdb78070b4c55a
    """
    cocotb.start_soon(Clock(dut.clk, 20, unit="ns").start())
    await reset(dut)

    key_hex = "000102030405060708090a0b0c0d0e0f"
    pt_hex  = "00112233445566778899aabbccddeeff"
    exp_hex = "69c4e0d86a7b0430d8cdb78070b4c55a"

    dut._log.info(f"Loading key : {key_hex}")
    await load_key_bytes(dut, key_hex)

    dut._log.info(f"Encrypting  : {pt_hex}")
    await encrypt(dut, pt_hex)

    ct = await read_ciphertext(dut)
    dut._log.info(f"Got         : {ct.hex()}")
    dut._log.info(f"Expected    : {exp_hex}")

    assert ct.hex() == exp_hex, f"MISMATCH: got {ct.hex()}, expected {exp_hex}"
    dut._log.info("PASS — NIST FIPS 197 Appendix C.1")


@cocotb.test()
async def test_nist_fips197_appb(dut):
    """
    NIST FIPS 197 Appendix B
      Key       : 2b7e151628aed2a6abf7158809cf4f3c
      Plaintext : 3243f6a8885a308d313198a2e0370734
      Expected  : 3925841d02dc09fbdc118597196a0b32
    """
    cocotb.start_soon(Clock(dut.clk, 20, unit="ns").start())
    await reset(dut)

    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    pt_hex  = "3243f6a8885a308d313198a2e0370734"
    exp_hex = "3925841d02dc09fbdc118597196a0b32"

    await load_key_bytes(dut, key_hex)
    await encrypt(dut, pt_hex)

    ct = await read_ciphertext(dut)
    dut._log.info(f"Got         : {ct.hex()}")
    dut._log.info(f"Expected    : {exp_hex}")

    assert ct.hex() == exp_hex, f"MISMATCH: {ct.hex()} != {exp_hex}"
    dut._log.info("PASS — NIST FIPS 197 Appendix B")


@cocotb.test()
async def test_second_encrypt_same_key(dut):
    """
    Two consecutive encryptions with same key.
    Verifies rk resets to orig_key between blocks.
      Key    : 2b7e151628aed2a6abf7158809cf4f3c
      Block1 : 6bc1bee22e409f96e93d7e117393172a → 3ad77bb40d7a3660a89ecaf32466ef97
      Block2 : ae2d8a571e03ac9c9eb76fac45af8e51 → f5d3d58503b9699de785895a96fdbaaf
    """
    cocotb.start_soon(Clock(dut.clk, 20, unit="ns").start())
    await reset(dut)

    key_hex = "2b7e151628aed2a6abf7158809cf4f3c"
    await load_key_bytes(dut, key_hex)

    # Block 1
    await encrypt(dut, "6bc1bee22e409f96e93d7e117393172a")
    ct1 = await read_ciphertext(dut)
    dut._log.info(f"Block 1 got : {ct1.hex()}")
    assert ct1.hex() == "3ad77bb40d7a3660a89ecaf32466ef97", \
           f"Block 1 FAIL: {ct1.hex()}"
    dut._log.info("Block 1 PASS")

    # Block 2 — same key, no key reload needed
    await encrypt(dut, "ae2d8a571e03ac9c9eb76fac45af8e51")
    ct2 = await read_ciphertext(dut)
    dut._log.info(f"Block 2 got : {ct2.hex()}")
    assert ct2.hex() == "f5d3d58503b9699de785895a96fdbaaf", \
           f"Block 2 FAIL: {ct2.hex()}"
    dut._log.info("Block 2 PASS — key correctly reset between blocks")

import cocotb
from cocotb.triggers import RisingEdge


@cocotb.test()
async def test_aes_wrapper_basic(dut):
    """Basic smoke test for Tiny Tapeout AES wrapper."""

    dut._log.info("Starting AES Tiny Tapeout wrapper smoke test")

    dut.ena.value = 1
    dut.ui_in.value = 0
    dut.uio_in.value = 0

    dut.rst_n.value = 0
    for _ in range(5):
        await RisingEdge(dut.clk)

    dut.rst_n.value = 1
    for _ in range(5):
        await RisingEdge(dut.clk)

    assert int(dut.uio_oe.value) == 0x00

    # Write one key byte to check wrapper interface
    dut.ui_in.value = 0x00
    dut.uio_in.value = 0b0010_0000  # write_en=1, select_plaintext=0, index=0
    await RisingEdge(dut.clk)

    dut.uio_in.value = 0
    dut.ui_in.value = 0
    await RisingEdge(dut.clk)

    dut._log.info("AES wrapper basic smoke test passed")

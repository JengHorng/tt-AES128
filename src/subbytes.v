`timescale 1ns/1ps
// subbytes.v — stub only, kept so Makefile/info.yaml don't need changing.
// The S-box is now inlined as a function inside aes_top.v.
module subbytes (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [127:0] state_in,
    output wire [127:0] state_out,
    output wire         done,
    output wire         busy
);
    assign state_out = 128'h0;
    assign done      = 1'b0;
    assign busy      = 1'b0;
    // suppress unused-input warnings
    wire _unused = clk | rst_n | start | |state_in;
endmodule

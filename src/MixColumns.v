// MixColumns_comb.v — COMBINATIONAL only (no pipeline registers, no clock)
// Used in the BASELINE (v1) design to create a long critical path.

module MixColumns (
    input  wire [127:0] state_in,
    output wire [127:0] state_out
);
    function [7:0] mb2;
        input [7:0] b;
        begin mb2 = b[7] ? ((b << 1) ^ 8'h1b) : (b << 1); end
    endfunction
    function [7:0] mb3;
        input [7:0] b;
        begin mb3 = mb2(b) ^ b; end
    endfunction

    genvar i;
    generate
        for (i = 0; i < 4; i = i + 1) begin : col
            wire [7:0] s3 = state_in[(i*32+24)+:8];
            wire [7:0] s2 = state_in[(i*32+16)+:8];
            wire [7:0] s1 = state_in[(i*32+ 8)+:8];
            wire [7:0] s0 = state_in[(i*32+ 0)+:8];

            // All GF arithmetic and final XOR are purely combinational
            assign state_out[(i*32+24)+:8] = mb2(s3)^mb3(s2)^s1^s0;
            assign state_out[(i*32+16)+:8] = s3^mb2(s2)^mb3(s1)^s0;
            assign state_out[(i*32+ 8)+:8] = s3^s2^mb2(s1)^mb3(s0);
            assign state_out[(i*32+ 0)+:8] = mb3(s3)^s2^s1^mb2(s0);
        end
    endgenerate
endmodule
